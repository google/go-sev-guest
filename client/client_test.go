// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package client

import (
	"bytes"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"
	"unsafe"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-sev-guest/abi"
	labi "github.com/google/go-sev-guest/client/linuxabi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	test "github.com/google/go-sev-guest/testing"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/testing/protocmp"
)

var devMu sync.Once
var device Device
var qp QuoteProvider
var tests []test.TestCase

var guestPolicy = flag.Uint64("guest_policy", abi.SnpPolicyToBytes(abi.SnpPolicy{SMT: true}),
	"If --sev_guest_device_path is not 'default', this is the policy of the VM that is running this test")

type responseErrorDevice struct {
	Device
	status uint32
}

func (d *responseErrorDevice) Ioctl(_ uintptr, argument any) (uintptr, error) {
	request := argument.(*labi.SnpUserGuestRequest)
	switch response := request.RespData.(type) {
	case *labi.SnpDerivedKeyRespABI:
		response.Status = d.status
	case *labi.SnpReportRespABI:
		response.Status = d.status
	}
	return 0, request.ABI().Finish(request)
}

type requestFinalizer struct {
	name     string
	calls    *[]string
	err      error
	argument labi.BinaryConvertible
}

func (f *requestFinalizer) ABI() labi.BinaryConversion { return f }

func (f *requestFinalizer) Pointer() unsafe.Pointer { return unsafe.Pointer(f) }

func (f *requestFinalizer) Finish(argument labi.BinaryConvertible) error {
	*f.calls = append(*f.calls, f.name)
	f.argument = argument
	return f.err
}

// Initializing a device with key generation is expensive. Just do it once for the test suite.
func initDevice() {
	now := time.Date(2022, time.May, 3, 9, 0, 0, 0, time.UTC)
	for _, tc := range test.TestCases() {
		// Don't test faked errors when running real hardware tests.
		if !UseDefaultSevGuest() && tc.WantErr != "" {
			continue
		}
		tests = append(tests, tc)
	}
	ones32 := make([]byte, 32)
	for i := range ones32 {
		ones32[i] = 1
	}
	keys := map[string][]byte{
		test.DerivedKeyRequestToString(&labi.SnpDerivedKeyReqABI{}):                    make([]byte, 32),
		test.DerivedKeyRequestToString(&labi.SnpDerivedKeyReqABI{GuestFieldSelect: 1}): ones32,
	}
	opts := &test.DeviceOptions{Keys: keys, Now: now}
	// Choose a mock device or a real device depending on the given flag. This is like testclient,
	// but without the circular dependency.
	if UseDefaultSevGuest() {
		sevTestDevice, err := test.TcDevice(tests, opts)
		if err != nil {
			panic(fmt.Sprintf("failed to create test device: %v", err))
		}
		if err := sevTestDevice.Open("/dev/sev-guest"); err != nil {
			panic(err)
		}
		device = sevTestDevice
		qp = &test.QuoteProvider{Device: sevTestDevice}
		return
	}

	client, err := OpenDevice()
	if err != nil { // Unexpected
		panic(err)
	}
	device = client
	qp = &test.QuoteProvider{Device: device.(*test.Device)}
}

func cleanReport(report *spb.Report) {
	report.ReportId = make([]byte, abi.ReportIDSize)
	report.ReportIdMa = make([]byte, abi.ReportIDMASize)
	report.ChipId = make([]byte, abi.ChipIDSize)
	report.Measurement = make([]byte, abi.MeasurementSize)
	report.PlatformInfo = 0
	report.CommittedTcb = 0
	report.CommittedBuild = 0
	report.CommittedMinor = 0
	report.CommittedMajor = 0
	report.CurrentTcb = 0
	report.CurrentBuild = 0
	report.CurrentMinor = 0
	report.CurrentMajor = 0
	report.LaunchTcb = 0
	report.ReportedTcb = 0
}

func fixReportWants(report *spb.Report) {
	if !UseDefaultSevGuest() {
		// The GCE default policy isn't the same as for the mock tests.
		report.Policy = *guestPolicy
	}
}

func modifyReportBytes(raw []byte, process func(report *spb.Report)) error {
	report, err := abi.ReportToProto(raw)
	if err != nil {
		return err
	}
	process(report)
	result, err := abi.ReportToAbiBytes(report)
	if err != nil {
		return err
	}
	copy(raw, result)
	return nil
}

func cleanRawReport(raw []byte) error {
	return modifyReportBytes(raw, cleanReport)
}

func fixRawReportWants(raw []byte) error {
	return modifyReportBytes(raw, fixReportWants)
}

func TestOpenGetReportClose(t *testing.T) {
	devMu.Do(initDevice)
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			reportProto := &spb.Report{}
			if err := prototext.Unmarshal([]byte(tc.OutputProto), reportProto); err != nil {
				t.Fatalf("test failure: %v", err)
			}
			fixReportWants(reportProto)

			// Does the proto report match expectations?
			attestation, err := GetQuoteProto(qp, tc.Input)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("GetReport(device, %v) = %v, %v. Want err: %v", tc.Input, attestation, err, tc.WantErr)
			}

			if tc.WantErr == "" {
				got := attestation.Report
				cleanReport(got)
				want := reportProto
				want.Signature = got.Signature // Zeros were placeholders.
				if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
					t.Errorf("GetReport(%v) expectation diff %s", tc.Input, diff)
				}
			}
		})
	}
}

func TestOpenGetRawExtendedReportClose(t *testing.T) {
	devMu.Do(initDevice)
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			rawcerts, err := qp.GetRawQuote(tc.Input)
			if !test.Match(err, tc.WantErr) || (tc.WantErr == "" && len(rawcerts) < abi.ReportSize) {
				t.Fatalf("qp.GetRawQuote(%v) = %v, %v. Want err: %v", tc.Input, rawcerts, err, tc.WantErr)
			}
			if tc.WantErr == "" {
				raw := rawcerts[:abi.ReportSize]
				if err := cleanRawReport(raw); err != nil {
					t.Fatal(err)
				}
				got := abi.SignedComponent(raw)
				if err := fixRawReportWants(tc.Output[:]); err != nil {
					t.Fatal(err)
				}
				want := abi.SignedComponent(tc.Output[:])
				if !bytes.Equal(got, want) {
					t.Errorf("qp.GetRawQuote(%v) = {data: %v, certs: _} want %v", tc.Input, got, want)
				}
				der, err := abi.ReportToSignatureDER(raw)
				if err != nil {
					t.Errorf("ReportToSignatureDER(%v) errored unexpectedly: %v", raw, err)
				}
				if UseDefaultSevGuest() {
					tcdev := device.(*test.Device)
					infoRaw, _ := abi.ReportSignerInfo(raw)
					info, _ := abi.ParseSignerInfo(infoRaw)
					reportSigner := tcdev.Signer.Vcek
					if info.SigningKey == abi.VlekReportSigner {
						reportSigner = tcdev.Signer.Vlek
					}
					if err := reportSigner.CheckSignature(x509.ECDSAWithSHA384, got, der); err != nil {
						t.Errorf("signature with test keys did not verify: %v", err)
					}
				}
			}
		})
	}
}

func TestGetQuoteProto(t *testing.T) {
	devMu.Do(initDevice)
	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			ereport, err := GetQuoteProto(qp, tc.Input)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("GetQuoteProto(qp, %v) = %v, %v. Want err: %v", tc.Input, ereport, err, tc.WantErr)
			}
			if tc.WantErr == "" {
				reportProto := &spb.Report{}
				if err := prototext.Unmarshal([]byte(tc.OutputProto), reportProto); err != nil {
					t.Fatalf("test failure: %v", err)
				}
				fixReportWants(reportProto)

				got := ereport.Report
				cleanReport(got)
				want := reportProto
				want.Signature = got.Signature // Zeros were placeholders.
				if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
					t.Errorf("GetQuoteProto(qp, %v) = {data: %v, certs: _} want %v. Diff: %s", tc.Input, got, want, diff)
				}

				if UseDefaultSevGuest() {
					tcdev := device.(*test.Device)
					if !bytes.Equal(ereport.GetCertificateChain().GetArkCert(), tcdev.Signer.Ark.Raw) {
						t.Errorf("ARK certificate mismatch. Got %v, want %v",
							ereport.GetCertificateChain().GetArkCert(), tcdev.Signer.Ark.Raw)
					}
					if !bytes.Equal(ereport.GetCertificateChain().GetAskCert(), tcdev.Signer.Ask.Raw) {
						t.Errorf("ASK certificate mismatch. Got %v, want %v",
							ereport.GetCertificateChain().GetAskCert(), tcdev.Signer.Ask.Raw)
					}
					if !bytes.Equal(ereport.GetCertificateChain().GetVcekCert(), tcdev.Signer.Vcek.Raw) {
						t.Errorf("VCEK certificate mismatch. Got %v, want %v",
							ereport.GetCertificateChain().GetVcekCert(), tcdev.Signer.Vcek.Raw)
					}
				}
			}
		})
	}
}

func TestGetDerivedKey(t *testing.T) {
	devMu.Do(initDevice)
	key1, err := GetDerivedKeyAcknowledgingItsLimitations(device, &SnpDerivedKeyReq{
		UseVCEK: true,
	})
	if err != nil {
		t.Fatalf("Could not get key1: %v", err)
	}
	key2, err := GetDerivedKeyAcknowledgingItsLimitations(device, &SnpDerivedKeyReq{
		UseVCEK: true,
		GuestFieldSelect: GuestFieldSelect{
			GuestPolicy: true,
		},
	})
	if err != nil {
		t.Fatalf("Could not get key2: %v", err)
	}
	key3, err := GetDerivedKeyAcknowledgingItsLimitations(device, &SnpDerivedKeyReq{
		UseVCEK: true,
	})
	if err != nil {
		t.Fatalf("Could not get key3: %v", err)
	}
	if bytes.Equal(key1.Data[:], key2.Data[:]) {
		t.Errorf("GetDerivedKey...(nothing) = %v = GetDerivedKey...(guestPolicy) = %v", key1.Data, key2.Data)
	}
	if !bytes.Equal(key1.Data[:], key3.Data[:]) {
		t.Errorf("GetDerivedKey...(nothing) = %v and %v. Expected equality", key1.Data, key3.Data)
	}
}

func TestGetRawReportResponseError(t *testing.T) {
	for _, tc := range []struct {
		Name    string
		Status  uint32
		WantErr string
	}{
		{Name: "success"},
		{
			Name:    "invalid parameters",
			Status:  0x16,
			WantErr: "could not finalize response data: get_report had invalid parameters",
		},
		{
			Name:    "invalid key",
			Status:  0x27,
			WantErr: "could not finalize response data: unknown status: 0x27",
		},
		{
			Name:    "unknown",
			Status:  0xffffffff,
			WantErr: "could not finalize response data: unknown status: 0xffffffff",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			d := &responseErrorDevice{status: tc.Status}
			report, err := GetRawReport(d, [64]byte{})
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("GetRawReport() = %v, %v. Want err: %v", report, err, tc.WantErr)
			}
			if tc.WantErr == "" {
				if len(report) != abi.ReportSize {
					t.Errorf("len(report) = %d, want %d", len(report), abi.ReportSize)
				}
				return
			}
			if report != nil {
				t.Errorf("GetRawReport() = %v, want nil report", report)
			}
			if err.Error() != tc.WantErr {
				t.Errorf("GetRawReport() error = %q, want %q", err, tc.WantErr)
			}
			var firmwareErr *abi.SevFirmwareErr
			if !errors.As(err, &firmwareErr) || firmwareErr.Status != abi.SevFirmwareStatus(tc.Status) {
				t.Errorf("GetRawReport() error = %v, want firmware status %#x", err, tc.Status)
			}
		})
	}
}

func TestGetDerivedKeyResponseError(t *testing.T) {
	for _, tc := range []struct {
		Name    string
		Status  uint32
		WantErr string
	}{
		{Name: "success"},
		{
			Name:    "invalid parameters",
			Status:  0x16,
			WantErr: "error getting derived key: could not finalize response data: msg_key_req error: invalid parameters",
		},
		{
			Name:    "invalid key",
			Status:  0x27,
			WantErr: "error getting derived key: could not finalize response data: msg_key_req unknown status code: 0x27",
		},
		{
			Name:    "unknown",
			Status:  0xffffffff,
			WantErr: "error getting derived key: could not finalize response data: msg_key_req unknown status code: 0xffffffff",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			d := &responseErrorDevice{status: tc.Status}
			key, err := GetDerivedKeyAcknowledgingItsLimitations(d, &SnpDerivedKeyReq{})
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("GetDerivedKeyAcknowledgingItsLimitations() = %v, %v. Want err: %v", key, err, tc.WantErr)
			}
			if tc.WantErr == "" {
				if key == nil {
					t.Error("GetDerivedKeyAcknowledgingItsLimitations() returned nil key")
				}
				return
			}
			if key != nil {
				t.Errorf("GetDerivedKeyAcknowledgingItsLimitations() = %v, want nil key", key)
			}
			if err.Error() != tc.WantErr {
				t.Errorf("GetDerivedKeyAcknowledgingItsLimitations() error = %q, want %q", err, tc.WantErr)
			}
			var firmwareErr *abi.SevFirmwareErr
			if !errors.As(err, &firmwareErr) || firmwareErr.Status != abi.SevFirmwareStatus(tc.Status) {
				t.Errorf("GetDerivedKeyAcknowledgingItsLimitations() error = %v, want firmware status %#x", err, tc.Status)
			}
		})
	}
}

func TestResponseErrorTextCompatibility(t *testing.T) {
	for _, tc := range []struct {
		Name          string
		Status        uint32
		WantReportErr string
		WantKeyErr    string
	}{
		{Name: "success"},
		{
			Name: "invalid parameters", Status: 0x16,
			WantReportErr: "get_report had invalid parameters",
			WantKeyErr:    "msg_key_req error: invalid parameters",
		},
		{
			Name: "invalid key", Status: 0x27,
			WantReportErr: "unknown status: 0x27",
			WantKeyErr:    "msg_key_req unknown status code: 0x27",
		},
		{
			Name: "unknown low", Status: 1,
			WantReportErr: "unknown status: 0x1",
			WantKeyErr:    "msg_key_req unknown status code: 0x1",
		},
		{
			Name: "unknown high", Status: 0xffffffff,
			WantReportErr: "unknown status: 0xffffffff",
			WantKeyErr:    "msg_key_req unknown status code: 0xffffffff",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			report := &labi.SnpReportRespABI{Status: tc.Status}
			if err := report.Finish(nil); !test.Match(err, tc.WantReportErr) {
				t.Fatalf("report.Finish(nil) = %v, want %q", err, tc.WantReportErr)
			} else if err != nil && err.Error() != tc.WantReportErr {
				t.Errorf("report.Finish(nil) = %q, want %q", err, tc.WantReportErr)
			}
			key := &labi.SnpDerivedKeyRespABI{Status: tc.Status}
			if err := key.Finish(nil); !test.Match(err, tc.WantKeyErr) {
				t.Fatalf("key.Finish(nil) = %v, want %q", err, tc.WantKeyErr)
			} else if err != nil && err.Error() != tc.WantKeyErr {
				t.Errorf("key.Finish(nil) = %q, want %q", err, tc.WantKeyErr)
			}
		})
	}
	firmwareErr := &abi.SevFirmwareErr{Status: 0x27}
	if got, want := firmwareErr.Error(), "unexpected firmware status (see SEV API spec): 27"; got != want {
		t.Errorf("SevFirmwareErr.Error() = %q, want %q", got, want)
	}
}

func TestRequestFinalizationCompatibility(t *testing.T) {
	for _, tc := range []struct {
		Name        string
		RequestErr  error
		ResponseErr error
		BadArgument bool
		WantErr     string
		WantCalls   []string
		WantFwErr   uint64
	}{
		{
			Name: "success", WantCalls: []string{"request", "response"}, WantFwErr: 9,
		},
		{
			Name: "request failure", RequestErr: errors.New("request failed"),
			WantErr:   "could not finalize request data: request failed",
			WantCalls: []string{"request"}, WantFwErr: 7,
		},
		{
			Name: "response failure", ResponseErr: errors.New("response failed"),
			WantErr:   "could not finalize response data: response failed",
			WantCalls: []string{"request", "response"}, WantFwErr: 7,
		},
		{
			Name: "both fail", RequestErr: errors.New("request failed"), ResponseErr: errors.New("response failed"),
			WantErr:   "could not finalize request data: request failed",
			WantCalls: []string{"request"}, WantFwErr: 7,
		},
		{
			Name: "bad argument", BadArgument: true,
			WantErr:   "Finish argument is <nil>. Expects a *SnpUserGuestRequestSafe",
			WantFwErr: 7,
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			var calls []string
			request := &requestFinalizer{name: "request", calls: &calls, err: tc.RequestErr}
			response := &requestFinalizer{name: "response", calls: &calls, err: tc.ResponseErr}
			guestRequest := &labi.SnpUserGuestRequest{ReqData: request, RespData: response, FwErr: 7}
			conversion := guestRequest.ABI()
			wire := (*labi.SnpUserGuestRequestABI)(conversion.Pointer())
			wire.FwErr = 9
			var argument labi.BinaryConvertible = guestRequest
			if tc.BadArgument {
				argument = nil
			}
			err := conversion.Finish(argument)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("Finish() = %v, want %q", err, tc.WantErr)
			}
			if err != nil && err.Error() != tc.WantErr {
				t.Errorf("Finish() = %q, want %q", err, tc.WantErr)
			}
			if diff := cmp.Diff(tc.WantCalls, calls); diff != "" {
				t.Errorf("Finish() call order diff (-want +got): %s", diff)
			}
			if guestRequest.FwErr != tc.WantFwErr {
				t.Errorf("FwErr = %d, want %d", guestRequest.FwErr, tc.WantFwErr)
			}
			if len(calls) > 0 && request.argument != request {
				t.Error("request.Finish() did not receive the original request")
			}
			if len(calls) > 1 && response.argument != response {
				t.Error("response.Finish() did not receive the original response")
			}
		})
	}
}

func TestExtendedReportFinalizationCompatibility(t *testing.T) {
	for _, tc := range []struct {
		Name      string
		Status    uint32
		WantErr   string
		WantFwErr uint64
	}{
		{Name: "success", WantFwErr: 9},
		{
			Name: "response failure", Status: 0x16, WantFwErr: 7,
			WantErr: "could not finalize response data: get_report had invalid parameters",
		},
	} {
		t.Run(tc.Name, func(t *testing.T) {
			request := &labi.SnpExtendedReportReq{CertsLength: 4096}
			response := &labi.SnpReportRespABI{Status: tc.Status}
			guestRequest := &labi.SnpUserGuestRequest{ReqData: request, RespData: response, FwErr: 7}
			conversion := guestRequest.ABI()
			wire := (*labi.SnpUserGuestRequestABI)(conversion.Pointer())
			wire.FwErr = 9
			(*labi.SnpExtendedReportReqABI)(wire.ReqData).CertsLength = 8192
			err := conversion.Finish(guestRequest)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("Finish() = %v, want %q", err, tc.WantErr)
			}
			if err != nil && err.Error() != tc.WantErr {
				t.Errorf("Finish() = %q, want %q", err, tc.WantErr)
			}
			if request.CertsLength != 8192 {
				t.Errorf("CertsLength = %d, want 8192", request.CertsLength)
			}
			if guestRequest.FwErr != tc.WantFwErr {
				t.Errorf("FwErr = %d, want %d", guestRequest.FwErr, tc.WantFwErr)
			}
		})
	}
}
