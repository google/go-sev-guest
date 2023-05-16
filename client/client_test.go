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
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"

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
var tests []test.TestCase

var guestPolicy = flag.Uint64("guest_policy", abi.SnpPolicyToBytes(abi.SnpPolicy{SMT: true}),
	"If --sev_guest_device_path is not 'default', this is the policy of the VM that is running this test")

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
		return
	}

	client, err := OpenDevice()
	if err != nil { // Unexpected
		panic(err)
	}
	device = client
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
		reportProto := &spb.Report{}
		if err := prototext.Unmarshal([]byte(tc.OutputProto), reportProto); err != nil {
			t.Fatalf("test failure: %v", err)
		}
		fixReportWants(reportProto)

		// Does the proto report match expectations?
		got, err := GetReport(device, tc.Input)
		if !test.Match(err, tc.WantErr) {
			t.Fatalf("GetReport(device, %v) = %v, %v. Want err: %v", tc.Input, got, err, tc.WantErr)
		}

		if tc.WantErr == "" {
			cleanReport(got)
			want := reportProto
			want.Signature = got.Signature // Zeros were placeholders.
			if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
				t.Errorf("%s: GetReport(%v) expectation diff %s", tc.Name, tc.Input, diff)
			}
		}
	}
}

func TestOpenGetRawExtendedReportClose(t *testing.T) {
	devMu.Do(initDevice)
	for _, tc := range tests {
		raw, certs, err := GetRawExtendedReport(device, tc.Input)
		if !test.Match(err, tc.WantErr) {
			t.Fatalf("%s: GetRawExtendedReport(device, %v) = %v, %v, %v. Want err: %v", tc.Name, tc.Input, raw, certs, err, tc.WantErr)
		}
		if tc.WantErr == "" {
			if err := cleanRawReport(raw); err != nil {
				t.Fatal(err)
			}
			got := abi.SignedComponent(raw)
			if err := fixRawReportWants(tc.Output[:]); err != nil {
				t.Fatal(err)
			}
			want := abi.SignedComponent(tc.Output[:])
			if !bytes.Equal(got, want) {
				t.Errorf("%s: GetRawExtendedReport(%v) = {data: %v, certs: _} want %v", tc.Name, tc.Input, got, want)
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
	}
}

func TestOpenGetExtendedReportClose(t *testing.T) {
	devMu.Do(initDevice)
	for _, tc := range tests {
		ereport, err := GetExtendedReport(device, tc.Input)
		if !test.Match(err, tc.WantErr) {
			t.Fatalf("%s: GetExtendedReport(device, %v) = %v, %v. Want err: %v", tc.Name, tc.Input, ereport, err, tc.WantErr)
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
				t.Errorf("%s: GetExtendedReport(%v) = {data: %v, certs: _} want %v. Diff: %s", tc.Name, tc.Input, got, want, diff)
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
