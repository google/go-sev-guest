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
var device *test.Device
var tests []test.TestCase

// Initializing a device with key generation is expensive. Just do it once for the test suite.
func initDevice() {
	now := time.Date(2022, time.May, 3, 9, 0, 0, 0, time.UTC)
	tests := test.TestCases()
	ones32 := make([]byte, 32)
	for i := range ones32 {
		ones32[i] = 1
	}
	keys := map[string][]byte{
		test.DerivedKeyRequestToString(&labi.SnpDerivedKeyReqABI{}):                    make([]byte, 32),
		test.DerivedKeyRequestToString(&labi.SnpDerivedKeyReqABI{GuestFieldSelect: 1}): ones32,
	}
	newDevice, err := test.TcDevice(tests, keys, now)
	if err != nil { // Unexpected
		panic(err)
	}
	device = newDevice
}

func TestOpenGetReportClose(t *testing.T) {
	devMu.Do(initDevice)
	d := device
	if err := d.Open("/dev/sev-guest"); err != nil {
		t.Error(err)
	}
	defer d.Close()
	for _, tc := range tests {
		reportProto := &spb.Report{}
		if err := prototext.Unmarshal([]byte(tc.OutputProto), reportProto); err != nil {
			t.Fatalf("test failure: %v", err)
		}

		// Does the proto report match expectations?
		got, err := GetReport(d, tc.Input)
		if err != tc.WantErr {
			t.Fatalf("GetReport(d, %v) = %v, %v. Want err: %v", tc.Input, got, err, tc.WantErr)
		}

		if tc.WantErr == nil {
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
	d := device
	if err := d.Open("/dev/sev-guest"); err != nil {
		t.Error(err)
	}
	defer d.Close()
	for _, tc := range tests {
		raw, certs, err := GetRawExtendedReport(d, tc.Input)
		if err != tc.WantErr {
			t.Fatalf("%s: GetRawExtendedReport(d, %v) = %v, %v, %v. Want err: %v", tc.Name, tc.Input, raw, certs, err, tc.WantErr)
		}
		if tc.WantErr == nil {
			got := abi.SignedComponent(raw)
			want := abi.SignedComponent(tc.Output[:])
			if !bytes.Equal(got, want) {
				t.Errorf("%s: GetRawExtendedReport(%v) = {data: %v, certs: _} want %v", tc.Name, tc.Input, got, want)
			}
			der, err := abi.ReportToSignatureDER(raw)
			if err != nil {
				t.Errorf("ReportToSignatureDER(%v) errored unexpectely: %v", raw, err)
			}
			if err := d.Signer.Vcek.CheckSignature(x509.ECDSAWithSHA384, got, der); err != nil {
				t.Errorf("signature with test keys did not verify: %v", err)
			}
		}
	}
}

func TestOpenGetExtendedReportClose(t *testing.T) {
	devMu.Do(initDevice)
	d := device
	if err := d.Open("/dev/sev-guest"); err != nil {
		t.Error(err)
	}
	defer d.Close()
	for _, tc := range tests {
		ereport, err := GetExtendedReport(d, tc.Input)
		if err != tc.WantErr {
			t.Fatalf("%s: GetExtendedReport(d, %v) = %v, %v. Want err: %v", tc.Name, tc.Input, ereport, err, tc.WantErr)
		}
		if tc.WantErr == nil {
			reportProto := &spb.Report{}
			if err := prototext.Unmarshal([]byte(tc.OutputProto), reportProto); err != nil {
				t.Fatalf("test failure: %v", err)
			}

			got := ereport.Report
			want := reportProto
			want.Signature = got.Signature // Zeros were placeholders.
			if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
				t.Errorf("%s: GetExtendedReport(%v) = {data: %v, certs: _} want %v. Diff: %s", tc.Name, tc.Input, got, want, diff)
			}

			if !bytes.Equal(ereport.GetCertificateChain().GetArkCert(), d.Signer.Ark.Raw) {
				t.Errorf("ARK certificate mismatch. Got %v, want %v",
					ereport.GetCertificateChain().GetArkCert(), d.Signer.Ark.Raw)
			}
			if !bytes.Equal(ereport.GetCertificateChain().GetAskCert(), d.Signer.Ask.Raw) {
				t.Errorf("ASK certificate mismatch. Got %v, want %v",
					ereport.GetCertificateChain().GetAskCert(), d.Signer.Ask.Raw)
			}
			if !bytes.Equal(ereport.GetCertificateChain().GetVcekCert(), d.Signer.Vcek.Raw) {
				t.Errorf("VCEK certificate mismatch. Got %v, want %v",
					ereport.GetCertificateChain().GetVcekCert(), d.Signer.Vcek.Raw)
			}
		}
	}
}

func TestGetDerivedKey(t *testing.T) {
	devMu.Do(initDevice)
	d := device
	if err := d.Open("/dev/sev-guest"); err != nil {
		t.Error(err)
	}
	defer d.Close()
	key1, err := GetDerivedKeyAcknowledgingItsLimitations(device, &SnpDerivedKeyReq{
		UseVCEK: true,
	})
	if err != nil {
		t.Fatal("Could not get key1: %v", err)
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
	if bytes.Equal(key1, key2) {
		t.Errorf("GetDerivedKey...(nothing) = %v = GetDerivedKey...(guestPolicy) = %v", key1, key2)
	}
	if !bytes.Equal(key1, key3) {
		t.Errorf("GetDerivedKey...(nothing) = %v and %v. Expected equality", key1, key3)
	}
}
