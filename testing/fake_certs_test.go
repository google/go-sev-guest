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

package testing

import (
	"bytes"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"
)

func TestCertificatesParse(t *testing.T) {
	signer, err := DefaultTestOnlyCertChain("Milan", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := signer.CertTableBytes()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := abi.ParseSnpCertTableHeader(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	var hasVcek bool
	var hasVlek bool
	var hasAsk bool
	var hasAsvk bool
	var hasArk bool
	if len(entries) != 5 {
		t.Errorf("ParseSnpCertTableHeader(_) returned %d entries, want 5", len(entries))
	}
	for _, entry := range entries {
		if entry.GUID == uuid.MustParse(abi.VlekGUID) {
			hasVlek = true
		}
		if entry.GUID == uuid.MustParse(abi.VcekGUID) {
			hasVcek = true
		}
		if entry.GUID == uuid.MustParse(abi.AskGUID) {
			hasAsk = true
		}
		if entry.GUID == uuid.MustParse(abi.AsvkGUID) {
			hasAsvk = true
		}
		if entry.GUID == uuid.MustParse(abi.ArkGUID) {
			hasArk = true
		}
		der := certBytes[entry.Offset : entry.Offset+entry.Length]
		if _, err := x509.ParseCertificate(der); err != nil {
			t.Errorf("could not parse certificate of %v: %v", entry.GUID, err)
		}
	}
	if !hasVlek {
		t.Errorf("fake certs missing VLEK")
	}
	if !hasVcek {
		t.Errorf("fake certs missing VCEK")
	}
	if !hasAsk {
		t.Errorf("fake certs missing ASK")
	}
	if !hasArk {
		t.Errorf("fake certs missing ARK")
	}
	if !hasAsvk {
		t.Errorf("fake certs missing ASVK")
	}
	if _, err := kds.VcekCertificateExtensions(signer.Vcek); err != nil {
		t.Errorf("could not parse generated VCEK extensions: %v", err)
	}
}

func TestCertificatesExtras(t *testing.T) {
	b := &AmdSignerBuilder{
		Extras: map[string][]byte{abi.ExtraPlatformInfoGUID: []byte("test")},
	}
	s, err := b.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	certBytes, err := s.CertTableBytes()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := abi.ParseSnpCertTableHeader(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	var hasXtra bool
	if len(entries) != 6 {
		t.Errorf("ParseSnpCertTableHeader(_) returned %d entries, want 6", len(entries))
	}
	for _, entry := range entries {
		if entry.GUID == uuid.MustParse(abi.ExtraPlatformInfoGUID) {
			hasXtra = true
			got := certBytes[entry.Offset : entry.Offset+entry.Length]
			want := []byte("test")
			if !bytes.Equal(got, want) {
				t.Errorf("%v data is %v, want %v", abi.ExtraPlatformInfoGUID, got, want)
			}
		}
	}
	if !hasXtra {
		t.Errorf("fake certs missing extra cert")
	}
}

func TestFakeKDSFromSignerUnknownProduct(t *testing.T) {
	signer := &AmdSigner{Product: &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_UNKNOWN}}
	if _, err := FakeKDSFromSigner(signer); err == nil {
		t.Error("FakeKDSFromSigner(unknown product) = nil error, want error")
	}
}

func TestCustomExtensionsV1TruncatesHWID(t *testing.T) {
	tcb := kds.TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8}
	hwid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	exts := CustomExtensionsV1(tcb, hwid, "", "Turin-B0")
	got, err := kds.VcekCertificateExtensions(&x509.Certificate{Extensions: exts})
	if err != nil {
		t.Fatalf("kds.VcekCertificateExtensions(CustomExtensionsV1(%v, %x, \"\", \"Turin-B0\")) = %+v, %v, want nil error", tcb, hwid, got, err)
	}
	want := &kds.Extensions{
		StructVersion: 1,
		ProductName:   "Turin-B0",
		HWID:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
		TCBVersion: kds.TCBVersionV1{
			FmcSpl:   1,
			BlSpl:    2,
			TeeSpl:   3,
			SnpSpl:   4,
			Spl5:     5,
			Spl6:     6,
			Spl7:     7,
			UcodeSpl: 8,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("CustomExtensionsV1(%v, %x, \"\", \"Turin-B0\") = %+v, want %+v (-want +got):\n%s", tcb, hwid, got, want, diff)
	}
}

func TestCustomExtensionsV1VLEKHasNoHWID(t *testing.T) {
	tcb := kds.TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8}
	exts := CustomExtensionsV1(tcb, nil, "csp-id", "Turin-B0")
	for _, ext := range exts {
		if ext.Id.Equal(kds.OidHwid) {
			t.Fatalf("CustomExtensionsV1(%v, nil, \"csp-id\", \"Turin-B0\") contains HWID extension %v, want none", tcb, ext)
		}
	}
	got, err := kds.VlekCertificateExtensions(&x509.Certificate{Extensions: exts})
	if err != nil {
		t.Fatalf("kds.VlekCertificateExtensions(CustomExtensionsV1(%v, nil, \"csp-id\", \"Turin-B0\")) = %+v, %v, want nil error", tcb, got, err)
	}
	want := &kds.Extensions{
		StructVersion: 1,
		ProductName:   "Turin",
		CspID:         "csp-id",
		TCBVersion: kds.TCBVersionV1{
			FmcSpl:   1,
			BlSpl:    2,
			TeeSpl:   3,
			SnpSpl:   4,
			Spl5:     5,
			Spl6:     6,
			Spl7:     7,
			UcodeSpl: 8,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("CustomExtensionsV1(%v, nil, \"csp-id\", \"Turin-B0\") = %+v, want %+v (-want +got):\n%s", tcb, got, want, diff)
	}
}

func TestTestOnlyCertChainTurin(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	b := &AmdSignerBuilder{
		ProductName:      "Turin-B0",
		ArkCreationTime:  fixedTime,
		AskCreationTime:  fixedTime,
		AsvkCreationTime: fixedTime,
		VcekCreationTime: fixedTime,
		VlekCreationTime: fixedTime,
		HWID:             [abi.ChipIDSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		TCB:              kds.TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8},
	}
	signer, err := b.TestOnlyCertChain()
	if err != nil {
		t.Fatalf("(%+v).TestOnlyCertChain() = %v, %v, want nil error", b, signer, err)
	}
	got, err := kds.VcekCertificateExtensions(signer.Vcek)
	if err != nil {
		t.Fatalf("kds.VcekCertificateExtensions(signer.Vcek) = %+v, %v, want nil error", got, err)
	}
	want := &kds.Extensions{
		StructVersion: 1,
		ProductName:   "Turin-B0",
		HWID:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
		TCBVersion: kds.TCBVersionV1{
			FmcSpl:   1,
			BlSpl:    2,
			TeeSpl:   3,
			SnpSpl:   4,
			Spl5:     5,
			Spl6:     6,
			Spl7:     7,
			UcodeSpl: 8,
		},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("kds.VcekCertificateExtensions(signer.Vcek) = %+v, want %+v (-want +got):\n%s", got, want, diff)
	}
}

func TestFakeKDSFromSignerTurin(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	b := &AmdSignerBuilder{
		ProductName:      "Turin-B0",
		ArkCreationTime:  fixedTime,
		AskCreationTime:  fixedTime,
		AsvkCreationTime: fixedTime,
		VcekCreationTime: fixedTime,
		VlekCreationTime: fixedTime,
		HWID:             [abi.ChipIDSize]byte{0xfe, 0, 0, 0, 0, 0, 0, 0xc0, 0xaa},
		TCB:              kds.TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, UcodeSpl: 5},
	}
	signer, err := b.TestOnlyCertChain()
	if err != nil {
		t.Fatalf("(%+v).TestOnlyCertChain() = %v, %v, want nil error", b, signer, err)
	}
	signer.Product = &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_TURIN}
	fakeKDS, err := FakeKDSFromSigner(signer)
	if err != nil {
		t.Fatalf("FakeKDSFromSigner(%+v) = %v, %v, want nil error", signer, fakeKDS, err)
	}
	rawURL := "https://kdsintf.amd.com/vcek/v1/Turin/fe000000000000c0?blSPL=2&fmcSPL=1&snpSPL=4&teeSPL=3&ucodeSPL=5"
	got, err := fakeKDS.Get(rawURL)
	if err != nil {
		t.Fatalf("fakeKDS.Get(%q) = %x, %v, want nil error", rawURL, got, err)
	}
	if !bytes.Equal(got, signer.Vcek.Raw) {
		t.Errorf("fakeKDS.Get(%q) = %x, want %x", rawURL, got, signer.Vcek.Raw)
	}
}

type unsupportedTCB struct{ kds.TCBVersion }

func TestAmdSignerBuilderExtensionsErrors(t *testing.T) {
	tcs := []struct {
		name    string
		builder AmdSignerBuilder
		wantErr string
	}{
		{
			name:    "unknown product line",
			builder: AmdSignerBuilder{ProductName: "Unknown-B0"},
			wantErr: `unknown product line: "Unknown"`,
		},
		{
			name:    "unsupported TCB type",
			builder: AmdSignerBuilder{ProductName: "Turin-B0", TCB: unsupportedTCB{}},
			wantErr: "unsupported TCB type",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.builder
			got, err := b.extensions(nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("(%+v).extensions(nil) = %v, %v, want error containing %q", tc.builder, got, err, tc.wantErr)
			}
		})
	}
}

func TestMakeTestCertsNilStepping(t *testing.T) {
	fixedTime := time.Date(2025, time.January, 1, 0, 0, 0, 0, time.UTC)
	opts := &DeviceOptions{
		Now:     fixedTime,
		Product: &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_TURIN},
	}
	_, signer, err := makeTestCerts(opts)
	if err != nil {
		t.Fatalf("makeTestCerts(%+v) = _, %v, %v, want nil error", opts, signer, err)
	}
	exts, err := kds.VcekCertificateExtensions(signer.Vcek)
	if err != nil {
		t.Fatalf("kds.VcekCertificateExtensions(signer.Vcek) = %+v, %v, want nil error", exts, err)
	}
	if exts.ProductName != "Turin-B0" {
		t.Errorf("makeTestCerts(%+v) ProductName = %q, want %q", opts, exts.ProductName, "Turin-B0")
	}
}
