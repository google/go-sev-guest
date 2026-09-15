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

package kds

import (
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-sev-guest/abi"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestProductCertChainURL(t *testing.T) {
	got := ProductCertChainURL(abi.VcekReportSigner, "Milan")
	want := "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain"
	if got != want {
		t.Errorf("ProductCertChainURL(\"Milan\") = %q, want %q", got, want)
	}
}

func TestVCEKCertURL(t *testing.T) {
	hwid := make([]byte, abi.ChipIDSize)
	hwid[0] = 0xfe
	hwid[abi.ChipIDSize-1] = 0xc0
	got := VCEKCertURL("Milan", hwid, TCBVersionV0{})
	want := "https://kdsintf.amd.com/vcek/v1/Milan/fe0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0?blSPL=0&snpSPL=0&teeSPL=0&ucodeSPL=0"
	if got != want {
		t.Errorf("VCEKCertURL(\"Milan\", %v, 0) = %q, want %q", hwid, got, want)
	}
}

func TestParseProductBaseURL(t *testing.T) {
	tcs := []struct {
		name        string
		url         string
		wantProduct string
		wantURL     *url.URL
		wantErr     string
	}{
		{
			name:        "happy path",
			url:         ProductCertChainURL(abi.VcekReportSigner, "Milan"),
			wantProduct: "Milan",
			wantURL: &url.URL{
				Scheme: "https",
				Host:   "kdsintf.amd.com",
				Path:   "cert_chain", // The vcek/v1/Milan part is expected to be trimmed.
			},
		},
		{
			name:    "bad host",
			url:     "https://fakekds.com/vcek/v1/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL host \"fakekds.com\", want \"kdsintf.amd.com\"",
		},
		{
			name:    "bad scheme",
			url:     "http://kdsintf.amd.com/vcek/v1/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL scheme \"http\", want \"https\"",
		},
		{
			name:    "bad path",
			url:     "https://kdsintf.amd.com/vcek/v2/Milan/cert_chain",
			wantErr: "unexpected AMD KDS URL path \"/vcek/v2/Milan/cert_chain\", want prefix \"/vcek/v1/\"",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := parseBaseProductURL(tc.url)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("parseBaseProductURL(%q) = _, _, %v, want %q", tc.url, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(parsed.simpleURL, tc.wantURL); diff != "" {
					t.Errorf("parseBaseProductURL(%q) returned unexpected diff (-want +got):\n%s", tc.url, diff)
				}
				if parsed.productLine != tc.wantProduct {
					t.Errorf("parseBaseProductURL(%q) = %q, _, _ want %q", tc.url, parsed.productLine, tc.wantProduct)
				}
			}
		})
	}
}

func TestParseProductCertChainURL(t *testing.T) {
	tests := []struct {
		key     abi.ReportSigner
		product string
		wantKey CertFunction
	}{
		{
			key:     abi.VcekReportSigner,
			product: "Milan",
			wantKey: VcekCertFunction,
		},
		{
			key:     abi.VlekReportSigner,
			product: "Milan",
			wantKey: VlekCertFunction,
		},
	}
	for _, tc := range tests {
		url := ProductCertChainURL(tc.key, tc.product)
		got, key, err := ParseProductCertChainURL(url)
		if err != nil {
			t.Fatalf("ParseProductCertChainURL(%q) = _, _, %v, want nil", tc.product, err)
		}
		if got != tc.product || key != tc.wantKey {
			t.Errorf("ProductCertChainURL(%q) = %q, %v, nil want %q, %v", url, got, key, tc.product, tc.wantKey)
		}
	}
}

func TestParseVCEKCertURL(t *testing.T) {
	hwid := make([]byte, abi.ChipIDSize)
	hwidhex := hex.EncodeToString(hwid)
	tcs := []struct {
		name    string
		url     string
		want    VCEKCert
		wantErr string
	}{
		{
			name: "happy path",
			url:  VCEKCertURL("Milan", hwid, TCBVersionV0{}),
			want: func() VCEKCert {
				c := VCEKCertProduct("Milan")
				c.HWID = hwid
				c.TCB = TCBVersionV0{}
				return c
			}(),
		},
		{
			name:    "bad query format",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?ha;ha", hwidhex),
			wantErr: "invalid AMD KDS URL query \"ha;ha\": invalid semicolon separator in query",
		},
		{
			name:    "bad query key",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?fakespl=4", hwidhex),
			wantErr: "unexpected KDS TCB version URL argument \"fakespl\"",
		},
		{
			name:    "bad query argument numerical",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=-4", hwidhex),
			wantErr: "invalid KDS TCB version URL argument value \"-4\", want a value 0-127",
		},
		{
			name:    "bad query argument numerical",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=alpha", hwidhex),
			wantErr: "invalid KDS TCB version URL argument value \"alpha\", want a value 0-127",
		},
		{
			name:    "query argument exceeds 127 for blSPL",
			url:     fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/Milan/%s?blSPL=128", hwidhex),
			wantErr: "invalid KDS TCB version URL argument value \"128\", want a value 0-127",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVCEKCertURL(tc.url)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("ParseVCEKCertURL(%q) = _, %v, want %q", tc.url, err, tc.wantErr)
			}
			if err == nil {
				if diff := cmp.Diff(got, tc.want); diff != "" {
					t.Errorf("ParseVCEKCertURL(%q) returned unexpected diff (-want +got):\n%s", tc.url, diff)
				}
			}
		})
	}
}

func TestProductName(t *testing.T) {
	tcs := []struct {
		name  string
		input *pb.SevProduct
		want  string
	}{
		{
			name: "nil",
			want: "Milan-B1",
		},
		{
			name: "unknown",
			input: &pb.SevProduct{
				MachineStepping: &wrapperspb.UInt32Value{Value: 0x1A},
			},
			want: "badstepping",
		},
		{
			name: "Milan-B0",
			input: &pb.SevProduct{
				Name: pb.SevProduct_SEV_PRODUCT_MILAN,
			},
			want: "UnknownStepping",
		},
		{
			name: "Milan-B0",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0},
			},
			want: "Milan-B0",
		},
		{
			name: "Genoa-FF",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0xff},
			},
			want: "badstepping",
		},
		{
			name: "unknown milan stepping",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "unmappedMilanStepping",
		},
		{
			name: "unknown genoa stepping",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "unmappedGenoaStepping",
		},
		{
			name: "unknown",
			input: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_UNKNOWN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 15},
			},
			want: "Unknown",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProductName(tc.input); got != tc.want {
				t.Errorf("ProductName(%v) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestParseProductName(t *testing.T) {
	tcs := []struct {
		name    string
		input   string
		key     abi.ReportSigner
		want    *pb.SevProduct
		wantErr string
	}{
		{
			name:    "empty",
			wantErr: "unknown product name",
		},
		{
			name:    "Too big",
			input:   "Milan-100",
			wantErr: "unknown product name",
		},
		{
			name:  "happy path Genoa",
			input: "Genoa-B1",
			want: &pb.SevProduct{
				Name:            pb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 1},
			},
		},
		{
			name:    "bad revision Milan",
			input:   "Milan-A1",
			wantErr: "unknown product name",
		},
		{
			name:  "vlek products have no stepping",
			input: "Genoa",
			key:   abi.VlekReportSigner,
			want: &pb.SevProduct{
				Name: pb.SevProduct_SEV_PRODUCT_GENOA,
			},
		},
		{
			name:    "Unhandled report signer",
			input:   "ignored",
			key:     abi.NoneReportSigner,
			wantErr: "internal: unhandled reportSigner",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseProductName(tc.input, tc.key)
			if (err == nil && tc.wantErr != "") || (err != nil && (tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Fatalf("ParseProductName(%v) errored unexpectedly: %v, want %q", tc.input, err, tc.wantErr)
			}
			if tc.wantErr == "" {
				if diff := cmp.Diff(got, tc.want, protocmp.Transform()); diff != "" {
					t.Fatalf("ParseProductName(%v) = %v, want %v\nDiff: %s", tc.input, got, tc.want, diff)
				}
			}
		})
	}
}

func TestTCBVersionV0(t *testing.T) {
	tcb := TCBVersionV0{
		BlSpl:    1,
		TeeSpl:   2,
		Spl4:     3,
		Spl5:     4,
		Spl6:     5,
		Spl7:     6,
		SnpSpl:   7,
		UcodeSpl: 8,
	}
	if tcb.BlSpl != 1 || tcb.TeeSpl != 2 || tcb.Spl4 != 3 || tcb.Spl5 != 4 ||
		tcb.Spl6 != 5 || tcb.Spl7 != 6 || tcb.SnpSpl != 7 || tcb.UcodeSpl != 8 {
		t.Errorf("TCBVersionV0 fields failed: got bl=%d tee=%d spl4=%d spl5=%d spl6=%d spl7=%d snp=%d ucode=%d",
			tcb.BlSpl, tcb.TeeSpl, tcb.Spl4, tcb.Spl5, tcb.Spl6, tcb.Spl7, tcb.SnpSpl, tcb.UcodeSpl)
	}
	if tcb.StructVersion() != 0 {
		t.Errorf("StructVersion() = %d, want 0", tcb.StructVersion())
	}

	raw := tcb.Uint64()
	decomposed := DecomposeTCBVersionV0(raw)
	if decomposed != tcb {
		t.Errorf("DecomposeTCBVersionV0(0x%x) = %+v, want %+v", raw, decomposed, tcb)
	}

	vals := tcb.Values()
	parsed, err := ParseTCBVersionV0(vals)
	if err != nil {
		t.Fatalf("ParseTCBVersionV0(%v) failed: %v", vals, err)
	}
	if parsed != (TCBVersionV0{BlSpl: 1, TeeSpl: 2, SnpSpl: 7, UcodeSpl: 8}) {
		t.Errorf("ParseTCBVersionV0(%v) = %+v, want %+v", vals, parsed, tcb)
	}

	// Component-wise LE tests across all 8 fields.
	base := TCBVersionV0{
		BlSpl:    10,
		TeeSpl:   10,
		Spl4:     10,
		Spl5:     10,
		Spl6:     10,
		Spl7:     10,
		SnpSpl:   10,
		UcodeSpl: 10,
	}
	if !base.LE(base) {
		t.Errorf("expected base.LE(base) to be true")
	}

	higherFields := []struct {
		name string
		tcb  TCBVersionV0
	}{
		{"BlSpl", TCBVersionV0{BlSpl: 11, TeeSpl: 10, Spl4: 10, Spl5: 10, Spl6: 10, Spl7: 10, SnpSpl: 10, UcodeSpl: 10}},
		{"TeeSpl", TCBVersionV0{BlSpl: 10, TeeSpl: 11, Spl4: 10, Spl5: 10, Spl6: 10, Spl7: 10, SnpSpl: 10, UcodeSpl: 10}},
		{"Spl4", TCBVersionV0{BlSpl: 10, TeeSpl: 10, Spl4: 11, Spl5: 10, Spl6: 10, Spl7: 10, SnpSpl: 10, UcodeSpl: 10}},
		{"Spl5", TCBVersionV0{BlSpl: 10, TeeSpl: 10, Spl4: 10, Spl5: 11, Spl6: 10, Spl7: 10, SnpSpl: 10, UcodeSpl: 10}},
		{"Spl6", TCBVersionV0{BlSpl: 10, TeeSpl: 10, Spl4: 10, Spl5: 10, Spl6: 11, Spl7: 10, SnpSpl: 10, UcodeSpl: 10}},
		{"Spl7", TCBVersionV0{BlSpl: 10, TeeSpl: 10, Spl4: 10, Spl5: 10, Spl6: 10, Spl7: 11, SnpSpl: 10, UcodeSpl: 10}},
		{"SnpSpl", TCBVersionV0{BlSpl: 10, TeeSpl: 10, Spl4: 10, Spl5: 10, Spl6: 10, Spl7: 10, SnpSpl: 11, UcodeSpl: 10}},
		{"UcodeSpl", TCBVersionV0{BlSpl: 10, TeeSpl: 10, Spl4: 10, Spl5: 10, Spl6: 10, Spl7: 10, SnpSpl: 10, UcodeSpl: 11}},
	}
	for _, tc := range higherFields {
		if !base.LE(tc.tcb) {
			t.Errorf("expected base.LE(higher for %s) to be true", tc.name)
		}
		if tc.tcb.LE(base) {
			t.Errorf("expected higher.LE(base for %s) to be false", tc.name)
		}
	}
}

func TestTCBVersionV1(t *testing.T) {
	tcb := TCBVersionV1{
		FmcSpl:   1,
		BlSpl:    2,
		TeeSpl:   3,
		SnpSpl:   4,
		Spl5:     5,
		Spl6:     6,
		Spl7:     7,
		UcodeSpl: 8,
	}
	if tcb.FmcSpl != 1 || tcb.BlSpl != 2 || tcb.TeeSpl != 3 || tcb.SnpSpl != 4 ||
		tcb.Spl5 != 5 || tcb.Spl6 != 6 || tcb.Spl7 != 7 || tcb.UcodeSpl != 8 {
		t.Errorf("TCBVersionV1 fields failed: got fmc=%d bl=%d tee=%d snp=%d spl5=%d spl6=%d spl7=%d ucode=%d",
			tcb.FmcSpl, tcb.BlSpl, tcb.TeeSpl, tcb.SnpSpl, tcb.Spl5, tcb.Spl6, tcb.Spl7, tcb.UcodeSpl)
	}
	if tcb.StructVersion() != 1 {
		t.Errorf("StructVersion() = %d, want 1", tcb.StructVersion())
	}

	raw := tcb.Uint64()
	decomposed := DecomposeTCBVersionV1(raw)
	if decomposed != tcb {
		t.Errorf("DecomposeTCBVersionV1(0x%x) = %+v, want %+v", raw, decomposed, tcb)
	}

	vals := tcb.Values()
	parsed, err := ParseTCBVersionV1(vals)
	if err != nil {
		t.Fatalf("ParseTCBVersionV1(%v) failed: %v", vals, err)
	}
	wantParsed := TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, UcodeSpl: 8}
	if parsed != wantParsed {
		t.Errorf("ParseTCBVersionV1(%v) = %+v, want %+v", vals, parsed, wantParsed)
	}

	base := TCBVersionV1{
		FmcSpl:   10,
		BlSpl:    10,
		TeeSpl:   10,
		SnpSpl:   10,
		Spl5:     10,
		Spl6:     10,
		Spl7:     10,
		UcodeSpl: 10,
	}
	if !base.LE(base) {
		t.Errorf("expected base.LE(base) to be true")
	}

	higherFields := []struct {
		name string
		tcb  TCBVersionV1
	}{
		{"FmcSpl", TCBVersionV1{FmcSpl: 11, BlSpl: 10, TeeSpl: 10, SnpSpl: 10, Spl5: 10, Spl6: 10, Spl7: 10, UcodeSpl: 10}},
		{"BlSpl", TCBVersionV1{FmcSpl: 10, BlSpl: 11, TeeSpl: 10, SnpSpl: 10, Spl5: 10, Spl6: 10, Spl7: 10, UcodeSpl: 10}},
		{"TeeSpl", TCBVersionV1{FmcSpl: 10, BlSpl: 10, TeeSpl: 11, SnpSpl: 10, Spl5: 10, Spl6: 10, Spl7: 10, UcodeSpl: 10}},
		{"SnpSpl", TCBVersionV1{FmcSpl: 10, BlSpl: 10, TeeSpl: 10, SnpSpl: 11, Spl5: 10, Spl6: 10, Spl7: 10, UcodeSpl: 10}},
		{"Spl5", TCBVersionV1{FmcSpl: 10, BlSpl: 10, TeeSpl: 10, SnpSpl: 10, Spl5: 11, Spl6: 10, Spl7: 10, UcodeSpl: 10}},
		{"Spl6", TCBVersionV1{FmcSpl: 10, BlSpl: 10, TeeSpl: 10, SnpSpl: 10, Spl5: 10, Spl6: 11, Spl7: 10, UcodeSpl: 10}},
		{"Spl7", TCBVersionV1{FmcSpl: 10, BlSpl: 10, TeeSpl: 10, SnpSpl: 10, Spl5: 10, Spl6: 10, Spl7: 11, UcodeSpl: 10}},
		{"UcodeSpl", TCBVersionV1{FmcSpl: 10, BlSpl: 10, TeeSpl: 10, SnpSpl: 10, Spl5: 10, Spl6: 10, Spl7: 10, UcodeSpl: 11}},
	}
	for _, tc := range higherFields {
		t.Run("LE_"+tc.name, func(t *testing.T) {
			if !base.LE(tc.tcb) {
				t.Errorf("expected base.LE(higher) to be true")
			}
			if tc.tcb.LE(base) {
				t.Errorf("expected higher.LE(base) to be false")
			}
		})
	}
}

func TestDecomposeTCBVersion(t *testing.T) {
	tcs := []struct {
		name          string
		structVersion uint8
		raw           uint64
		want          TCBVersion
		wantErr       bool
	}{
		{
			name:          "StructVersion 0",
			structVersion: 0,
			raw:           0x0807060504030201,
			want:          TCBVersionV0{BlSpl: 1, TeeSpl: 2, Spl4: 3, Spl5: 4, Spl6: 5, Spl7: 6, SnpSpl: 7, UcodeSpl: 8},
		},
		{
			name:          "StructVersion 1",
			structVersion: 1,
			raw:           0x0807060504030201,
			want:          TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8},
		},
		{
			name:          "unsupported StructVersion",
			structVersion: 2,
			raw:           0,
			wantErr:       true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecomposeTCBVersion(tc.structVersion, tc.raw)
			if (err != nil) != tc.wantErr {
				t.Fatalf("DecomposeTCBVersion(%d, 0x%x) error = %v, wantErr %v", tc.structVersion, tc.raw, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("DecomposeTCBVersion(%d, 0x%x) = %+v, want %+v", tc.structVersion, tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseTCBVersion(t *testing.T) {
	v0Vals := TCBVersionV0{BlSpl: 1, TeeSpl: 2, SnpSpl: 3, UcodeSpl: 4}.Values()
	gotV0, err := ParseTCBVersion(0, v0Vals)
	if err != nil {
		t.Fatalf("ParseTCBVersion(0, %v) failed: %v", v0Vals, err)
	}
	wantV0 := TCBVersionV0{BlSpl: 1, TeeSpl: 2, SnpSpl: 3, UcodeSpl: 4}
	if gotV0 != wantV0 {
		t.Errorf("ParseTCBVersion(0, %v) = %+v, want %+v", v0Vals, gotV0, wantV0)
	}

	v1Vals := TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, UcodeSpl: 5}.Values()
	gotV1, err := ParseTCBVersion(1, v1Vals)
	if err != nil {
		t.Fatalf("ParseTCBVersion(1, %v) failed: %v", v1Vals, err)
	}
	wantV1 := TCBVersionV1{FmcSpl: 1, BlSpl: 2, TeeSpl: 3, SnpSpl: 4, UcodeSpl: 5}
	if gotV1 != wantV1 {
		t.Errorf("ParseTCBVersion(1, %v) = %+v, want %+v", v1Vals, gotV1, wantV1)
	}

	if _, err := ParseTCBVersion(2, v1Vals); err == nil {
		t.Errorf("ParseTCBVersion(2, %v) expected error, got nil", v1Vals)
	}
}

func TestStructVersionForProductLine(t *testing.T) {
	tcs := []struct {
		productLine string
		want        uint8
		wantErr     bool
	}{
		{"Milan", 0, false},
		{"Genoa", 0, false},
		{"Turin", 1, false},
		{"Unknown", 0, true},
	}
	for _, tc := range tcs {
		t.Run(tc.productLine, func(t *testing.T) {
			got, err := StructVersionForProductLine(tc.productLine)
			if (err != nil) != tc.wantErr {
				t.Fatalf("StructVersionForProductLine(%q) error = %v, wantErr %v", tc.productLine, err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("StructVersionForProductLine(%q) = %d, want %d", tc.productLine, got, tc.want)
			}
		})
	}
}

func TestDecomposeProductTCB(t *testing.T) {
	raw := uint64(0x0807060504030201)
	milanTCB, err := DecomposeProductTCB("Milan", raw)
	if err != nil {
		t.Fatalf("DecomposeProductTCB(Milan) failed: %v", err)
	}
	if milanTCB.StructVersion() != 0 {
		t.Errorf("DecomposeProductTCB(Milan).StructVersion = %d, want 0", milanTCB.StructVersion())
	}
	turinTCB, err := DecomposeProductTCB("Turin", raw)
	if err != nil {
		t.Fatalf("DecomposeProductTCB(Turin) failed: %v", err)
	}
	if turinTCB.StructVersion() != 1 {
		t.Errorf("DecomposeProductTCB(Turin).StructVersion = %d, want 1", turinTCB.StructVersion())
	}
	if _, err := DecomposeProductTCB("Unknown", raw); err == nil {
		t.Errorf("DecomposeProductTCB(Unknown) expected error, got nil")
	}
}
