// Copyright 2026 Google LLC
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

// These tests are in package kds_test because package testing imports package kds.

package kds_test

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-sev-guest/kds"
	test "github.com/google/go-sev-guest/testing"
)

// withoutOID returns exts without any extension matching id.
func withoutOID(exts []pkix.Extension, id asn1.ObjectIdentifier) []pkix.Extension {
	var out []pkix.Extension
	for _, ext := range exts {
		if !ext.Id.Equal(id) {
			out = append(out, ext)
		}
	}
	return out
}

func TestVcekCertificateExtensions(t *testing.T) {
	tcs := []struct {
		name string
		exts []pkix.Extension
		want *kds.Extensions
	}{
		{
			name: "struct_version_0",
			exts: test.CustomExtensionsV0(
				kds.TCBVersionV0{BlSpl: 1, TeeSpl: 2, SnpSpl: 3, Spl4: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8},
				[]byte{0: 1, 63: 64}, "", "Milan-B0"),
			want: &kds.Extensions{
				StructVersion: 0,
				ProductName:   "Milan-B0",
				HWID:          []byte{0: 1, 63: 64},
				TCBVersion:    kds.TCBVersionV0{BlSpl: 1, TeeSpl: 2, SnpSpl: 3, Spl4: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8},
			},
		},
		{
			name: "struct_version_1",
			exts: test.CustomExtensionsV1(
				kds.TCBVersionV1{BlSpl: 1, TeeSpl: 2, SnpSpl: 3, FmcSpl: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8},
				[]byte{1, 2, 3, 4, 5, 6, 7, 8}, "", "Turin-B0"),
			want: &kds.Extensions{
				StructVersion: 1,
				ProductName:   "Turin-B0",
				HWID:          []byte{1, 2, 3, 4, 5, 6, 7, 8},
				TCBVersion:    kds.TCBVersionV1{BlSpl: 1, TeeSpl: 2, SnpSpl: 3, FmcSpl: 4, Spl5: 5, Spl6: 6, Spl7: 7, UcodeSpl: 8},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{Extensions: tc.exts}
			got, err := kds.VcekCertificateExtensions(cert)
			if err != nil {
				t.Fatalf("kds.VcekCertificateExtensions() = %+v, %v, want nil error", got, err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("kds.VcekCertificateExtensions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVcekCertificateExtensionsErrors(t *testing.T) {
	v2, err := asn1.Marshal(2)
	if err != nil {
		t.Fatalf("asn1.Marshal(2) = %v, %v, want nil error", v2, err)
	}
	v0Base := test.CustomExtensionsV0(kds.TCBVersionV0{}, []byte{0: 1, 63: 64}, "", "Milan-B0")
	v1Base := test.CustomExtensionsV1(kds.TCBVersionV1{}, []byte{1, 2, 3, 4, 5, 6, 7, 8}, "", "Turin-B0")

	tcs := []struct {
		name    string
		exts    []pkix.Extension
		wantErr string
	}{
		{
			name:    "struct_version_0_without_spl4",
			exts:    withoutOID(v0Base, kds.OidSpl4),
			wantErr: "Spl4",
		},
		{
			name:    "struct_version_1_without_fmc_spl",
			exts:    withoutOID(v1Base, kds.OidFmcSpl),
			wantErr: "FmcSpl",
		},
		{
			name:    "struct_version_1_wrong_hwid_length",
			exts:    test.CustomExtensionsV1(kds.TCBVersionV1{}, []byte{1, 2, 3, 4}, "", "Turin-B0"),
			wantErr: "size is 4, expected 8",
		},
		{
			name:    "struct_version_1_without_hwid",
			exts:    withoutOID(v1Base, kds.OidHwid),
			wantErr: "missing HWID extension",
		},
		{
			name:    "struct_version_2",
			exts:    append(withoutOID(v1Base, kds.OidStructVersion), pkix.Extension{Id: kds.OidStructVersion, Value: v2}),
			wantErr: "unsupported structVersion 2",
		},
		{
			name:    "struct_version_2_without_hwid",
			exts:    append(withoutOID(withoutOID(v1Base, kds.OidHwid), kds.OidStructVersion), pkix.Extension{Id: kds.OidStructVersion, Value: v2}),
			wantErr: "unsupported structVersion 2",
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cert := &x509.Certificate{Extensions: tc.exts}
			got, err := kds.VcekCertificateExtensions(cert)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("kds.VcekCertificateExtensions() = %+v, %v, want error containing %q", got, err, tc.wantErr)
			}
		})
	}
}
