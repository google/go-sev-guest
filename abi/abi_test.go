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

package abi

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	emptyReportV2 = `
	version: 2
	policy: 0xa0000
	signature_algo: 1
	report_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
	family_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	image_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	measurement: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	host_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	id_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	author_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id_ma: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	chip_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	signature: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	`

	emptyReportV3 = `
	version: 3
	policy: 0xa0000
	signature_algo: 1
	report_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
	family_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	image_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	measurement: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	host_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	id_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	author_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id_ma: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	cpuid1eax_fms: 0
	chip_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	signature: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	`
)

func TestMbz64(t *testing.T) {
	tests := []struct {
		data    uint64
		lo      int
		hi      int
		wantErr string
	}{
		{
			data: uint64(0),
			lo:   0,
			hi:   63,
		},
		{
			data: ^uint64(0) &^ (uint64(1<<31) | uint64(1<<32) | uint64(1<<33)),
			lo:   31,
			hi:   33,
		},
		{
			data:    ^uint64(0) &^ (uint64(1<<0x1f) | uint64(1<<0x20)),
			lo:      0x1f,
			hi:      0x21,
			wantErr: "mbz range test[0x1f:0x21] not all zero",
		},
		{
			data:    ^uint64(0) &^ (uint64(1<<0x20) | uint64(1<<0x21)),
			lo:      0x1f,
			hi:      0x21,
			wantErr: "mbz range test[0x1f:0x21] not all zero",
		},
	}
	for _, tc := range tests {
		err := mbz64(tc.data, "test", tc.hi, tc.lo)
		if (tc.wantErr == "" && err != nil) || (tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr))) {
			t.Errorf("mbz64(0x%x, %d, %d) = %v, want %q", tc.data, tc.hi, tc.lo, err, tc.wantErr)
		}
	}
}

func TestReportMbz(t *testing.T) {
	tests := []struct {
		name        string
		report      string
		changeIndex int
		changeValue byte
		wantErr     string
	}{
		{
			name:        "AuthorKeyEn reserved",
			changeIndex: 0x49,
			wantErr:     "mbz range data[0x48:0x4C][0x5:0x1f] not all zero: cc00",
		},
		{
			name:        "pre-report data",
			changeIndex: 0x4f,
			wantErr:     "mbz range [0x4c:0x50] not all zero: 000000cc",
		},
		{
			name:        "pre-chip id",
			changeIndex: 0x18A,
			wantErr:     "mbz range [0x188:0x1a0] not all zero: 0000cc",
		},
		{
			name:        "current reserved",
			changeIndex: 0x1EB,
			wantErr:     "mbz range [0x1eb:0x1ec] not all zero: cc",
		},
		{
			name:        "committed reserved",
			changeIndex: 0x1EF,
			wantErr:     "mbz range [0x1ef:0x1f0] not all zero: cc",
		},
		{
			name:        "pre-signature reserved",
			changeIndex: 0x209,
			wantErr:     "mbz range [0x208:0x2a0] not all zero: 00cc",
		},
		{
			name:        "post-ecdsa signature reserved",
			changeIndex: signatureOffset + EcdsaP384Sha384SignatureSize + 2,
			wantErr:     "mbz range [0x330:0x4a0] not all zero: 0000cc",
		},
		{
			name:        "Guest policy bit 17",
			changeIndex: policyOffset + 2, // Bits 16-23
			changeValue: 0x1d,             // Set bits 16, 18, 19, 20
			wantErr:     "policy[17] is reserved, must be 1, got 0",
		},
		{
			name:        "Guest policy bit 26",
			changeIndex: policyOffset + 3, // Bits 24-31
			changeValue: 0x40,             // Set bit 26
			wantErr:     "malformed guest policy: mbz range policy[0x1a:0x3f] not all zero",
		},
	}
	reportProto := &spb.Report{}
	if err := prototext.Unmarshal([]byte(emptyReportV2), reportProto); err != nil {
		t.Fatalf("test failure: %v", err)
	}
	for _, tc := range tests {
		// Everything but the signature hase
		raw, err := ReportToAbiBytes(reportProto)
		if err != nil {
			t.Fatalf("%s: test failure: ReportToAbiBytes(%v) errored unexpectedly: %v", tc.name, reportProto, err)
		}
		changeValue := byte(0xcc)
		if tc.changeValue != 0 {
			changeValue = tc.changeValue
		}
		raw[tc.changeIndex] = changeValue
		_, err = ReportToProto(raw)
		if err == nil {
			t.Errorf("%s: ReportToProto(%v) = _, nil. Want error %q", tc.name, reportProto, tc.wantErr)
		} else if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: ReportToProto(%v) = _, %v. Want error %v", tc.name, reportProto, err, tc.wantErr)
		}
	}

	reportProto = &spb.Report{}
	if err := prototext.Unmarshal([]byte(emptyReportV3), reportProto); err != nil {
		t.Fatalf("test failure: %v", err)
	}
	raw, err := ReportToAbiBytes(reportProto)
	if err != nil {
		t.Fatalf("%s: test failure: ReportToAbiBytes(reportV3) errored unexpectedly: %v", reportProto, err)
	}
	raw[0x188] = 0xcc
	raw[0x189] = 0xcc
	raw[0x18A] = 0xcc
	if _, err := ReportToProto(raw); err != nil {
		t.Errorf("ReportToProto(%v) = _, %v. Want nil", reportProto, err)
	}
}

func TestSnpPolicySection(t *testing.T) {
	entropySize := 128
	entropy := make([]uint8, entropySize)
	rand.Read(entropy)
	for tc := 0; tc < entropySize/3; tc++ {
		policy := SnpPolicy{
			ABIMinor:             entropy[tc*3],
			ABIMajor:             entropy[tc*3+1],
			SMT:                  (entropy[tc*3+2] & 1) != 0,
			MigrateMA:            (entropy[tc*3+2] & 2) != 0,
			Debug:                (entropy[tc*3+2] & 4) != 0,
			SingleSocket:         (entropy[tc*3+2] & 8) != 0,
			CXLAllowed:           (entropy[tc*3+2] & 16) != 0,
			MemAES256XTS:         (entropy[tc*3+2] & 32) != 0,
			RAPLDis:              (entropy[tc*3+2] & 64) != 0,
			CipherTextHidingDRAM: (entropy[tc*3+2] & 128) != 0,
			PageSwapDisable:      (entropy[tc*3+3] & 1) != 0,
		}

		got, err := ParseSnpPolicy(SnpPolicyToBytes(policy))
		if err != nil {
			t.Errorf("ParseSnpPolicy(SnpPolicyToBytes(%v)) errored unexpectedly: %v", policy, err)
		}
		if got != policy {
			t.Errorf("ParseSnpPolicy(SnpPolicyToBytes(%v)) = %v, want %v", policy, got, policy)
		}
	}
}

func TestSnpPlatformInfo(t *testing.T) {
	tests := []struct {
		input   uint64
		want    SnpPlatformInfo
		wantErr string
	}{
		{
			input: 0,
		},
		{
			input: 3,
			want:  SnpPlatformInfo{TSMEEnabled: true, SMTEnabled: true},
		},
		{
			input: 21,
			want: SnpPlatformInfo{
				SMTEnabled:                  true,
				ECCEnabled:                  true,
				CiphertextHidingDRAMEnabled: true,
			},
		},
		{
			input: 42,
			want: SnpPlatformInfo{
				TSMEEnabled:        true,
				RAPLDisabled:       true,
				AliasCheckComplete: true,
			},
		},
		{
			input: 63,
			want: SnpPlatformInfo{
				TSMEEnabled:                 true,
				SMTEnabled:                  true,
				ECCEnabled:                  true,
				RAPLDisabled:                true,
				CiphertextHidingDRAMEnabled: true,
				AliasCheckComplete:          true,
			},
		},
		{
			input:   64,
			wantErr: "unrecognized platform info bit(s): 0x40",
		},
	}
	for _, tc := range tests {
		got, err := ParseSnpPlatformInfo(tc.input)
		if (err != nil && (tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr))) ||
			(err == nil && tc.wantErr != "") {
			t.Errorf("ParseSnpPlatformInfo(%x) errored unexpectedly. Got %v, want %v",
				tc.input, err, tc.wantErr)
		}
		if err == nil && tc.want != got {
			t.Errorf("ParseSnpPlatformInfo(%x) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestCpuid(t *testing.T) {
	// GitHub actions may run on AARCH64
	if runtime.GOARCH != "amd64" {
		t.Skip()
	}
	a, b, c, d := cpuid(1)
	if (a | b | c | d) == 0 {
		t.Errorf("cpuid(1) = 0, 0, 0, 0")
	}
}

type testCertTable struct {
	table    []byte
	extraraw []byte
}

const extraGUID = "00000000-0000-c0de-0000-000000000000"

func testRawCertTable(t testing.TB) *testCertTable {
	t.Helper()
	headers := make([]CertTableHeaderEntry, 6) // ARK, ASK, VCEK, VLEK, extra, NULL
	arkraw := []byte("ark")
	askraw := []byte("ask")
	vcekraw := []byte("vcek")
	vlekraw := []byte("vlek")
	extraraw := []byte("extra")
	headers[0].GUID = uuid.MustParse(ArkGUID)
	headers[0].Offset = uint32(len(headers) * CertTableEntrySize)
	headers[0].Length = uint32(len(arkraw))

	headers[1].GUID = uuid.MustParse(AskGUID)
	headers[1].Offset = headers[0].Offset + headers[0].Length
	headers[1].Length = uint32(len(askraw))

	headers[2].GUID = uuid.MustParse(VcekGUID)
	headers[2].Offset = headers[1].Offset + headers[1].Length
	headers[2].Length = uint32(len(vcekraw))

	headers[3].GUID = uuid.MustParse(VlekGUID)
	headers[3].Offset = headers[2].Offset + headers[2].Length
	headers[3].Length = uint32(len(vlekraw))

	headers[4].GUID = uuid.MustParse(extraGUID)
	headers[4].Offset = headers[3].Offset + headers[3].Length
	headers[4].Length = uint32(len(extraraw))

	result := &testCertTable{
		table:    make([]byte, headers[4].Offset+headers[4].Length),
		extraraw: extraraw,
	}
	for i, cert := range [][]byte{arkraw, askraw, vcekraw, vlekraw, extraraw} {
		if err := (&headers[i]).Write(result.table[i*CertTableEntrySize:]); err != nil {
			t.Fatalf("could not write header %d: %v", i, err)
		}
		copy(result.table[headers[i].Offset:], cert)
	}
	return result
}

func testRawCertTableNoVcek(t testing.TB) *testCertTable {
	t.Helper()
	headers := make([]CertTableHeaderEntry, 2) // extra, NULL
	extraraw := []byte("extra")

	headers[0].GUID = uuid.MustParse(extraGUID)
	headers[0].Offset = uint32(len(headers) * CertTableEntrySize)
	headers[0].Length = uint32(len(extraraw))
	result := &testCertTable{
		table:    make([]byte, headers[0].Offset+headers[0].Length),
		extraraw: extraraw,
	}
	for i, cert := range [][]byte{extraraw} {
		if err := (&headers[i]).Write(result.table[i*CertTableEntrySize:]); err != nil {
			t.Fatalf("could not write header %d: %v", i, err)
		}
		copy(result.table[headers[i].Offset:], cert)
	}
	return result
}

func TestCertTableProto(t *testing.T) {
	result := testRawCertTable(t)
	c := new(CertTable)
	if err := c.Unmarshal(result.table); err != nil {
		t.Errorf("c.Unmarshal(%s) = %v, want nil", hex.Dump(result.table), err)
	}
	p := c.Proto()
	if len(p.Extras) != 1 {
		t.Fatalf("got cert table Extras length %d, want 1", len(p.Extras))
	}
	gotExtra, ok := p.Extras[extraGUID]
	if !ok || !bytes.Equal(gotExtra, result.extraraw) {
		t.Fatalf("Extras[%q] = %v, want %v", extraGUID, gotExtra, result.extraraw)
	}
	bs := c.Marshal()
	if !bytes.Equal(bs, result.table) {
		t.Errorf("c.Marshal() = %v, want %v", bs, result.table)
	}
}

func TestSevProduct(t *testing.T) {
	oldCpuid := cpuid
	defer func() { cpuid = oldCpuid }()
	tcs := []struct {
		eax  uint32
		want *spb.SevProduct
	}{
		{
			eax: 0x00a00f10,
			want: &spb.SevProduct{
				Name:            spb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0},
			},
		},
		{
			eax: 0x00a00f11,
			want: &spb.SevProduct{
				Name:            spb.SevProduct_SEV_PRODUCT_MILAN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 1},
			},
		},
		{
			eax: 0x00a10f10,
			want: &spb.SevProduct{
				Name:            spb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0},
			},
		},
		{
			eax: 0x00a10f12,
			want: &spb.SevProduct{
				Name:            spb.SevProduct_SEV_PRODUCT_GENOA,
				MachineStepping: &wrapperspb.UInt32Value{Value: 2},
			},
		},
		{
			eax: 0x0b010f0,
			want: &spb.SevProduct{
				Name:            spb.SevProduct_SEV_PRODUCT_UNKNOWN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 0},
			},
		},
		{
			eax: 0x00b00f21,
			want: &spb.SevProduct{
				Name:            spb.SevProduct_SEV_PRODUCT_TURIN,
				MachineStepping: &wrapperspb.UInt32Value{Value: 1},
			},
		},
	}
	for _, tc := range tcs {
		t.Run(fmt.Sprintf("EAX_0x%x", tc.eax), func(t *testing.T) {
			cpuid = func(uint32) (uint32, uint32, uint32, uint32) { return tc.eax, 0, 0, 0 }
			got := SevProduct()
			if diff := cmp.Diff(got, tc.want, protocmp.Transform()); diff != "" {
				t.Errorf("SevProduct() = %+v, want %+v. Diff: %s", got, tc.want, diff)
			}
			got2 := SevProductFromCpuid1Eax(tc.eax)
			if diff := cmp.Diff(got2, got, protocmp.Transform()); diff != "" {
				t.Errorf("SevProductFromCpuid1Eax(0x%x) = %+v, want %+v. Diff: %s", tc.eax, got2, tc.want, diff)
			}
		})
	}
}

func TestExtendedPlatformCertTableConservation(t *testing.T) {
	// If VCEK is in the cert table, then the product info isn't added to the cert table.
	table := testRawCertTable(t).table
	oldt := new(CertTable)
	_ = oldt.Unmarshal(table)
	pold := oldt.Proto()

	nextTable, err := ExtendedPlatformCertTable(table)
	if err != nil {
		t.Fatalf("ExtendedPlatformCertTable(%v) =_, %v. Want nil", table, err)
	}

	newt := new(CertTable)
	if err := newt.Unmarshal(nextTable); err != nil {
		t.Fatalf("ExtendedPlatformCertTable(_) _ %v, which could not be unmarshaled: %v", nextTable, err)
	}
	pnew := newt.Proto()
	if len(pnew.Extras) != len(pold.Extras) {
		t.Fatalf("ExtendedPlatformCertTable(_) table extras size is %d, want %d", len(pnew.Extras), len(pold.Extras))
	}
}

func TestExtendedPlatformCertTable(t *testing.T) {
	oldCpuid := cpuid
	defer func() { cpuid = oldCpuid }()
	table := testRawCertTableNoVcek(t).table
	oldt := new(CertTable)
	_ = oldt.Unmarshal(table)
	pold := oldt.Proto()

	tcs := []struct {
		name     string
		pname    spb.SevProduct_SevProductName
		eax      uint32
		stepping uint32
	}{
		{name: "Genoa-B2", pname: spb.SevProduct_SEV_PRODUCT_GENOA, eax: 0x00a10f12, stepping: 2},
		{name: "Milan-B1", pname: spb.SevProduct_SEV_PRODUCT_MILAN, eax: 0x00a00f11, stepping: 1},
		{name: "Milan-B0", pname: spb.SevProduct_SEV_PRODUCT_MILAN, eax: 0x00a00f10, stepping: 0},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			cpuid = func(uint32) (uint32, uint32, uint32, uint32) { return tc.eax, 0, 0, 0 }
			nextTable, err := ExtendedPlatformCertTable(table)
			if err != nil {
				t.Fatalf("ExtendedPlatformCertTable(%v) =_, %v. Want nil", table, err)
			}

			newt := new(CertTable)
			if err := newt.Unmarshal(nextTable); err != nil {
				t.Fatalf("ExtendedPlatformCertTable(_) _ %v, which could not be unmarshaled: %v", nextTable, err)
			}
			pnew := newt.Proto()
			if len(pnew.Extras) != len(pold.Extras)+1 {
				t.Fatalf("ExtendedPlatformCertTable(_) table extras size is %d, want %d", len(pnew.Extras), len(pold.Extras)+1)
			}
			blob, ok := pnew.Extras[ExtraPlatformInfoGUID]
			if !ok {
				t.Fatalf("ExtendedPlatfromCertTable(_) table %v extras missing ExtraPlatformInfoGUID", pnew)
			}
			info, err := ParseExtraPlatformInfo(blob)
			if err != nil {
				t.Fatalf("ParseExtraPlatformInfo(%v) = _, %v. Want nil", blob, err)
			}
			if info.Size != ExtraPlatformInfoV0Size {
				t.Errorf("ExtraPltaformInfo Size %d is not %d", info.Size, ExtraPlatformInfoV0Size)
			}
			if info.Cpuid1Eax != tc.eax&CpuidProductMask {
				t.Errorf("ExtraPlatformInfo Cpuid1Eax 0x%x is not 0x%x", info.Cpuid1Eax, tc.eax&CpuidProductMask)
			}
			got := SevProductFromCpuid1Eax(info.Cpuid1Eax)
			want := &spb.SevProduct{Name: tc.pname, MachineStepping: &wrapperspb.UInt32Value{Value: tc.stepping}}
			if diff := cmp.Diff(got, want, protocmp.Transform()); diff != "" {
				t.Errorf("ExtraPlatformInfo Cpuid1Eax product %v is not %v: %s", got, want, diff)
			}
		})
	}
}
