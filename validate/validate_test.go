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

// Package validate is for checking attestation report properties other than signature verification.
package validate

import (
	"bytes"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	sg "github.com/google/go-sev-guest/client"
	labi "github.com/google/go-sev-guest/client/linuxabi"
	"github.com/google/go-sev-guest/kds"
	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/encoding/prototext"

	cpb "github.com/google/go-sev-guest/proto/check"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
)

const (
	snpReportVersion = 2
	debugPolicy      = 0xa0000
	ecdsaSigAlgo     = 1
)

func TestValidateSnpAttestation(t *testing.T) {
	mknonce := func(front []byte) [64]byte {
		var result [64]byte
		copy(result[:], front)
		return result
	}

	familyID := []byte{0x01, 0x03, 0x03, 0x07, 0x00, 0x0c, 0x00, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	imageID := []byte{0x0f, 0x0e, 0x0e, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f}
	measurement := []byte{0x01, 0x02, 0x03, 0x06, 0x05, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa0}
	hostData := []byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x0b}
	idKeyDigest := []byte{0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xee}
	authorKeyDigest := []byte{0xdd, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa}
	reportID := []byte{0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	reportIDMA := []byte{0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	chipID := [64]byte{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	goodtcb := kds.TCBVersionV0{
		BlSpl:    0x1f,
		TeeSpl:   0x7f,
		SnpSpl:   0x70,
		UcodeSpl: 0x92,
	}
	type testOptions struct {
		currentTcb     kds.TCBVersionV0
		reportedTcb    kds.TCBVersionV0
		committedTcb   kds.TCBVersionV0
		launchTcb      kds.TCBVersionV0
		signerInfo     abi.SignerInfo
		currentBuild   uint8
		currentMajor   uint8
		currentMinor   uint8
		committedBuild uint8
		committedMajor uint8
		committedMinor uint8
	}
	makeReport := func(reportData [64]byte, opts testOptions) [labi.SnpReportRespReportSize]byte {
		currentTcb := opts.currentTcb.Uint64()
		reportedTcb := opts.reportedTcb.Uint64()
		committedTcb := opts.committedTcb.Uint64()
		launchTcb := opts.launchTcb.Uint64()
		reportpb := &spb.Report{
			Version:         snpReportVersion,
			Policy:          debugPolicy,
			SignatureAlgo:   ecdsaSigAlgo,
			ReportData:      reportData[:],
			FamilyId:        familyID,
			ImageId:         imageID,
			Measurement:     measurement,
			HostData:        hostData,
			IdKeyDigest:     idKeyDigest,
			AuthorKeyDigest: authorKeyDigest,
			ReportId:        reportID,
			ReportIdMa:      reportIDMA,
			ChipId:          chipID[:],
			SignerInfo:      abi.ComposeSignerInfo(opts.signerInfo),
			CommittedBuild:  uint32(opts.committedBuild),
			CommittedMajor:  uint32(opts.committedMajor),
			CommittedMinor:  uint32(opts.committedMinor),
			CurrentBuild:    uint32(opts.currentBuild),
			CurrentMajor:    uint32(opts.currentMajor),
			CurrentMinor:    uint32(opts.currentMinor),
			PlatformInfo:    1,
			CommittedTcb:    uint64(committedTcb),
			CurrentTcb:      uint64(currentTcb),
			LaunchTcb:       uint64(launchTcb),
			ReportedTcb:     uint64(reportedTcb),
			Signature:       make([]byte, abi.SignatureSize),
		}
		reportRaw, err := abi.ReportToAbiBytes(reportpb)
		if err != nil {
			t.Fatal(err)
		}
		var result [labi.SnpReportRespReportSize]byte
		copy(result[:], reportRaw)
		return result
	}

	// Expensive: generate test keys.
	keys := test.DefaultAmdKeys()
	now := time.Now()
	productName := kds.ProductName(abi.DefaultSevProduct())
	sign0, err := test.DefaultTestOnlyCertChain(productName, now)
	if err != nil {
		t.Fatal(err)
	}
	sb := &test.AmdSignerBuilder{
		Keys:             keys,
		ProductName:      productName,
		ArkCreationTime:  now,
		AskCreationTime:  now,
		VcekCreationTime: now,
		VlekCreationTime: now,
		VcekCustom: test.CertOverride{
			Extensions: test.CustomExtensionsV0(
				goodtcb,
				chipID[:],
				"",
				productName,
			),
		},
		VlekCustom: test.CertOverride{
			Extensions: test.CustomExtensionsV0(
				goodtcb,
				nil,
				"Cloud Service Provider",
				productName,
			),
		},
	}
	sign, err := sb.TestOnlyCertChain()
	if err != nil {
		t.Fatal(err)
	}
	qp0, err := test.TcQuoteProvider(test.TestCases(),
		&test.DeviceOptions{Now: now, Signer: sign0, Product: abi.DefaultSevProduct()})
	if err != nil {
		t.Fatal(err)
	}

	rootBytes := append(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sign.Ask.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sign.Ark.Raw})...)

	opts := &test.DeviceOptions{
		Signer: sign,
		Now:    now,
	}
	baseOpts := testOptions{
		currentTcb:     goodtcb,
		committedTcb:   goodtcb,
		reportedTcb:    goodtcb,
		launchTcb:      goodtcb,
		signerInfo:     abi.SignerInfo{AuthorKeyEn: true},
		currentBuild:   2,
		committedBuild: 2,
		currentMajor:   1,
		committedMajor: 1,
		currentMinor:   49,
		committedMinor: 49,
	}
	var nonce0s1 [64]byte
	nonce0s1[63] = 1
	nonce12345 := mknonce([]byte{1, 2, 3, 4, 5})
	nonce54321 := mknonce([]byte{5, 4, 3, 2, 1})
	nonceb1455 := mknonce([]byte{0xb, 1, 4, 5, 5})
	noncecb1455 := mknonce([]byte{0xc, 0xb, 1, 4, 5, 5})
	nonce11355 := mknonce([]byte{1, 1, 3, 5, 5})

	tcs := []test.TestCase{
		{
			Name:   "deep validation",
			Input:  nonce12345,
			Output: makeReport(nonce12345, baseOpts),
		},
		{
			Name:  "no author key",
			Input: nonce54321,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.signerInfo = abi.SignerInfo{}
				return makeReport(nonce54321, opts)
			}(),
		},
		{
			Name:  "committed build less", // greater is architecturally illegal
			Input: nonceb1455,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.committedBuild = 1
				return makeReport(nonceb1455, opts)
			}(),
		},
		{
			Name:  "committed tcb less", // greater is architecturally illegal
			Input: noncecb1455,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.committedTcb = kds.TCBVersionV0{
					BlSpl:    0,
					TeeSpl:   0x7f,
					SnpSpl:   0x70,
					UcodeSpl: 0x92,
				}
				opts.launchTcb = opts.committedTcb
				return makeReport(noncecb1455, opts)
			}(),
		},
		{
			Name:  "committed version less", // greater is architecturally illegal
			Input: nonce11355,
			Output: func() [labi.SnpReportRespReportSize]byte {
				opts := baseOpts
				opts.committedMinor = 49
				opts.currentMinor = 51
				return makeReport(nonce11355, opts)
			}(),
		},
	}
	qp, err := test.TcQuoteProvider(tcs, opts)
	if err != nil {
		t.Fatal(err)
	}
	getter := test.SimpleGetter(
		map[string][]byte{
			"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": rootBytes,
			"https://kdsintf.amd.com/vcek/v1/Milan/0a0b0c0d0e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010203040506?blSPL=31&snpSPL=112&teeSPL=127&ucodeSPL=146": sign.Vcek.Raw,
		},
	)
	attestationFn := func(nonce [64]byte) *spb.Attestation {

		q, err := sg.GetQuoteProto(qp, nonce)
		if err != nil {
			t.Fatal(err)
		}
		report := q.Report
		attestation, err := verify.GetAttestationFromReport(report, &verify.Options{Getter: getter})
		if err != nil {
			t.Fatal(err)
		}
		return attestation
	}
	attestation12345 := attestationFn(nonce12345)
	attestation54321 := attestationFn(nonce54321)
	attestationb1455 := attestationFn(nonceb1455)
	attestationcb1455 := attestationFn(noncecb1455)
	attestation11355 := attestationFn(nonce11355)
	type testCase struct {
		name        string
		attestation *spb.Attestation
		opts        *Options
		wantErr     string
	}
	tests := []testCase{
		{
			name: "just reportData",
			attestation: func() *spb.Attestation {
				q, err := sg.GetQuoteProto(qp0, nonce0s1)
				if err != nil {
					t.Fatal(err)
				}
				report := q.Report
				return &spb.Attestation{
					Report: report,
					CertificateChain: &spb.CertificateChain{
						AskCert:  sign0.Ask.Raw,
						ArkCert:  sign0.Ark.Raw,
						VcekCert: sign0.Vcek.Raw,
					},
				}
			}(),
			opts: &Options{ReportData: nonce0s1[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
		},
		{
			name:        "deep check",
			attestation: attestation12345,
			opts: &Options{
				ReportData:             nonce12345[:],
				GuestPolicy:            abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:           &abi.SnpPlatformInfo{SMTEnabled: true},
				Measurement:            measurement,
				HostData:               hostData,
				ChipID:                 chipID[:],
				FamilyID:               familyID,
				ImageID:                imageID,
				RequireAuthorKey:       true,
				RequireIDBlock:         true,
				ReportID:               reportID,
				ReportIDMA:             reportIDMA,
				MinimumBuild:           2,
				MinimumVersion:         uint16((1 << 8) | 49),
				MinimumTCB:             kds.DecomposeTCBVersionV0(0x02 | (uint64(0x05) << 48) | (uint64(0x44) << 56)),
				TrustedAuthorKeyHashes: [][]byte{authorKeyDigest},
			},
		},
		{
			name:        "Minimum TCB checked",
			attestation: attestation12345,
			opts: &Options{
				ReportData:   nonce12345[:],
				GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},
				MinimumTCB:   kds.DecomposeTCBVersionV0(0x02 | (uint64(0x05) << 48) | (uint64(0xff) << 56)),
			},
			wantErr: "the report's REPORTED_TCB {BlSpl:31 TeeSpl:127 Spl4:0 Spl5:0 Spl6:0 Spl7:0 SnpSpl:112 UcodeSpl:146} is lower than the policy minimum TCB {BlSpl:2 TeeSpl:0 Spl4:0 Spl5:0 Spl6:0 Spl7:0 SnpSpl:5 UcodeSpl:255} in at least one component",
		},
		{
			name:        "Minimum build checked",
			attestation: attestation12345,
			opts: &Options{
				ReportData:   nonce12345[:],
				GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},
				MinimumBuild: 3,
			},
			wantErr: "firmware build number 2 is less than the required minimum 3",
		},
		{
			name:        "Minimum version checked",
			attestation: attestation12345,
			opts: &Options{
				ReportData:     nonce12345[:],
				GuestPolicy:    abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:   &abi.SnpPlatformInfo{SMTEnabled: true},
				MinimumVersion: 0xff00,
			},
			wantErr: "firmware API version (1.49) is less than the required minimum (255.0)",
		},
		{
			name:        "Author key checked",
			attestation: attestation54321,
			opts: &Options{
				ReportData:       nonce54321[:],
				GuestPolicy:      abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:     &abi.SnpPlatformInfo{SMTEnabled: true},
				RequireAuthorKey: true,
			},
			// Nevermind that author key digest is nonzero in the fake report.
			// That can't happen on real hardware.
			wantErr: "author key missing when required",
		},
		{
			name:        "PlatformInfo checked",
			attestation: attestation54321,
			opts: &Options{
				ReportData:   nonce54321[:],
				GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo: &abi.SnpPlatformInfo{},
			},
			wantErr: "unauthorized platform feature SMT enabled",
		},
		{
			name:        "Requiring IDBlock requires trust",
			attestation: attestation12345,
			opts: &Options{
				ReportData:     nonce12345[:],
				GuestPolicy:    abi.SnpPolicy{Debug: true, SMT: true},
				PlatformInfo:   &abi.SnpPlatformInfo{SMTEnabled: true},
				RequireIDBlock: true,
			},
			wantErr: "report ID key not trusted: ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ee",
		},
		// TODO(dionnaglaze): test varies ways provisional firmware shows up.
		// {name: "Provisional firmware"},
		{
			name:        "accepted provisional by build",
			attestation: attestationb1455,
			opts: &Options{
				ReportData:                nonceb1455[:],
				GuestPolicy:               abi.SnpPolicy{Debug: true},
				PermitProvisionalFirmware: true,
			},
		},
		{
			name:        "rejected provisional by build",
			attestation: attestationb1455,
			opts:        &Options{ReportData: nonceb1455[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
			wantErr:     "committed build number 1 does not match the current build number 2",
		},
		{
			name:        "accepted provisional by tcb",
			attestation: attestationcb1455,
			opts: &Options{
				ReportData:                noncecb1455[:],
				GuestPolicy:               abi.SnpPolicy{Debug: true},
				PermitProvisionalFirmware: true,
			},
		},
		{
			name:        "rejected provisional by tcb",
			attestation: attestationcb1455,
			opts:        &Options{ReportData: noncecb1455[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
			wantErr:     "the report's COMMITTED_TCB 0x9270000000007f00 does not match the report's CURRENT_TCB 0x9270000000007f1f",
		},
		{
			name:        "accepted provisional by version",
			attestation: attestation11355,
			opts: &Options{
				ReportData:                nonce11355[:],
				GuestPolicy:               abi.SnpPolicy{Debug: true},
				PermitProvisionalFirmware: true,
			},
		},
		{
			name:        "rejected provisional by version",
			attestation: attestation11355,
			opts:        &Options{ReportData: nonce11355[:], GuestPolicy: abi.SnpPolicy{Debug: true}},
			wantErr:     "committed API version (1.49) does not match the current API version (1.51)",
		},
	}
	numVerbatimFields := 8
	for i := 0; i < numVerbatimFields; i++ {
		opts := &Options{
			GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
			PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},
		}
		var name string
		switch i {
		case 0:
			name = "REPORT_DATA"
			opts.ReportData = make([]byte, abi.ReportDataSize)
		case 1:
			name = "HOST_DATA"
			opts.HostData = make([]byte, abi.HostDataSize)
		case 2:
			name = "FAMILY_ID"
			opts.FamilyID = make([]byte, abi.FamilyIDSize)
		case 3:
			name = "IMAGE_ID"
			opts.ImageID = make([]byte, abi.ImageIDSize)
		case 4:
			name = "REPORT_ID"
			opts.ReportID = make([]byte, abi.ReportIDSize)
		case 5:
			name = "REPORT_ID_MA"
			opts.ReportIDMA = make([]byte, abi.ReportIDMASize)
		case 6:
			name = "MEASUREMENT"
			opts.Measurement = make([]byte, abi.MeasurementSize)
		case 7:
			name = "CHIP_ID"
			opts.ChipID = make([]byte, abi.ChipIDReportSize)
		}
		tests = append(tests, testCase{
			name:        fmt.Sprintf("Test incorrect %s", name),
			attestation: attestation12345,
			opts:        opts,
			wantErr:     fmt.Sprintf("report field %s", name),
		})
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := SnpAttestation(tc.attestation, tc.opts); (err == nil && tc.wantErr != "") ||
				(err != nil && (tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr))) {
				t.Errorf("Got err '%v', want error containing '%s'", err, tc.wantErr)
			}
		})
	}
}

func TestCertTableOptions(t *testing.T) {
	sign0, err := test.DefaultTestOnlyCertChain(test.GetProductName(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	report := &spb.Report{}
	if err := prototext.Unmarshal([]byte(test.TestCases()[0].OutputProto), report); err != nil {
		t.Fatalf("could not unmarshal zero report: %v", err)
	}
	attestation := &spb.Attestation{
		Report: report,
		CertificateChain: &spb.CertificateChain{
			VcekCert: sign0.Vcek.Raw,
			Extras: map[string][]byte{
				"00000000-0000-c0de-0000-000000000000": []byte("findme"),
			},
		},
	}
	if err := SnpAttestation(attestation, &Options{
		GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
		PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},

		CertTableOptions: map[string]*CertEntryOption{
			"00000000-feee-feee-0000-000000000000": {
				Kind: CertEntryRequire,
				Validate: func(_ *spb.Attestation, blob []byte) error {
					if blob == nil {
						return fmt.Errorf("local data is required")
					}
					return nil
				},
			},
		},
	}); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("SnpAttestation(_, &Options{CertTableOptions: require feee-feee}) = %v, want error to contain %s", err, "required")
	}
	if err := SnpAttestation(attestation, &Options{
		GuestPolicy:  abi.SnpPolicy{Debug: true, SMT: true},
		PlatformInfo: &abi.SnpPlatformInfo{SMTEnabled: true},
		CertTableOptions: map[string]*CertEntryOption{
			"00000000-0000-c0de-0000-000000000000": {Kind: CertEntryRequire, Validate: func(_ *spb.Attestation, blob []byte) error {
				want := []byte("findme")
				if !bytes.Equal(blob, want) {
					return fmt.Errorf("c0de entry was %v, want %v", blob, want)
				}
				return nil
			}},
			"00000000-feee-feee-0000-000000000000": {Kind: CertEntryAllowMissing, Validate: func(*spb.Attestation, []byte) error { return errors.New("don't call me") }},
		},
	}); err != nil {
		t.Errorf("SnpAttestation(_, &Options{CertTableOptions: require c0de, allow feee-fee}) = %v, want nil", err)
	}

}

func TestCheckMitigationVectors(t *testing.T) {
	tests := []struct {
		name          string
		reportLaunch  uint64
		reportCurrent uint64
		opts          Options
		wantErr       bool
		wantErrSubstr string
	}{
		{
			name:          "Pass_NoRequirements",
			reportLaunch:  0x0,
			reportCurrent: 0x0,
			opts:          Options{},
			wantErr:       false,
		},
		{
			name:          "Pass_ExactMatch",
			reportLaunch:  0x3,
			reportCurrent: 0x1,
			opts: Options{
				MinimumLaunchMitigationVector:  0x3,
				MinimumCurrentMitigationVector: 0x1,
			},
			wantErr: false,
		},
		{
			name:          "Pass_Superset",
			reportLaunch:  0x7,
			reportCurrent: 0xF,
			opts: Options{
				MinimumLaunchMitigationVector:  0x3,
				MinimumCurrentMitigationVector: 0x1,
			},
			wantErr: false,
		},
		{
			name:          "Fail_MissingLaunchBit",
			reportLaunch:  0x1,
			reportCurrent: 0x3,
			opts: Options{
				MinimumLaunchMitigationVector: 0x3,
			},
			wantErr:       true,
			wantErrSubstr: "launch mitigation vector",
		},
		{
			name:          "Fail_MissingCurrentBit",
			reportLaunch:  0x3,
			reportCurrent: 0x4,
			opts: Options{
				MinimumCurrentMitigationVector: 0x5,
			},
			wantErr:       true,
			wantErrSubstr: "current mitigation vector",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockReport := &spb.Report{
				LaunchMitVector:  tc.reportLaunch,
				CurrentMitVector: tc.reportCurrent,
			}

			err := validateMitigationVectors(mockReport, &tc.opts)

			if (err != nil) != tc.wantErr {
				t.Errorf("checkMitigationVectors() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if tc.wantErr && err != nil {
				if !strings.Contains(err.Error(), tc.wantErrSubstr) {
					t.Errorf("expected error substring %q, got error: %v", tc.wantErrSubstr, err)
				}
			}
		})
	}
}

func TestValidateChipID(t *testing.T) {
	hwid8 := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	reportChipID := make([]byte, abi.ChipIDReportSize)
	copy(reportChipID, hwid8)

	// Turin: 8-byte match
	if err := validateChipID(spb.SevProduct_SEV_PRODUCT_TURIN, reportChipID, hwid8); err != nil {
		t.Errorf("validateChipID with 8-byte HWID on Turin failed: %v", err)
	}

	// Turin: 64-byte match
	if err := validateChipID(spb.SevProduct_SEV_PRODUCT_TURIN, reportChipID, reportChipID); err != nil {
		t.Errorf("validateChipID with 64-byte HWID on Turin failed: %v", err)
	}

	// Turin: 8-byte mismatch
	badHwid8 := []byte{1, 2, 3, 4, 5, 6, 7, 9}
	if err := validateChipID(spb.SevProduct_SEV_PRODUCT_TURIN, reportChipID, badHwid8); err == nil {
		t.Errorf("validateChipID with mismatched 8-byte HWID on Turin expected error, got nil")
	}

	// Turin: invalid option length (16 bytes)
	if err := validateChipID(spb.SevProduct_SEV_PRODUCT_TURIN, reportChipID, make([]byte, 16)); err == nil {
		t.Errorf("validateChipID with 16-byte HWID on Turin expected error, got nil")
	}

	// Turin: invalid option length (12 bytes)
	if err := validateChipID(spb.SevProduct_SEV_PRODUCT_TURIN, reportChipID, make([]byte, 12)); err == nil {
		t.Errorf("validateChipID with 12-byte HWID on Turin expected error, got nil")
	}

	// Milan: 8-byte option rejected
	if err := validateChipID(spb.SevProduct_SEV_PRODUCT_MILAN, reportChipID, hwid8); err == nil {
		t.Errorf("validateChipID with 8-byte HWID on Milan expected error, got nil")
	}

	// Milan: 64-byte match
	if err := validateChipID(spb.SevProduct_SEV_PRODUCT_MILAN, reportChipID, reportChipID); err != nil {
		t.Errorf("validateChipID with 64-byte HWID on Milan failed: %v", err)
	}
}

func TestCheckOptionsLengthsChipID(t *testing.T) {
	// Nil ChipID
	if err := checkOptionsLengths(&Options{}); err != nil {
		t.Errorf("checkOptionsLengths with nil ChipID failed: %v", err)
	}
	// Turin-size ChipID
	if err := checkOptionsLengths(&Options{ChipID: make([]byte, abi.ChipIDStruct1Size)}); err != nil {
		t.Errorf("checkOptionsLengths with %d-byte ChipID failed: %v", abi.ChipIDStruct1Size, err)
	}
	// 64-byte ChipID
	if err := checkOptionsLengths(&Options{ChipID: make([]byte, abi.ChipIDReportSize)}); err != nil {
		t.Errorf("checkOptionsLengths with %d-byte ChipID failed: %v", abi.ChipIDReportSize, err)
	}
	// 16-byte ChipID is invalid
	if err := checkOptionsLengths(&Options{ChipID: make([]byte, 16)}); err == nil {
		t.Errorf("checkOptionsLengths with 16-byte ChipID expected error, got nil")
	}
	// 12-byte ChipID is invalid
	if err := checkOptionsLengths(&Options{ChipID: make([]byte, 12)}); err == nil {
		t.Errorf("checkOptionsLengths with 12-byte ChipID expected error, got nil")
	}
}

func TestTcbGtErrorStructVersionMismatch(t *testing.T) {
	v0 := kds.TCBVersionV0{}
	v1 := kds.TCBVersionV1{}
	err := tcbGtError(
		partDescription{tcb: v0, desc: "policy minimum TCB"},
		partDescription{tcb: v1, desc: "report's REPORTED_TCB"},
	)
	if err == nil {
		t.Fatalf("expected error on struct version mismatch, got nil")
	}
	wantSubstring := "StructVersion 0 does not match"
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Errorf("tcbGtError returned %q, want substring %q", err.Error(), wantSubstring)
	}
}

func TestTcbNeErrorStructVersionMismatch(t *testing.T) {
	v0 := kds.TCBVersionV0{}
	v1 := kds.TCBVersionV1{}
	err := tcbNeError(
		partDescription{tcb: v0, desc: "TCB of the V[CL]EK certificate"},
		partDescription{tcb: v1, desc: "report's REPORTED_TCB"},
	)
	if err == nil {
		t.Fatalf("expected error on struct version mismatch, got nil")
	}
	wantSubstring := "StructVersion 0 does not match"
	if !strings.Contains(err.Error(), wantSubstring) {
		t.Errorf("tcbNeError returned %q, want substring %q", err.Error(), wantSubstring)
	}
}

func TestSnpAttestationCertificateStructVersionMismatch(t *testing.T) {
	signMilan, err := test.DefaultTestOnlyCertChain("Milan-B0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	signTurin, err := test.DefaultTestOnlyCertChain("Turin-B0", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	turinReport := &spb.Report{
		SignerInfo:   abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VcekReportSigner}),
		Cpuid1EaxFms: abi.MaskedCpuid1EaxFromSevProduct(&spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_TURIN}),
	}
	milanCertOnTurinReport := &spb.Attestation{
		Report: turinReport,
		CertificateChain: &spb.CertificateChain{
			VcekCert: signMilan.Vcek.Raw,
		},
	}
	err = SnpAttestation(milanCertOnTurinReport, &Options{})
	if err == nil || !strings.Contains(err.Error(), "certificate structVersion 0 does not match report expected structVersion 1") {
		t.Errorf("expected structVersion mismatch error, got: %v", err)
	}

	milanReport := &spb.Report{
		SignerInfo:   abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VcekReportSigner}),
		Cpuid1EaxFms: abi.MaskedCpuid1EaxFromSevProduct(&spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_MILAN}),
	}
	turinCertOnMilanReport := &spb.Attestation{
		Report: milanReport,
		CertificateChain: &spb.CertificateChain{
			VcekCert: signTurin.Vcek.Raw,
		},
	}
	err = SnpAttestation(turinCertOnMilanReport, &Options{})
	if err == nil || !strings.Contains(err.Error(), "certificate structVersion 1 does not match report expected structVersion 0") {
		t.Errorf("expected structVersion mismatch error, got: %v", err)
	}
}

func TestSnpAttestationTurinSuccess(t *testing.T) {
	signTurin, err := test.DefaultTestOnlyCertChain("Turin-B0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	exts, err := kds.VcekCertificateExtensions(signTurin.Vcek)
	if err != nil {
		t.Fatal(err)
	}

	reportChipID := make([]byte, abi.ChipIDReportSize)
	copy(reportChipID, exts.HWID)

	turinReport := &spb.Report{
		SignerInfo:   abi.ComposeSignerInfo(abi.SignerInfo{SigningKey: abi.VcekReportSigner}),
		Cpuid1EaxFms: abi.MaskedCpuid1EaxFromSevProduct(&spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_TURIN}),
		Policy:       abi.SnpPolicyToBytes(abi.SnpPolicy{}),
		ReportedTcb:  exts.TCBVersion.Uint64(),
		CurrentTcb:   exts.TCBVersion.Uint64(),
		CommittedTcb: exts.TCBVersion.Uint64(),
		LaunchTcb:    exts.TCBVersion.Uint64(),
		ChipId:       reportChipID,
	}
	attestation := &spb.Attestation{
		Report: turinReport,
		CertificateChain: &spb.CertificateChain{
			VcekCert: signTurin.Vcek.Raw,
		},
	}

	// Default options (no explicit constraints)
	if err := SnpAttestation(attestation, &Options{}); err != nil {
		t.Errorf("SnpAttestation with valid Turin report and cert failed: %v", err)
	}

	// Matching Turin ChipID option
	if err := SnpAttestation(attestation, &Options{ChipID: exts.HWID}); err != nil {
		t.Errorf("SnpAttestation with matching %d-byte ChipID failed: %v", abi.ChipIDStruct1Size, err)
	}

	// Mismatched Turin ChipID option
	mismatchedTurin := make([]byte, abi.ChipIDStruct1Size)
	copy(mismatchedTurin, exts.HWID)
	mismatchedTurin[0] ^= 0xff
	if err := SnpAttestation(attestation, &Options{ChipID: mismatchedTurin}); err == nil {
		t.Errorf("SnpAttestation with mismatched %d-byte ChipID expected error, got nil", abi.ChipIDStruct1Size)
	}

	// Matching 64-byte ChipID option
	if err := SnpAttestation(attestation, &Options{ChipID: reportChipID}); err != nil {
		t.Errorf("SnpAttestation with matching 64-byte ChipID failed: %v", err)
	}

	// Mismatched 64-byte ChipID option
	mismatched64 := make([]byte, abi.ChipIDReportSize)
	copy(mismatched64, reportChipID)
	mismatched64[0] ^= 0xff
	if err := SnpAttestation(attestation, &Options{ChipID: mismatched64}); err == nil {
		t.Errorf("SnpAttestation with mismatched 64-byte ChipID expected error, got nil")
	}
}

func TestPolicyToOptions(t *testing.T) {
	validPolicy := abi.SnpPolicyToBytes(abi.SnpPolicy{})

	// Turin product with non-zero minimum_tcb decomposes to TCBVersionV1
	turinPolicy := &cpb.Policy{
		Policy:     validPolicy,
		Product:    &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_TURIN},
		MinimumTcb: 0x0102030405060708,
	}
	turinOpts, err := PolicyToOptions(turinPolicy)
	if err != nil {
		t.Fatalf("PolicyToOptions(turinPolicy) failed: %v", err)
	}
	if turinOpts.MinimumTCB == nil || turinOpts.MinimumTCB.StructVersion() != 1 {
		t.Errorf("PolicyToOptions(turinPolicy).MinimumTCB StructVersion = %v, want 1",
			turinOpts.MinimumTCB)
	}

	// Milan product with non-zero minimum_tcb decomposes to TCBVersionV0
	milanPolicy := &cpb.Policy{
		Policy:     validPolicy,
		Product:    &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_MILAN},
		MinimumTcb: 0x0102030405060708,
	}
	milanOpts, err := PolicyToOptions(milanPolicy)
	if err != nil {
		t.Fatalf("PolicyToOptions(milanPolicy) failed: %v", err)
	}
	if milanOpts.MinimumTCB == nil || milanOpts.MinimumTCB.StructVersion() != 0 {
		t.Errorf("PolicyToOptions(milanPolicy).MinimumTCB StructVersion = %v, want 0",
			milanOpts.MinimumTCB)
	}

	// Zero minimum_tcb leaves MinimumTCB as nil
	zeroPolicy := &cpb.Policy{
		Policy:     validPolicy,
		Product:    &spb.SevProduct{Name: spb.SevProduct_SEV_PRODUCT_TURIN},
		MinimumTcb: 0,
	}
	zeroOpts, err := PolicyToOptions(zeroPolicy)
	if err != nil {
		t.Fatalf("PolicyToOptions(zeroPolicy) failed: %v", err)
	}
	if zeroOpts.MinimumTCB != nil {
		t.Errorf("PolicyToOptions(zeroPolicy).MinimumTCB = %v, want nil", zeroOpts.MinimumTCB)
	}
}

func TestValidateTcbUnsupportedStructVersion(t *testing.T) {
	report := &spb.Report{}
	err := validateTcb(report, kds.TCBVersionV0{}, &Options{}, 2)
	if err == nil || !strings.Contains(err.Error(), "unsupported TCB structVersion: 2") {
		t.Errorf("validateTcb with structVersion 2 error = %v, want unsupported TCB structVersion: 2", err)
	}
}
