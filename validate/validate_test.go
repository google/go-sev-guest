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
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/prototext"

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
	goodtcb := kds.TCBParts{
		BlSpl:    0x1f,
		TeeSpl:   0x7f,
		SnpSpl:   0x70,
		UcodeSpl: 0x92,
	}
	type testOptions struct {
		currentTcb     kds.TCBParts
		reportedTcb    kds.TCBParts
		committedTcb   kds.TCBParts
		launchTcb      kds.TCBParts
		signerInfo     abi.SignerInfo
		currentBuild   uint8
		currentMajor   uint8
		currentMinor   uint8
		committedBuild uint8
		committedMajor uint8
		committedMinor uint8
	}
	makeReport := func(reportData [64]byte, opts testOptions) [labi.SnpReportRespReportSize]byte {
		currentTcb, currerr := kds.ComposeTCBParts(opts.currentTcb)
		reportedTcb, reportederr := kds.ComposeTCBParts(opts.reportedTcb)
		committedTcb, committederr := kds.ComposeTCBParts(opts.committedTcb)
		launchTcb, launcherr := kds.ComposeTCBParts(opts.launchTcb)
		if err := multierr.Combine(currerr,
			reportederr,
			committederr,
			launcherr); err != nil {
			t.Fatal(err)
		}
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
	keys, err := test.DefaultAmdKeys()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sign0, err := test.DefaultTestOnlyCertChain(kds.DefaultProductString(), now)
	if err != nil {
		t.Fatal(err)
	}
	sb := &test.AmdSignerBuilder{
		Keys:             keys,
		Product:          kds.DefaultProductString(),
		ArkCreationTime:  now,
		AskCreationTime:  now,
		VcekCreationTime: now,
		VlekCreationTime: now,
		VcekCustom: test.CertOverride{
			Extensions: test.CustomExtensions(
				goodtcb,
				chipID[:],
				"",
			),
		},
		VlekCustom: test.CertOverride{
			Extensions: test.CustomExtensions(
				goodtcb,
				nil,
				"Cloud Service Provider",
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
				tcb := goodtcb
				tcb.BlSpl = 0
				opts.committedTcb = tcb
				opts.launchTcb = tcb
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
			"https://kdsintf.amd.com/vcek/v1/Milan/0a0b0c0d0e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010203040506?blSPL=31&teeSPL=127&snpSPL=112&ucodeSPL=146": sign.Vcek.Raw,
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
				MinimumTCB:             kds.TCBParts{UcodeSpl: 0x44, SnpSpl: 0x05, BlSpl: 0x02},
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
				MinimumTCB:   kds.TCBParts{UcodeSpl: 0xff, SnpSpl: 0x05, BlSpl: 0x02},
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
			opts.ChipID = make([]byte, abi.ChipIDSize)
		}
		tests = append(tests, testCase{
			name:        fmt.Sprintf("Test incorrect %s", name),
			attestation: attestation12345,
			opts:        opts,
			wantErr:     fmt.Sprintf("report field %s", name),
		})
	}

	for _, tc := range tests {
		if err := SnpAttestation(tc.attestation, tc.opts); (err == nil && tc.wantErr != "") ||
			(err != nil && (tc.wantErr == "" || !strings.Contains(err.Error(), tc.wantErr))) {
			t.Errorf("%s: SnpAttestation(%v) errored unexpectedly. Got '%v', want '%s'", tc.name, tc.attestation, err, tc.wantErr)
		}
	}
}

func TestCertTableOptions(t *testing.T) {
	sign0, err := test.DefaultTestOnlyCertChain(kds.DefaultProductString(), time.Now())
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
			"00000000-feee-feee-0000-000000000000": {Kind: CertEntryRequire, Validate: func(*spb.Attestation, []byte) error { return nil }},
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
