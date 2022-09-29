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

package verify

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"encoding/asn1"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	sg "github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/kds"
	test "github.com/google/go-sev-guest/testing"
)

// These certificates are committed regardless of its expiration date since we adjust the
// CurrentTime to compare against so that the validity with respect to time is always true.
//
//go:embed testdata/vcek.testcer
var vcekBytes []byte

//go:embed testdata/milan.testcer
var milanBytes []byte

//go:embed testdata/attestation.bin
var attestationBytes []byte

const product = "Milan"

var signMu sync.Once
var signer *test.AmdSigner

func initSigner() {
	newSigner, err := test.DefaultCertChain(product, time.Now())
	if err != nil { // Unexpected
		panic(err)
	}
	signer = newSigner
}

func TestEmbeddedCertsAppendixB3Expectations(t *testing.T) {
	// https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf
	// Appendix B.1
	for _, root := range DefaultRootCerts {
		if err := root.ValidateAskSev(); err != nil {
			t.Errorf("Embedded ASK failed validation: %v", err)
		}
		if err := root.ValidateArkSev(); err != nil {
			t.Errorf("Embedded ARK failed validation: %v", err)
		}
	}
}

func TestFakeCertsKDSExpectations(t *testing.T) {
	signMu.Do(initSigner)
	root := AMDRootCerts{
		Product: product,
		ArkX509: signer.Ark,
		AskX509: signer.Ask,
		// No ArkSev or AskSev intentionally for test certs.
	}
	if err := root.ValidateArkX509(); err != nil {
		t.Errorf("fake ARK validation error: %v", err)
	}
	if err := root.ValidateAskX509(); err != nil {
		t.Errorf("fake ASK validation error: %v", err)
	}
}

func TestParseVcekCert(t *testing.T) {
	cert, err := x509.ParseCertificate(vcekBytes)
	if err != nil {
		t.Errorf("could not parse valid VCEK certificate: %v", err)
	}
	if _, err := validateVcekCertificateProductNonspecific(cert); err != nil {
		t.Errorf("could not validate valid VCEK certificate: %v", err)
	}
}

func TestVerifyVcekCert(t *testing.T) {
	// This certificate is committed regardless of its expiration date, but we'll adjust the
	// CurrentTime to compare against so that the validity with respect to time is always true.
	root := new(AMDRootCerts)
	if err := root.FromKDSCertBytes(milanBytes); err != nil {
		t.Fatalf("could not read Milan certificate file: %v", err)
	}
	vcek, err := x509.ParseCertificate(vcekBytes)
	if err != nil {
		t.Errorf("could not parse valid VCEK certificate: %v", err)
	}
	opts := root.X509Options()
	if opts == nil {
		t.Fatalf("root x509 certificates missing: %v", root)
	}
	// This time is within the 25 year lifespan of the Milan product.
	opts.CurrentTime = time.Date(2022, time.September, 24, 1, 0, 0, 0, time.UTC)
	chains, err := vcek.Verify(*opts)
	if err != nil {
		t.Errorf("could not verify VCEK certificate: %v", err)
	}
	if len(chains) != 1 {
		t.Fatalf("x509 verification returned %d chains, want 1", len(chains))
	}
	if len(chains[0]) != 3 {
		t.Fatalf("x509 verification returned a chain of length %d, want length 3", len(chains[0]))
	}
	if !chains[0][0].Equal(vcek) {
		t.Errorf("VCEK verification chain did not start with the VCEK certificate: %v", chains[0][0])
	}
	if !chains[0][1].Equal(root.AskX509) {
		t.Errorf("VCEK verification chain did not step to with the ASK certificate: %v", chains[0][1])
	}
	if !chains[0][2].Equal(root.ArkX509) {
		t.Errorf("VCEK verification chain did not end with the ARK certificate: %v", chains[0][2])
	}
}

func TestSnpReportSignature(t *testing.T) {
	tests := test.TestCases()
	now := time.Date(2022, time.May, 3, 9, 0, 0, 0, time.UTC)
	d, err := test.TcDevice(tests, &test.DeviceOptions{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Open("/dev/sev-guest"); err != nil {
		t.Error(err)
	}
	defer d.Close()
	for _, tc := range tests {
		// Does the Raw report match expectations?
		raw, err := sg.GetRawReport(d, tc.Input)
		if err != tc.WantErr {
			t.Fatalf("GetRawReport(d, %v) = %v, %v. Want err: %v", tc.Input, raw, err, tc.WantErr)
		}
		if tc.WantErr == nil {
			got := abi.SignedComponent(raw)
			want := abi.SignedComponent(tc.Output[:])
			if !bytes.Equal(got, want) {
				t.Errorf("%s: GetRawReport(%v) = %v, want %v", tc.Name, tc.Input, got, want)
			}
			if err := SnpReportSignature(raw, d.Signer.Vcek); err != nil {
				t.Errorf("signature with test keys did not verify: %v", err)
			}
		}
	}
}

func TestKdsMetadataLogic(t *testing.T) {
	signMu.Do(initSigner)
	asn1Zero, _ := asn1.Marshal(0)
	productName, _ := asn1.Marshal("Cookie-B0")
	var hwid [64]byte
	asn1Hwid, _ := asn1.Marshal(hwid[:])
	tests := []struct {
		name    string
		builder test.AmdSignerBuilder
		wantErr string
	}{
		{
			name:    "no error",
			builder: test.AmdSignerBuilder{Keys: signer.Keys},
		},
		{
			name: "ARK issuer country",
			builder: test.AmdSignerBuilder{
				Keys: signer.Keys,
				ArkCustom: test.CertOverride{
					Issuer:  &pkix.Name{Country: []string{"Canada"}},
					Subject: &pkix.Name{Country: []string{"Canada"}},
				},
			},
			wantErr: "country 'Canada' not expected for AMD. Expected 'US'",
		},
		{
			name: "ARK wrong CRL",
			builder: test.AmdSignerBuilder{
				Keys: signer.Keys,
				ArkCustom: test.CertOverride{
					CRLDistributionPoints: []string{"http://example.com"},
				},
			},
			wantErr: "ARK CRL distribution point is 'http://example.com', want 'https://kdsintf.amd.com/vcek/v1/Milan/crl'",
		},
		{
			name: "ARK too many CRLs",
			builder: test.AmdSignerBuilder{
				Keys: signer.Keys,
				ArkCustom: test.CertOverride{
					CRLDistributionPoints: []string{"https://kdsintf.amd.com/vcek/v1/Milan/crl", "http://example.com"},
				},
			},
			wantErr: "ARK has 2 CRL distribution points, want 1",
		},
		{
			name: "ASK subject state",
			builder: test.AmdSignerBuilder{
				Keys: signer.Keys,
				ArkCustom: test.CertOverride{
					Subject: &pkix.Name{
						Country:  []string{"US"},
						Locality: []string{"Santa Clara"},
						Province: []string{"TX"},
					},
				},
			},
			wantErr: "state 'TX' not expected for AMD. Expected 'CA'",
		},
		{
			name: "VCEK unknown product",
			builder: test.AmdSignerBuilder{
				Keys: signer.Keys,
				VcekCustom: test.CertOverride{
					Extensions: []pkix.Extension{
						{
							Id:    kds.OidStructVersion,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidProductName1,
							Value: productName,
						},
						{
							Id:    kds.OidBlSpl,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidTeeSpl,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidSnpSpl,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidSpl4,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidSpl5,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidSpl6,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidSpl7,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidUcodeSpl,
							Value: asn1Zero,
						},
						{
							Id:    kds.OidHwid,
							Value: asn1Hwid,
						},
					},
				},
			},
			wantErr: "unknown VCEK product name: Cookie-B0",
		},
	}
	for _, tc := range tests {
		bcopy := tc.builder
		newSigner, err := (&bcopy).CertChain()
		if err != nil {
			t.Errorf("%+v.CertChain() errored unexpectedly: %v", tc.builder, err)
			continue
		}
		// Trust the test-generated root if the test should pass. Otherwise, other root logic
		// won't get tested.
		options := &Options{TrustedRoots: map[string][]*AMDRootCerts{
			"Milan": {&AMDRootCerts{
				Product: "Milan",
				ArkX509: newSigner.Ark,
				AskX509: newSigner.Ask,
			}},
		}}
		if tc.wantErr != "" {
			options = &Options{}
		}
		vcek, _, err := VcekDER(newSigner.Vcek.Raw, newSigner.Ask.Raw, newSigner.Ark.Raw, options)
		if err == nil && tc.wantErr != "" {
			t.Errorf("%s: VcekDER(...) = %+v did not error as expected.", tc.name, vcek)
		}
		if err != nil && tc.wantErr == "" {
			t.Errorf("%s: VcekDER(...) errored unexpectedly: %v", tc.name, err)
		}
		if err != nil && tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%s: VcekDER(...) did not error as expected. Got %v, want %s", tc.name, err, tc.wantErr)
		}
	}
}

func TestCRLRootValidity(t *testing.T) {
	// Tests that the CRL is signed by the ARK.
	signMu.Do(initSigner)
	now := time.Date(2022, time.June, 14, 12, 0, 0, 0, time.UTC)

	ark2, err := test.DefaultArk()
	if err != nil {
		t.Fatal(err)
	}
	sb := &test.AmdSignerBuilder{
		Product:          "Milan",
		ArkCreationTime:  now,
		AskCreationTime:  now,
		VcekCreationTime: now,
		Keys: &test.AmdKeys{
			Ark:  ark2,
			Ask:  signer.Keys.Ask,
			Vcek: signer.Keys.Vcek,
		},
		VcekCustom: test.CertOverride{
			SerialNumber: big.NewInt(0xd),
		},
		AskCustom: test.CertOverride{
			SerialNumber: big.NewInt(0x8088),
		},
	}
	signer2, err := sb.CertChain()
	if err != nil {
		t.Fatal(err)
	}

	insecureRandomness := rand.New(rand.NewSource(0xc0de))
	afterCreation := now.Add(1 * time.Minute)
	template := &x509.RevocationList{
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		RevokedCertificates: []pkix.RevokedCertificate{
			// The default fake VCEK serial number is 0.
			{SerialNumber: big.NewInt(0), RevocationTime: afterCreation},
			{SerialNumber: big.NewInt(0x8088), RevocationTime: afterCreation},
		},
		Number: big.NewInt(1),
	}
	root := &AMDRootCerts{
		Product: "Milan",
		ArkX509: signer.Ark,
		AskX509: signer.Ask,
	}

	// Now try signing a CRL with a different root that certifies Vcek with a different serial number.
	crl, err := x509.CreateRevocationList(insecureRandomness, template, signer2.Ark, signer2.Keys.Ark)
	if err != nil {
		t.Fatal(err)
	}
	g2 := &test.Getter{
		Responses: map[string][]byte{
			"https://kdsintf.amd.com/vcek/v1/Milan/crl": crl,
		},
	}
	wantErr := "CRL is not signed by ARK"
	if err := root.VcekNotRevoked(g2, signer2.Vcek); err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Errorf("Bad Root: VcekNotRevoked(%v) did not error as expected. Got %v, want %v", signer.Vcek, err, wantErr)
	}

	// Finally try checking a VCEK that's signed by a revoked ASK.
	root2 := &AMDRootCerts{
		Product: "Milan",
		ArkX509: signer2.Ark,
		AskX509: signer2.Ask,
	}
	wantErr2 := "ASK was revoked at 2022-06-14 12:01:00 +0000 UTC"
	if err := root2.VcekNotRevoked(g2, signer2.Vcek); err == nil || !strings.Contains(err.Error(), wantErr2) {
		t.Errorf("Bad ASK: VcekNotRevoked(%v) did not error as expected. Got %v, want %v", signer.Vcek, err, wantErr2)
	}
}

func TestOpenGetExtendedReportVerifyClose(t *testing.T) {
	tests := test.TestCases()
	d, err := test.TcDevice(tests, &test.DeviceOptions{Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Open("/dev/sev-guest"); err != nil {
		t.Error(err)
	}
	defer d.Close()
	// Trust the test device's root certs.
	options := &Options{TrustedRoots: map[string][]*AMDRootCerts{
		"Milan": {&AMDRootCerts{
			Product: "Milan",
			ArkX509: d.Signer.Ark,
			AskX509: d.Signer.Ask,
		}}}}
	for _, tc := range tests {
		ereport, err := sg.GetExtendedReport(d, tc.Input)
		if err != tc.WantErr {
			t.Fatalf("%s: GetExtendedReport(d, %v) = %v, %v. Want err: %v", tc.Name, tc.Input, ereport, err, tc.WantErr)
		}
		if tc.WantErr == nil {
			if err := SnpAttestation(ereport, options); err != nil {
				t.Errorf("SnpAttestation(%v) errored unexpectedly: %v", ereport, err)
			}
		}
	}
}

func TestRealAttestationVerification(t *testing.T) {
	var nonce [64]byte
	copy(nonce[:], []byte{1, 2, 3, 4, 5})
	getter := &test.Getter{
		Responses: map[string][]byte{
			"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": milanBytes,
			// Use the VCEK's hwID and known TCB values to specify the URL its VCEK cert would be fetched from.
			"https://kdsintf.amd.com/vcek/v1/Milan/3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68": vcekBytes,
		},
	}
	if err := RawSnpReport(attestationBytes, &Options{Getter: getter}); err != nil {
		t.Error(err)
	}
}
