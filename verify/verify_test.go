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
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	sg "github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/kds"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	test "github.com/google/go-sev-guest/testing"
	testclient "github.com/google/go-sev-guest/testing/client"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/logger"
)

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

func TestMain(m *testing.M) {
	logger.Init("VerifyTestLog", false, false, os.Stderr)
	os.Exit(m.Run())
}

func TestEmbeddedCertsAppendixB3Expectations(t *testing.T) {
	// https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf
	// Appendix B.1
	for _, root := range trust.DefaultRootCerts {
		if err := ValidateAskSev(root); err != nil {
			t.Errorf("Embedded ASK failed validation: %v", err)
		}
		if err := ValidateArkSev(root); err != nil {
			t.Errorf("Embedded ARK failed validation: %v", err)
		}
	}
}

func TestFakeCertsKDSExpectations(t *testing.T) {
	signMu.Do(initSigner)
	trust.ClearProductCertCache()
	root := &trust.AMDRootCerts{
		Product: product,
		ProductCerts: &trust.ProductCerts{
			Ark: signer.Ark,
			Ask: signer.Ask,
		},
		// No ArkSev or AskSev intentionally for test certs.
	}
	if err := ValidateArkX509(root); err != nil {
		t.Errorf("fake ARK validation error: %v", err)
	}
	if err := ValidateAskX509(root); err != nil {
		t.Errorf("fake ASK validation error: %v", err)
	}
}

func TestParseVcekCert(t *testing.T) {
	cert, err := x509.ParseCertificate(testdata.VcekBytes)
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
	root := new(trust.AMDRootCerts)
	if err := root.FromKDSCertBytes(testdata.MilanBytes); err != nil {
		t.Fatalf("could not read Milan certificate file: %v", err)
	}
	vcek, err := x509.ParseCertificate(testdata.VcekBytes)
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
	if !chains[0][1].Equal(root.ProductCerts.Ask) {
		t.Errorf("VCEK verification chain did not step to with the ASK certificate: %v", chains[0][1])
	}
	if !chains[0][2].Equal(root.ProductCerts.Ark) {
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
		if testclient.SkipUnmockableTestCase(&tc) {
			continue
		}
		// Does the Raw report match expectations?
		raw, err := sg.GetRawReport(d, tc.Input)
		if !test.Match(err, tc.WantErr) {
			t.Fatalf("GetRawReport(d, %v) = %v, %v. Want err: %v", tc.Input, raw, err, tc.WantErr)
		}
		if tc.WantErr == "" {
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
	trust.ClearProductCertCache()
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
		options := &Options{TrustedRoots: map[string][]*trust.AMDRootCerts{
			"Milan": {&trust.AMDRootCerts{
				Product: "Milan",
				ProductCerts: &trust.ProductCerts{
					Ark: newSigner.Ark,
					Ask: newSigner.Ask,
				},
			}},
		}}
		if tc.wantErr != "" {
			options = &Options{}
		}
		vcek, _, err := VcekDER(newSigner.Vcek.Raw, newSigner.Ask.Raw, newSigner.Ark.Raw, options)
		if !test.Match(err, tc.wantErr) {
			t.Errorf("%s: VcekDER(...) = %+v, %v did not error as expected. Want %q", tc.name, vcek, err, tc.wantErr)
		}
	}
}

func TestCRLRootValidity(t *testing.T) {
	// Tests that the CRL is signed by the ARK.
	signMu.Do(initSigner)
	trust.ClearProductCertCache()
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
	root := &trust.AMDRootCerts{
		Product: "Milan",
		ProductCerts: &trust.ProductCerts{
			Ark: signer.Ark,
			Ask: signer.Ask,
		},
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
	if err := VcekNotRevoked(root, g2, signer2.Vcek); !test.Match(err, wantErr) {
		t.Errorf("Bad Root: VcekNotRevoked(%v) did not error as expected. Got %v, want %v", signer.Vcek, err, wantErr)
	}

	// Finally try checking a VCEK that's signed by a revoked ASK.
	root2 := &trust.AMDRootCerts{
		Product: "Milan",
		ProductCerts: &trust.ProductCerts{
			Ark: signer2.Ark,
			Ask: signer2.Ask,
		},
	}
	wantErr2 := "ASK was revoked at 2022-06-14 12:01:00 +0000 UTC"
	if err := VcekNotRevoked(root2, g2, signer2.Vcek); !test.Match(err, wantErr2) {
		t.Errorf("Bad ASK: VcekNotRevoked(%v) did not error as expected. Got %v, want %v", signer.Vcek, err, wantErr2)
	}
}

func TestOpenGetExtendedReportVerifyClose(t *testing.T) {
	trust.ClearProductCertCache()
	tests := test.TestCases()
	d, goodRoots, badRoots, kds := testclient.GetSevGuest(tests, &test.DeviceOptions{Now: time.Now()}, t)
	defer d.Close()
	type reportGetter func(sg.Device, [64]byte) (*pb.Attestation, error)
	reportGetters := []struct {
		name   string
		getter reportGetter
	}{
		{
			name:   "GetExtendedReport",
			getter: sg.GetExtendedReport,
		},
		{
			name: "GetReport",
			getter: func(d sg.Device, input [64]byte) (*pb.Attestation, error) {
				report, err := sg.GetReport(d, input)
				if err != nil {
					return nil, err
				}
				return &pb.Attestation{Report: report}, nil
			},
		},
	}
	// Trust the test device's root certs.
	options := &Options{TrustedRoots: goodRoots, Getter: kds}
	badOptions := &Options{TrustedRoots: badRoots, Getter: kds}
	for _, tc := range tests {
		if testclient.SkipUnmockableTestCase(&tc) {
			continue
		}
		for _, getReport := range reportGetters {
			ereport, err := getReport.getter(d, tc.Input)
			if !test.Match(err, tc.WantErr) {
				t.Fatalf("%s: %s(d, %v) = %v, %v. Want err: %v", tc.Name, getReport.name, tc.Input, ereport, err, tc.WantErr)
			}
			if tc.WantErr == "" {
				if err := SnpAttestation(ereport, options); err != nil {
					t.Errorf("SnpAttestation(%v) errored unexpectedly: %v", ereport, err)
				}
				wantBad := "error verifying VCEK certificate"
				if err := SnpAttestation(ereport, badOptions); !test.Match(err, wantBad) {
					t.Errorf("SnpAttestation(_) bad root test errored unexpectedly: %v, want %s", err, wantBad)
				}
			}
		}
	}
}

func TestRealAttestationVerification(t *testing.T) {
	trust.ClearProductCertCache()
	var nonce [64]byte
	copy(nonce[:], []byte{1, 2, 3, 4, 5})
	getter := &test.Getter{
		Responses: map[string][]byte{
			"https://kdsintf.amd.com/vcek/v1/Milan/cert_chain": testdata.MilanBytes,
			// Use the VCEK's hwID and known TCB values to specify the URL its VCEK cert would be fetched from.
			"https://kdsintf.amd.com/vcek/v1/Milan/3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d?blSPL=2&teeSPL=0&snpSPL=5&ucodeSPL=68": testdata.VcekBytes,
		},
	}
	if err := RawSnpReport(testdata.AttestationBytes, &Options{Getter: getter}); err != nil {
		t.Error(err)
	}
}
