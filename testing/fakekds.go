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
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-sev-guest/kds"
	kpb "github.com/google/go-sev-guest/proto/fakekds"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/proto"
)

var testUseKDS = flag.Bool("test_use_kds", false, "Deprecated: If true, tests will attempt to retrieve certificates from AMD KDS")

type testKdsType struct {
	value string
}

func (t *testKdsType) String() string { return t.value }
func (t *testKdsType) Set(value string) error {
	if value != "amd" && value != "cache" && value != "none" {
		return fmt.Errorf("--test_kds must be one of amd, cache, or none. Got %q", value)
	}
	t.value = value
	return nil
}

var testKds = testKdsType{value: "cache"}

func init() {
	flag.Var(&testKds, "test_kds", "One of amd, cache, none. If amd, tests will "+
		"attempt to retrieve certificates from AMD KDS. If cache, only piper-submitted certificates "+
		"will be available given a hostname and TCB version. If none, then no VCEK certificates will "+
		"be retrieved.")
}

// TestUseKDS returns whether tests should use the network to connect the live AMD Key Distribution
// service.
func TestUseKDS() bool {
	return *testUseKDS || testKds.value == "amd"
}

// Insert your own KDS cache here with go:embed.
var internalKDSCache []byte

// RootBundle represents the two different CA bundles that the KDS can
// return.
type RootBundle struct {
	VcekBundle string
	VlekBundle string
}

// FakeKDS implements the verify.HTTPSGetter interface to provide certificates like AMD KDS, but
// with certificates cached in a protobuf.
type FakeKDS struct {
	Certs *kpb.Certificates
	// Two CERTIFICATE PEMs for ASK, then ARK or ASVK then ARK, per product
	RootBundles map[string]RootBundle
}

// FakeKDSFromFile returns a FakeKDS from a path to a serialized fakekds.Certificates message.
func FakeKDSFromFile(path string) (*FakeKDS, error) {
	result := &FakeKDS{
		Certs: &kpb.Certificates{},
		RootBundles: map[string]RootBundle{"Milan": {
			VcekBundle: string(testdata.MilanVcekBytes),
			VlekBundle: string(testdata.MilanVlekBytes),
		}},
	}

	contents, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return result, err
	}
	if err != nil {
		return nil, fmt.Errorf("could not load FakeKDS file %q: %v", path, err)
	}
	if err := proto.Unmarshal(contents, result.Certs); err != nil {
		return nil, fmt.Errorf("could not unmarshal FakeKDS file %q: %v", path, err)
	}
	return result, nil
}

// FakeKDSFromSigner returns a FakeKDS that produces the fake signer's certificates following the
// AMD KDS REST API expectations.
func FakeKDSFromSigner(signer *AmdSigner) (*FakeKDS, error) {
	certs := &kpb.Certificates{}
	certs.ChipCerts = []*kpb.Certificates_ChipTCBCerts{
		{
			ChipId: signer.HWID[:],
			TcbCerts: map[uint64][]byte{
				uint64(signer.TCB): signer.Vcek.Raw,
			},
		},
	}

	b := &strings.Builder{}
	if err := multierr.Combine(
		pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ask.Raw}),
		pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ark.Raw}),
	); err != nil {
		return nil, fmt.Errorf("could not encode VCEK root certificates: %v", err)
	}
	vcekBundle := b.String()
	var vlekBundle string
	if signer.Asvk != nil {
		b := &strings.Builder{}
		if err := multierr.Combine(
			pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Asvk.Raw}),
			pem.Encode(b, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ark.Raw}),
		); err != nil {
			return nil, fmt.Errorf("could not encode VLEK root certificates: %v", err)
		}
		vlekBundle = b.String()
	}
	return &FakeKDS{
		Certs: certs,
		RootBundles: map[string]RootBundle{"Milan": {
			VcekBundle: vcekBundle,
			VlekBundle: vlekBundle,
		}},
	}, nil
}

// FindChipTcbCerts returns the TcbCerts associated with the given chipID in the database if they
// exist. If not, returns nil.
func FindChipTcbCerts(database *kpb.Certificates, chipID []byte) map[uint64][]byte {
	for _, cert := range database.ChipCerts {
		if bytes.Equal(cert.ChipId, chipID) {
			return cert.TcbCerts
		}
	}
	return nil
}

// Get translates a KDS url into the expected certificate as represented in the fake's certificate
// database.
func (f *FakeKDS) Get(url string) ([]byte, error) {
	// If a root cert request, return the embedded default root certs.
	product, key, err := kds.ParseProductCertChainURL(url)
	if err == nil {
		bundles, ok := f.RootBundles[product]
		if !ok {
			return nil, fmt.Errorf("no embedded CA bundle for product %q", product)
		}
		switch key {
		case kds.VcekCertFunction:
			return []byte(bundles.VcekBundle), nil
		case kds.VlekCertFunction:
			return []byte(bundles.VlekBundle), nil
		default:
			return nil, fmt.Errorf("internal: unsupperted key type for fake bundles: %q", key)
		}
	}
	vcek, err := kds.ParseVCEKCertURL(url)
	if err != nil {
		return nil, err
	}
	certs := FindChipTcbCerts(f.Certs, vcek.HWID)
	if certs == nil {
		return nil, fmt.Errorf("no certificate found at %q (unknown HWID %v)", url, vcek.HWID)
	}
	certbytes, ok := certs[vcek.TCB]
	if !ok {
		return nil, fmt.Errorf("no certificate found at %q (host present, bad TCB %v)", url, vcek.TCB)
	}
	return certbytes, nil
}

// GetKDS returns an HTTPSGetter that can produce the expected certificates for a given URL in the
// test environment.
func GetKDS(t testing.TB) trust.HTTPSGetter {
	if TestUseKDS() {
		return trust.DefaultHTTPSGetter()
	}
	fakeKds := &FakeKDS{
		Certs: &kpb.Certificates{},
		RootBundles: map[string]RootBundle{"Milan": {
			VcekBundle: string(testdata.MilanVcekBytes),
			VlekBundle: string(testdata.MilanVlekBytes),
		}},
	}
	// Provide nothing if --test_kds=none.
	if testKds.value == "none" {
		return fakeKds
	}
	if err := proto.Unmarshal(internalKDSCache, fakeKds.Certs); err != nil {
		t.Fatalf("could not unmarshal embedded FakeKDS file: %v", err)
	}
	return fakeKds
}
