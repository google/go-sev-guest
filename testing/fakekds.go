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
	_ "embed"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-sev-guest/kds"
	kpb "github.com/google/go-sev-guest/proto/fakekds"
	"github.com/google/go-sev-guest/verify/trust"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/proto"
)

// The Milan product certificate bundle is only embedded for tests rather than in the main library
// since it's generally bad practice to embed certificates that can expire directly into a software
// project. Production uses should be providing their own certificates.
//
//go:embed "milan.pem"
var milanCerts []byte

// FakeKDS implements the verify.HTTPSGetter interface to provide certificates like AMD KDS, but
// with certificates cached in a protobuf.
type FakeKDS struct {
	Certs *kpb.Certificates
	// Two CERTIFICATE PEMs for ASK, then ARK.
	RootBundle string
}

// FakeKDSFromFile returns a FakeKDS from a path to a serialized fakekds.Certificates message.
func FakeKDSFromFile(path string) (*FakeKDS, error) {
	result := &FakeKDS{Certs: &kpb.Certificates{}}

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
		return nil, fmt.Errorf("could not encode root certificates: %v", err)
	}
	return &FakeKDS{
		Certs:      certs,
		RootBundle: b.String(),
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
	product, err := kds.ParseProductCertChainURL(url)
	if err == nil {
		if product == "Milan" {
			return milanCerts, nil
		}
		return nil, fmt.Errorf("no embedded CA bundle for product %q", product)
	}
	vcek, err := kds.ParseVCEKCertURL(url)
	if err != nil {
		return nil, err
	}
	certs := FindChipTcbCerts(f.Certs, vcek.HWID)
	if certs == nil {
		return nil, fmt.Errorf("no certificate found at %q", url)
	}
	certbytes, ok := certs[vcek.TCB]
	if !ok {
		return nil, fmt.Errorf("no certificate found at %q", url)
	}
	return certbytes, nil
}

// GetKDS returns an HTTPSGetter that can produce the expected certificates for a given URL in the
// test environment.
func GetKDS(t testing.TB) trust.HTTPSGetter {
	// Insert your own KDS cache here.
	/*
	   fakeKds := &FakeKDS{Certs: &kpb.Certificates{}}
	   if err := proto.Unmarshal(internalKdsCache, fakeKds.Certs); err != nil {
	   	t.Fatalf("could not unmarshal embedded FakeKDS file: %v", err)
	   }
	   return fakeKds
	*/
	return nil
}
