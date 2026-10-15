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

// The seeds use the AMD certificate chains in package trust. Package trust imports kds, so this
// file must be in package kds_test.
package kds_test

import (
	"encoding/pem"
	"testing"

	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/go-sev-guest/verify/trust"
)

// FuzzParseProductCertChain mutates the body of a KDS cert_chain response: an ASK and an ARK
// certificate in PEM form.
func FuzzParseProductCertChain(f *testing.F) {
	vcekPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testdata.VcekBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: testdata.VcekBytes})
	headerPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"X": "y"}, Bytes: testdata.VcekBytes})
	f.Add([]byte{})
	f.Add(trust.AskArkMilanVcekBytes)
	f.Add(trust.AskArkMilanVlekBytes)
	// Chain with an invalid PEM block type. The fuzzer rarely edits matching BEGIN and END lines
	// together.
	f.Add(append(append([]byte{}, keyPEM...), vcekPEM...))
	// Chain with PEM headers.
	f.Add(append(append([]byte{}, headerPEM...), vcekPEM...))
	// Valid certificate chain with extra trailing bytes.
	f.Add(append(append([]byte{}, trust.AskArkMilanVcekBytes...), 'x'))

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = kds.ParseProductCertChain(data)
	})
}
