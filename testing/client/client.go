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

// Package client (in testing) allows tests to get a fake or real sev-guest device.
package client

import (
	"fmt"
	"testing"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
)

// SkipUnmockableTestCase returns whether we have to skip a mocked failure test case on real hardware.
func SkipUnmockableTestCase(tc *test.TestCase) bool {
	return !client.UseDefaultSevGuest() && tc.FwErr != 0
}

// GetSevGuest is a cross-platform testing helper function that retrives the
// appropriate SEV-guest device from the flags passed into "go test".
//
// If using a test guest device, this will also produce a fake AMD-SP that produces the signed
// versions of given attestation reports based on different nonce input. Its returned roots of trust
// are based on the fake's signing credentials.
func GetSevGuest(tcs []test.TestCase, opts *test.DeviceOptions, tb testing.TB) (client.Device, map[string][]*trust.AMDRootCerts, map[string][]*trust.AMDRootCerts, trust.HTTPSGetter) {
	tb.Helper()
	if client.UseDefaultSevGuest() {
		sevTestDevice, err := test.TcDevice(tcs, opts)
		if err != nil {
			tb.Fatalf("failed to create test device: %v", err)
		}
		goodSnpRoot := map[string][]*trust.AMDRootCerts{
			"Milan": {
				{
					Product: "Milan",
					ProductCerts: &trust.ProductCerts{
						Ask:  sevTestDevice.Signer.Ask,
						Ark:  sevTestDevice.Signer.Ark,
						Asvk: sevTestDevice.Signer.Asvk,
					},
				},
			},
		}
		badSnpRoot := map[string][]*trust.AMDRootCerts{
			"Milan": {
				{
					Product: "Milan",
					ProductCerts: &trust.ProductCerts{
						// No ASK, oops.
						Ask:  sevTestDevice.Signer.Ark,
						Ark:  sevTestDevice.Signer.Ark,
						Asvk: sevTestDevice.Signer.Ark,
					},
				},
			},
		}
		fakekds, err := test.FakeKDSFromSigner(sevTestDevice.Signer)
		if err != nil {
			tb.Fatalf("failed to create fake KDS from signer: %v", err)
		}
		return sevTestDevice, goodSnpRoot, badSnpRoot, fakekds
	}

	client, err := client.OpenDevice()
	if err != nil {
		tb.Fatalf("Failed to open SEV guest device: %v", err)
	}
	kdsImpl := test.GetKDS(tb)

	badSnpRoot := make(map[string][]*trust.AMDRootCerts)
	for product, rootCerts := range trust.DefaultRootCerts {
		// Supplement the defaults with the missing x509 certificates.
		pc, err := trust.GetProductChain(product, abi.VcekReportSigner, kdsImpl)
		if err != nil {
			tb.Fatalf("failed to get product chain for %q: %v", product, err)
		}
		fmt.Printf("Making bad root %s %v", product, rootCerts)
		// By removing the ASK intermediate, we ensure that the attestation will never verify.
		badSnpRoot[product] = []*trust.AMDRootCerts{{
			Product: product,
			ProductCerts: &trust.ProductCerts{
				Ark:  pc.Ark,
				Ask:  pc.Ark,
				Asvk: pc.Ark,
			},
			AskSev: rootCerts.ArkSev,
			ArkSev: rootCerts.AskSev,
		}}
	}
	return client, nil, badSnpRoot, kdsImpl
}
