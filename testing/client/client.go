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
	"testing"

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
						Ask: sevTestDevice.Signer.Ask,
						Ark: sevTestDevice.Signer.Ark,
					},
				},
			},
		}
		badSnpRoot := map[string][]*trust.AMDRootCerts{
			"Milan": {
				{
					Product: "Milan",
					ProductCerts: &trust.ProductCerts{
						// Backwards, oops
						Ask: sevTestDevice.Signer.Ark,
						Ark: sevTestDevice.Signer.Ask,
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
	badSnpRoot := make(map[string][]*trust.AMDRootCerts)
	for product, rootCerts := range trust.DefaultRootCerts {
		// By flipping the ASK and ARK, we ensure that the attestation will never verify.
		badSnpRoot[product] = []*trust.AMDRootCerts{{
			Product: product,
			ProductCerts: &trust.ProductCerts{
				Ark: rootCerts.ProductCerts.Ask,
				Ask: rootCerts.ProductCerts.Ark,
			},
			AskSev: rootCerts.ArkSev,
			ArkSev: rootCerts.AskSev,
		}}
	}
	return client, nil, badSnpRoot, test.GetKDS(tb)
}
