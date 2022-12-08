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

	"flag"

	"github.com/google/go-sev-guest/client"
	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
)

var sevGuestPath = flag.String("sev_guest_device_path", "", "Path to Linux SEV guest device (i.e., /dev/sev-guest). Empty value (default) will run tests against a fake.")

func useRealSevGuest() bool {
	return *sevGuestPath != ""
}

func getRealSevGuest() (client.Device, error) {
	result := &client.LinuxDevice{}
	return result, result.Open(*sevGuestPath)
}

// GetSevGuest is a cross-platform testing helper function that retrives the
// appropriate SEV-guest device from the flags passed into "go test".
//
// If using a test guest device, this will also produce a fake AMD-SP that produces the signed
// versions of given attestation reports based on different nonce input. Its returned roots of trust
// are based on the fake's signing credentials.
func GetSevGuest(tcs []test.TestCase, opts *test.DeviceOptions, tb testing.TB) (client.Device, map[string][]*trust.AMDRootCerts, map[string][]*trust.AMDRootCerts) {
	tb.Helper()
	if !useRealSevGuest() {
		sevTestDevice, err := test.TcDevice(tcs, opts)
		if err != nil {
			tb.Fatalf("failed to create test device: %v", err)
		}
		goodSnpRoot := map[string][]*trust.AMDRootCerts{
			"Milan": {
				{
					Product: "Milan",
					AskX509: sevTestDevice.Signer.Ask,
					ArkX509: sevTestDevice.Signer.Ark,
				},
			},
		}
		badSnpRoot := map[string][]*trust.AMDRootCerts{
			"Milan": {
				{
					Product: "Milan",
					// Backwards, oops
					AskX509: sevTestDevice.Signer.Ark,
					ArkX509: sevTestDevice.Signer.Ask,
				},
			},
		}
		return sevTestDevice, goodSnpRoot, badSnpRoot
	}

	client, err := getRealSevGuest()
	if err != nil {
		tb.Fatalf("Failed to open SEV guest device: %v", err)
	}
	badSnpRoot := make(map[string][]*trust.AMDRootCerts)
	for product, rootCerts := range trust.DefaultRootCerts {
		// By flipping the ASK and ARK, we ensure that the attestation will never verify.
		badSnpRoot[product] = []*trust.AMDRootCerts{&trust.AMDRootCerts{
			Product: product,
			ArkX509: rootCerts.AskX509,
			AskX509: rootCerts.ArkX509,
			AskSev:  rootCerts.ArkSev,
			ArkSev:  rootCerts.AskSev,
		}}
	}
	return client, nil, badSnpRoot
}
