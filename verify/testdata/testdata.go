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

// Package testdata provides embedded binaries of example ABI material.
package testdata

import _ "embed"

// These certificates are committed regardless of its expiration date since we adjust the
// CurrentTime to compare against so that the validity with respect to time is always true.

// VcekBytes is an example VCEK certificate as issued by the AMD KDS.
//
//go:embed vcek.testcer
var VcekBytes []byte

// MilanVcekBytes is the Milan product vcek cert_chain as issued by the AMD KDS.
//
// Deprecated: Use trust.AskArkMilanVcekBytes
//
//go:embed milan.testcer
var MilanVcekBytes []byte

// MilanVlekBytes is the Milan product vlek cert_chain as issued by the AMD KDS.
//
// Deprecated: Use trust.AskArkMilanVlekBytes
//
//go:embed milanvlek.testcer
var MilanVlekBytes []byte

// AttestationBytes is an example attestation report from a VM that was
// launched without an ID_BLOCK.
//
//go:embed attestation.bin
var AttestationBytes []byte
