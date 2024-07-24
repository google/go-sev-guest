// Copyright 2024 Google LLC
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

// Package data (in testing) allows tests to access data for testing purpose.
package data

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"log"
)

//go:embed keys/vcek_private_key.pem
var vcekPrivateKeyPEM []byte

//go:embed keys/vlek_private_key.pem
var vlekPrivateKeyPEM []byte

//go:embed keys/ark_private_key.pem
var arkPrivateKeyPEM []byte

//go:embed keys/ask_private_key.pem
var askPrivateKeyPEM []byte

//go:embed keys/asvk_private_key.pem
var asvkPrivateKeyPEM []byte

// VCEKPrivateKey is the ECDSA private key using P-384 curve with a SHA384 digest for VCEK
// Generated using:
//
//	openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt
var VCEKPrivateKey = mustParseECDSAPrivateKey(vcekPrivateKeyPEM)

// VLEKPrivateKey is the ECDSA private key using P-384 curve with a SHA384 digest for VLEK
// Generated using:
//
//	openssl ecparam -genkey -name secp384r1 | openssl pkcs8 -topk8 -nocrypt
var VLEKPrivateKey = mustParseECDSAPrivateKey(vlekPrivateKeyPEM)

// ARKPrivateKey is the RSA private key using 4096-bit length with a SHA256 digest for ARK
// Generated using:
//
//	openssl genrsa 4096 | openssl pkcs8 -topk8 -nocrypt
var ARKPrivateKey = mustParseRSAPrivateKey(arkPrivateKeyPEM)

// ASKPrivateKey is the ECDSA private key using 4096-bit length with a SHA256 digest for ASK
// Generated using:
//
//	openssl genrsa 4096 | openssl pkcs8 -topk8 -nocrypt
var ASKPrivateKey = mustParseRSAPrivateKey(askPrivateKeyPEM)

// ASVKPrivateKey is the ECDSA private key using 4096-bit length with a SHA256 digest for ASVK
// Generated using:
//
//	openssl genrsa 4096 | openssl pkcs8 -topk8 -nocrypt
var ASVKPrivateKey = mustParseRSAPrivateKey(asvkPrivateKeyPEM)

func mustParseECDSAPrivateKey(pemBytes []byte) *ecdsa.PrivateKey {
	privateKey := mustParsePKCS8PrivateKey(pemBytes)
	ecPrivateKey, ok := privateKey.(*ecdsa.PrivateKey)
	if !ok {
		log.Fatalf("Unexpected private key type, want ECDSA private key")
	}
	return ecPrivateKey
}

func mustParseRSAPrivateKey(pemBytes []byte) *rsa.PrivateKey {
	privateKey := mustParsePKCS8PrivateKey(pemBytes)
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		log.Fatalf("Unexpected private key type, want RSA private key")
	}
	return rsaPrivateKey
}

func mustParsePKCS8PrivateKey(pemBytes []byte) any {
	block, rest := pem.Decode(pemBytes)
	if block == nil {
		log.Fatal("Unable to decode key as PEM")
	}
	if len(rest) > 0 {
		log.Fatal("Unexpected trailing data in key file")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Unable to parse PKCS8 private key: %v", err)
	}
	return privateKey
}
