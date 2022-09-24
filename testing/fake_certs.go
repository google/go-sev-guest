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

// Package testing defines fakes and mocks for the sev-guest device and AMD-SP.
package testing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"

	// Insecure randomness for faster testing.
	"math/rand"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/verify/kds"
	"github.com/pborman/uuid"
)

// KDS specification:
// https://www.amd.com/system/files/TechDocs/57230.pdf

const (
	arkExpirationYears  = 25
	askExpirationYears  = 25
	vcekExpirationYears = 7
	arkRsaBits          = 4096
	askRsaBits          = 4096
)

// AmdSigner encapsulates a key and certificate chain following the format of AMD-SP's VCEK for
// signing attestation reports.
type AmdSigner struct {
	Ark  *x509.Certificate
	Ask  *x509.Certificate
	Vcek *x509.Certificate
	Keys *AmdKeys
}

// AmdKeys encapsulates the key chain of ARK through ASK down to VCEK.
type AmdKeys struct {
	Ark  *rsa.PrivateKey
	Ask  *rsa.PrivateKey
	Vcek *ecdsa.PrivateKey
}

var insecureRandomness = rand.New(rand.NewSource(0xc0de))

// Sign takes a chunk of bytes, signs it with VcekPriv, and returns the R, S pair for the signature
// in little endian format.
func (s *AmdSigner) Sign(toSign []byte) (*big.Int, *big.Int, error) {
	h := crypto.SHA384.New()
	h.Write(toSign)
	R, S, err := ecdsa.Sign(insecureRandomness, s.Keys.Vcek, h.Sum(nil))
	if err != nil {
		return nil, nil, err
	}
	return R, S, nil
}

// CertOverride encapsulates certificate aspects that can be overridden when creating a certificate
// chain.
type CertOverride struct {
	// If 0, interpreted as Version, otherwise the ARK cert version number.
	Version            int
	SerialNumber       *big.Int
	Issuer             *pkix.Name
	Subject            *pkix.Name
	SignatureAlgorithm x509.SignatureAlgorithm
	PublicKeyAlgorithm x509.PublicKeyAlgorithm
	KeyUsage           x509.KeyUsage
	// If nil, interpreted as default, otherwise the CRLDistributionPoints for the cert.
	CRLDistributionPoints []string
	// If nil, interpreted as default list.
	Extensions []pkix.Extension
}

// AmdSignerBuilder represents toggleable configurations of the VCEK certificate chain.
type AmdSignerBuilder struct {
	// Keys contains the private keys that will get a certificate chain structure.
	Keys             *AmdKeys
	Product          string
	ArkCreationTime  time.Time
	AskCreationTime  time.Time
	VcekCreationTime time.Time
	ArkCustom        CertOverride
	AskCustom        CertOverride
	VcekCustom       CertOverride
	// Intermediate built certificates
	Ark  *x509.Certificate
	Ask  *x509.Certificate
	Vcek *x509.Certificate
}

func amdPkixName(commonName string, serialNumber string) pkix.Name {
	return pkix.Name{
		Organization:       []string{"Advanced Micro Devices"},
		Country:            []string{"US"},
		OrganizationalUnit: []string{"Engineering"},
		Locality:           []string{"Santa Clara"},
		Province:           []string{"CA"},
		SerialNumber:       serialNumber,
		CommonName:         commonName,
	}
}

func unsignedArkOrAsk(issuerRole, subjectRole, productName string, issuerSerialNumber string, creationTime time.Time, expirationYears int) *x509.Certificate {
	cert := &x509.Certificate{}
	cert.NotBefore = creationTime
	cert.NotAfter = creationTime.Add(time.Duration(365*24*expirationYears) * time.Hour)
	cert.SignatureAlgorithm = x509.SHA384WithRSAPSS
	cert.PublicKeyAlgorithm = x509.RSA
	cert.Version = 3
	cert.SerialNumber = big.NewInt(0xc0dec0de)
	cert.Issuer = amdPkixName(fmt.Sprintf("%s-%s", issuerRole, productName), issuerSerialNumber)
	cert.Subject = amdPkixName(fmt.Sprintf("%s-%s", subjectRole, productName), fmt.Sprintf("%x", cert.SerialNumber))
	cert.CRLDistributionPoints = []string{fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/%s/crl", productName)}
	cert.IsCA = true
	cert.BasicConstraintsValid = true
	return cert
}

func (o CertOverride) override(cert *x509.Certificate) *x509.Certificate {
	if o.SignatureAlgorithm != x509.UnknownSignatureAlgorithm {
		cert.SignatureAlgorithm = o.SignatureAlgorithm
	}
	if o.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		cert.PublicKeyAlgorithm = o.PublicKeyAlgorithm
	}
	if o.Version != 0 {
		cert.Version = o.Version
	}
	if o.Issuer != nil {
		cert.Issuer = *o.Issuer
	}
	if o.Subject != nil {
		cert.Subject = *o.Subject
	}
	if o.SerialNumber != nil {
		cert.SerialNumber = o.SerialNumber
		cert.Subject.SerialNumber = fmt.Sprintf("%x", o.SerialNumber)
	}
	if o.KeyUsage != x509.KeyUsage(0) {
		cert.KeyUsage = o.KeyUsage
	}
	if o.CRLDistributionPoints != nil {
		cert.CRLDistributionPoints = o.CRLDistributionPoints
	}
	if o.Extensions != nil {
		cert.ExtraExtensions = o.Extensions
	}
	return cert
}

// DefaultArk returns a new RSA key with the expected size for an ARK.
func DefaultArk() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(insecureRandomness, arkRsaBits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// DefaultAsk returns a new RSA key with the expected size for an ASK.
func DefaultAsk() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(insecureRandomness, askRsaBits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// DefaultVcek returns a new ECDSA key on the expected curve for a VCEK.
func DefaultVcek() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), insecureRandomness)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// DefaultAmdKeys returns a key set for ARK, ASK, and VCEK with the expected key type and size.
func DefaultAmdKeys() (*AmdKeys, error) {
	ark, err := DefaultArk()
	if err != nil {
		return nil, err
	}
	ask, err := DefaultAsk()
	if err != nil {
		return nil, err
	}
	vcek, err := DefaultVcek()
	if err != nil {
		return nil, err
	}
	return &AmdKeys{Ark: ark, Ask: ask, Vcek: vcek}, nil
}

func (b *AmdSignerBuilder) certifyArk() error {
	cert := unsignedArkOrAsk(
		"ARK", "ARK", b.Product, "0xc0dec0de", b.ArkCreationTime, arkExpirationYears)
	cert.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign

	b.ArkCustom.override(cert)

	caBytes, err := x509.CreateCertificate(insecureRandomness, cert, cert, b.Keys.Ark.Public(), b.Keys.Ark)
	if err != nil {
		return fmt.Errorf("could not create a certificate from %v: %v", cert, err)
	}
	signed, err := x509.ParseCertificate(caBytes)
	b.Ark = signed
	return err
}

func (b *AmdSignerBuilder) certifyAsk() error {
	cert := unsignedArkOrAsk("ARK", "SEV", b.Product, b.Ark.Subject.SerialNumber, b.AskCreationTime, askExpirationYears)
	cert.KeyUsage = x509.KeyUsageCertSign

	b.AskCustom.override(cert)

	caBytes, err := x509.CreateCertificate(insecureRandomness, cert, b.Ark, b.Keys.Ask.Public(), b.Keys.Ark)
	if err != nil {
		return fmt.Errorf("could not create a certificate from %v: %v", cert, err)
	}
	askcert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}
	b.Ask = askcert
	return err
}

func (b *AmdSignerBuilder) certifyVcek() error {
	cert := &x509.Certificate{}
	cert.SignatureAlgorithm = x509.SHA384WithRSAPSS
	cert.PublicKeyAlgorithm = x509.ECDSA
	cert.Version = 3
	cert.Issuer = amdPkixName(fmt.Sprintf("SEV-%s", b.Product), b.Ask.Subject.SerialNumber)
	cert.Subject = amdPkixName("SEV-VCEK", "0")
	cert.SerialNumber = big.NewInt(0)
	cert.Subject.SerialNumber = fmt.Sprintf("%x", cert.SerialNumber)
	cert.NotBefore = time.Time{}
	cert.NotAfter = b.VcekCreationTime.Add(vcekExpirationYears * 365 * 24 * time.Hour)
	asn1Zero, _ := asn1.Marshal(0)
	productName, _ := asn1.Marshal("Milan-B0")
	var hwid [64]byte
	asn1Hwid, _ := asn1.Marshal(hwid[:])
	cert.ExtraExtensions = []pkix.Extension{
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
	}

	b.VcekCustom.override(cert)

	caBytes, err := x509.CreateCertificate(insecureRandomness, cert, b.Ask, b.Keys.Vcek.Public(), b.Keys.Ask)
	if err != nil {
		return fmt.Errorf("could not create a certificate from %v: %v", cert, err)
	}
	signed, err := x509.ParseCertificate(caBytes)
	b.Vcek = signed
	return err
}

// CertChain creates a test-only certificate chain from the keys and configurables in b.
func (b *AmdSignerBuilder) CertChain() (*AmdSigner, error) {
	if b.Product == "" {
		b.Product = "Milan" // For terse tests.
	}
	if err := b.certifyArk(); err != nil {
		return nil, fmt.Errorf("ark creation error: %v", err)
	}
	if err := b.certifyAsk(); err != nil {
		return nil, fmt.Errorf("ask creation error: %v", err)
	}
	if err := b.certifyVcek(); err != nil {
		return nil, fmt.Errorf("vcek creation error: %v", err)
	}
	return &AmdSigner{
		Ark:  b.Ark,
		Ask:  b.Ask,
		Vcek: b.Vcek,
		Keys: b.Keys,
	}, nil
}

// DefaultCertChain creates a test-only certificate chain for a fake attestation signer.
func DefaultCertChain(productName string, creationTime time.Time) (*AmdSigner, error) {
	keys, err := DefaultAmdKeys()
	if err != nil {
		return nil, fmt.Errorf("error generating fake keys: %v", err)
	}
	b := &AmdSignerBuilder{
		Keys:             keys,
		Product:          productName,
		ArkCreationTime:  creationTime,
		AskCreationTime:  creationTime,
		VcekCreationTime: creationTime,
	}
	return b.CertChain()
}

// CertTableBytes outputs the certificates in AMD's ABI format.
func (s *AmdSigner) CertTableBytes() ([]byte, error) {
	// Calculate the output size and the offset at which to copy each certificate.
	headers := make([]abi.CertTableHeaderEntry, 4) // ARK, ASK, VCEK, NULL
	headers[0].GUID = uuid.Parse(abi.ArkGUID)
	headers[0].Offset = uint32(len(headers) * abi.CertTableEntrySize)
	headers[0].Length = uint32(len(s.Ark.Raw))

	headers[1].GUID = uuid.Parse(abi.AskGUID)
	headers[1].Offset = headers[0].Offset + headers[0].Length
	headers[1].Length = uint32(len(s.Ask.Raw))

	headers[2].GUID = uuid.Parse(abi.VcekGUID)
	headers[2].Offset = headers[1].Offset + headers[1].Length
	headers[2].Length = uint32(len(s.Vcek.Raw))

	// Write out the headers and the certificates at the appropriate offsets.
	result := make([]byte, headers[2].Offset+headers[2].Length)
	for i, cert := range [][]byte{s.Ark.Raw, s.Ask.Raw, s.Vcek.Raw} {
		if err := (&headers[i]).Write(result[i*abi.CertTableEntrySize:]); err != nil {
			return nil, err
		}
		copy(result[headers[i].Offset:], cert)
	}
	return result, nil
}
