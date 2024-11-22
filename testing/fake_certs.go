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
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"flag"
	"fmt"
	"math/big"
	"strings"
	"testing"

	// Insecure randomness for faster testing.
	"math/rand"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/testing/data"
	"github.com/google/uuid"
)

// KDS specification:
// https://www.amd.com/system/files/TechDocs/57230.pdf

const (
	arkExpirationYears  = 25
	askExpirationYears  = 25
	asvkExpirationYears = 25
	vcekExpirationYears = 7
)

var (
	// Product decides the expected product for attestation report validation. If empty, inferred
	// to be the ProductLine of --product_name.
	Product = flag.String("product", "",
		"The product string for the SEV-SNP machine tested on. The stepping version is ignored.")

	// ProductName decides the fake certificates' product name. It must be parsable by
	// kds.ParseProductName. The flag may also be used to direct the hardware verification options.
	// If empty, defined to be kds.ProductName(abi.DefaultSevProduct()).
	ProductName = flag.String("product_name", "",
		"The product name for the SEV-SNP machine tested on. Overrides --product.")
)

// GetProductName returns the --product_name flag value or a valid Default.
func GetProductName() string {
	if *ProductName == "" {
		return kds.ProductName(abi.DefaultSevProduct())
	}
	return *ProductName
}

// GetProductLine returns the actual or inferred value of --product.
func GetProductLine() string {
	if *Product == "" {
		return kds.ProductLineOfProductName(GetProductName())
	}
	return *Product
}

// GetProduct returns the expected product for validation.
func GetProduct(t testing.TB) *spb.SevProduct {
	if *Product == "ignore" {
		return nil
	}
	// If a specific product name is not given, then use the product line.
	if *ProductName == "" {
		product, err := kds.ParseProductLine(GetProductLine())
		if err != nil {
			t.Fatalf("ParseProductLine(%s) = _, %v errored unexpectedly", GetProductLine(), err)
		}
		return product
	}
	product, err := kds.ParseProductName(*ProductName, abi.VcekReportSigner)
	if err != nil {
		t.Fatalf("ParseProductName(%s) = _, %v errored unexpectedly", *ProductName, err)
	}
	return product
}

// AmdSigner encapsulates a key and certificate chain following the format of AMD-SP's VCEK for
// signing attestation reports.
type AmdSigner struct {
	Ark    *x509.Certificate
	Ask    *x509.Certificate
	Asvk   *x509.Certificate
	Vcek   *x509.Certificate
	Vlek   *x509.Certificate
	Extras map[string][]byte
	Keys   *AmdKeys
	// This identity does not match AMD's notion of an HWID. It is purely to combine expectations of
	// report data -> KDS URL construction for the fake KDS implementation.
	HWID    [abi.ChipIDSize]byte
	TCB     kds.TCBVersion
	Product *spb.SevProduct
}

// AmdKeys encapsulates the key chain of ARK through ASK down to VCEK.
type AmdKeys struct {
	Ark  *rsa.PrivateKey
	Ask  *rsa.PrivateKey
	Asvk *rsa.PrivateKey
	Vcek *ecdsa.PrivateKey
	Vlek *ecdsa.PrivateKey
}

var insecureRandomness = rand.New(rand.NewSource(0xc0de))

// Sign takes a chunk of bytes, signs it with VcekPriv, and returns the R, S pair for the signature
// in little endian format.
func (s *AmdSigner) Sign(toSign []byte) (*big.Int, *big.Int, error) {
	info, err := abi.ReportSignerInfo(toSign)
	if err != nil {
		return nil, nil, err
	}
	si, err := abi.ParseSignerInfo(info)
	if err != nil {
		return nil, nil, err
	}
	var key *ecdsa.PrivateKey
	switch si.SigningKey {
	case abi.VcekReportSigner:
		key = s.Keys.Vcek
	case abi.VlekReportSigner:
		key = s.Keys.Vlek
	}
	h := crypto.SHA384.New()
	h.Write(toSign)
	R, S, err := ecdsa.Sign(insecureRandomness, key, h.Sum(nil))
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
	ProductName      string
	ArkCreationTime  time.Time
	AskCreationTime  time.Time
	AsvkCreationTime time.Time
	VcekCreationTime time.Time
	VlekCreationTime time.Time
	ArkCustom        CertOverride
	AskCustom        CertOverride
	AsvkCustom       CertOverride
	VcekCustom       CertOverride
	VlekCustom       CertOverride
	CSPID            string
	HWID             [abi.ChipIDSize]byte
	TCB              kds.TCBVersion
	// Intermediate built certificates
	Ark    *x509.Certificate
	Ask    *x509.Certificate
	Asvk   *x509.Certificate
	Vcek   *x509.Certificate
	Vlek   *x509.Certificate
	Extras map[string][]byte
}

func (b *AmdSignerBuilder) productName() string {
	if b.ProductName == "" {
		return GetProductName()
	}
	return b.ProductName
}

func (b *AmdSignerBuilder) productLine() string {
	return kds.ProductLineOfProductName(b.productName())
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

func arkName(productLine, serialNumber string) pkix.Name {
	return amdPkixName(fmt.Sprintf("ARK-%s", productLine), serialNumber)
}

func askName(productLine, serialNumber string) pkix.Name {
	return amdPkixName(fmt.Sprintf("SEV-%s", productLine), serialNumber)
}

func asvkName(productLine, serialNumber string) pkix.Name {
	return amdPkixName(fmt.Sprintf("SEV-VLEK-%s", productLine), serialNumber)
}

func (b *AmdSignerBuilder) unsignedRoot(arkName pkix.Name, key abi.ReportSigner, subjectSerial *big.Int, creationTime time.Time, expirationYears int) *x509.Certificate {
	var subject pkix.Name
	issuer := arkName
	cert := &x509.Certificate{}
	crl := kds.CrlLinkByKey(b.productLine(), key)
	sn := fmt.Sprintf("%x", subjectSerial)
	switch key {
	case abi.VcekReportSigner:
		subject = askName(b.productLine(), sn)
	case abi.VlekReportSigner:
		subject = asvkName(b.productLine(), sn)
	case abi.NoneReportSigner:
		crl = kds.CrlLinkByKey(b.productLine(), abi.VcekReportSigner)
		subject = arkName
	}
	cert.NotBefore = creationTime
	cert.NotAfter = creationTime.Add(time.Duration(365*24*expirationYears) * time.Hour)
	cert.SignatureAlgorithm = x509.SHA384WithRSAPSS
	cert.PublicKeyAlgorithm = x509.RSA
	cert.Version = 3
	cert.SerialNumber = subjectSerial
	cert.Issuer = issuer
	cert.Subject = subject
	cert.CRLDistributionPoints = []string{crl}
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
func DefaultArk() *rsa.PrivateKey {
	return data.ARKPrivateKey
}

// DefaultAsk returns a new RSA key with the expected size for an ASK.
func DefaultAsk() *rsa.PrivateKey {
	return data.ASKPrivateKey
}

// DefaultAsvk returns a new RSA key with the expected size for an ASVK.
func DefaultAsvk() *rsa.PrivateKey {
	return data.ASVKPrivateKey
}

// DefaultVcek returns a new ECDSA key on the expected curve for a VCEK.
func DefaultVcek() *ecdsa.PrivateKey {
	return data.VCEKPrivateKey
}

// DefaultVlek returns a new ECDSA key on the expected curve for a VLEK.
func DefaultVlek() *ecdsa.PrivateKey {
	return data.VLEKPrivateKey
}

// DefaultAmdKeys returns a key set for ARK, ASK, and VCEK with the expected key type and size.
func DefaultAmdKeys() *AmdKeys {
	return &AmdKeys{
		Ark:  DefaultArk(),
		Ask:  DefaultAsk(),
		Vcek: DefaultVcek(),
		Vlek: DefaultVlek(),
		Asvk: DefaultAsvk(),
	}
}

func (b *AmdSignerBuilder) certifyArk() error {
	sn := big.NewInt(0xc0dec0de)
	name := arkName(b.productLine(), fmt.Sprintf("%x", sn))
	cert := b.unsignedRoot(name, abi.NoneReportSigner, sn, b.ArkCreationTime, arkExpirationYears)
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

// must be called after certifyArk
func (b *AmdSignerBuilder) certifyAsk() error {
	sn := big.NewInt(0xc0dec0de)
	cert := b.unsignedRoot(b.Ark.Subject, abi.VcekReportSigner, sn, b.AskCreationTime, askExpirationYears)
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

// must be called after certifyArk
func (b *AmdSignerBuilder) certifyAsvk() error {
	sn := big.NewInt(0xc0dec0de)
	cert := b.unsignedRoot(b.Ark.Subject, abi.VlekReportSigner, sn, b.AsvkCreationTime, asvkExpirationYears)
	cert.KeyUsage = x509.KeyUsageCertSign

	b.AsvkCustom.override(cert)

	caBytes, err := x509.CreateCertificate(insecureRandomness, cert, b.Ark, b.Keys.Asvk.Public(), b.Keys.Ark)
	if err != nil {
		return fmt.Errorf("could not create a certificate from %v: %v", cert, err)
	}
	asvkcert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		return err
	}
	b.Asvk = asvkcert
	return err
}

// CustomExtensions returns an array of extensions following the KDS specification
// for the given values.
func CustomExtensions(tcb kds.TCBParts, hwid []byte, cspid, productName string) []pkix.Extension {
	var productNameAsn1 []byte
	asn1Zero, _ := asn1.Marshal(0)
	if hwid != nil {
		productNameAsn1, _ = asn1.MarshalWithParams(productName, "ia5")
	} else {
		parts := strings.SplitN(productName, "-", 2)
		// VLEK doesn't have a -stepping component to its productName.
		productNameAsn1, _ = asn1.MarshalWithParams(parts[0], "ia5")
	}
	blSpl, _ := asn1.Marshal(int(tcb.BlSpl))
	teeSpl, _ := asn1.Marshal(int(tcb.TeeSpl))
	snpSpl, _ := asn1.Marshal(int(tcb.SnpSpl))
	spl4, _ := asn1.Marshal(int(tcb.Spl4))
	spl5, _ := asn1.Marshal(int(tcb.Spl5))
	spl6, _ := asn1.Marshal(int(tcb.Spl6))
	spl7, _ := asn1.Marshal(int(tcb.Spl7))
	ucodeSpl, _ := asn1.Marshal(int(tcb.UcodeSpl))
	exts := []pkix.Extension{
		{Id: kds.OidStructVersion, Value: asn1Zero},
		{Id: kds.OidProductName1, Value: productNameAsn1},
		{Id: kds.OidBlSpl, Value: blSpl},
		{Id: kds.OidTeeSpl, Value: teeSpl},
		{Id: kds.OidSnpSpl, Value: snpSpl},
		{Id: kds.OidSpl4, Value: spl4},
		{Id: kds.OidSpl5, Value: spl5},
		{Id: kds.OidSpl6, Value: spl6},
		{Id: kds.OidSpl7, Value: spl7},
		{Id: kds.OidUcodeSpl, Value: ucodeSpl},
	}
	if hwid != nil {
		asn1Hwid, _ := asn1.Marshal(hwid[:])
		exts = append(exts, pkix.Extension{Id: kds.OidHwid, Value: asn1Hwid})
	} else {
		if cspid == "" {
			cspid = "placeholder"
		}
		asn1cspid, _ := asn1.MarshalWithParams(cspid, "ia5")
		exts = append(exts, pkix.Extension{Id: kds.OidCspID, Value: asn1cspid})
	}
	return exts
}

func (b *AmdSignerBuilder) endorsementKeyPrecert(creationTime time.Time, hwid []byte, serialNumber *big.Int, key abi.ReportSigner) *x509.Certificate {
	subject := amdPkixName(fmt.Sprintf("SEV-%s", key.String()), "0")
	subject.SerialNumber = fmt.Sprintf("%x", serialNumber)
	ica := b.Ask
	if key == abi.VlekReportSigner {
		ica = b.Asvk
	}
	return &x509.Certificate{
		Version:            3,
		SignatureAlgorithm: x509.SHA384WithRSAPSS,
		PublicKeyAlgorithm: x509.ECDSA,
		Issuer:             amdPkixName(fmt.Sprintf("SEV-%s", b.productLine()), ica.Subject.SerialNumber),
		Subject:            subject,
		SerialNumber:       serialNumber,
		NotBefore:          time.Time{},
		NotAfter:           creationTime.Add(vcekExpirationYears * 365 * 24 * time.Hour),
		ExtraExtensions:    CustomExtensions(kds.TCBParts{}, hwid, b.CSPID, b.productName()),
	}
}

func (b *AmdSignerBuilder) certifyVcek() error {
	cert := b.endorsementKeyPrecert(b.VcekCreationTime, make([]byte, abi.ChipIDSize), big.NewInt(0), abi.VcekReportSigner)
	b.VcekCustom.override(cert)

	caBytes, err := x509.CreateCertificate(insecureRandomness, cert, b.Ask, b.Keys.Vcek.Public(), b.Keys.Ask)
	if err != nil {
		return fmt.Errorf("could not create a certificate from %v: %v", cert, err)
	}
	signed, err := x509.ParseCertificate(caBytes)
	b.Vcek = signed
	return err
}

func (b *AmdSignerBuilder) certifyVlek() error {
	cert := b.endorsementKeyPrecert(b.VlekCreationTime, nil, big.NewInt(0), abi.VlekReportSigner)
	b.VlekCustom.override(cert)

	caBytes, err := x509.CreateCertificate(insecureRandomness, cert, b.Asvk, b.Keys.Vlek.Public(), b.Keys.Asvk)
	if err != nil {
		return fmt.Errorf("could not create a certificate from %v: %v", cert, err)
	}
	signed, err := x509.ParseCertificate(caBytes)
	b.Vlek = signed
	return err
}

// TestOnlyCertChain creates a test-only certificate chain from the keys and configurables in b.
func (b *AmdSignerBuilder) TestOnlyCertChain() (*AmdSigner, error) {
	if b.Keys == nil {
		b.Keys = DefaultAmdKeys()
	}
	if err := b.certifyArk(); err != nil {
		return nil, fmt.Errorf("ark creation error: %v", err)
	}
	if err := b.certifyAsk(); err != nil {
		return nil, fmt.Errorf("ask creation error: %v", err)
	}
	if err := b.certifyAsvk(); err != nil {
		return nil, fmt.Errorf("asvk creation error: %v", err)
	}
	if err := b.certifyVcek(); err != nil {
		return nil, fmt.Errorf("vcek creation error: %v", err)
	}
	if b.Keys.Vlek != nil {
		if err := b.certifyVlek(); err != nil {
			return nil, fmt.Errorf("vlek creation error: %v", err)
		}
	}
	s := &AmdSigner{
		Ark:    b.Ark,
		Ask:    b.Ask,
		Asvk:   b.Asvk,
		Vcek:   b.Vcek,
		Vlek:   b.Vlek,
		Keys:   b.Keys,
		Extras: b.Extras,
		TCB:    b.TCB,
	}
	copy(s.HWID[:], b.HWID[:])
	return s, nil
}

// DefaultTestOnlyCertChain creates a test-only certificate chain for a fake attestation signer.
func DefaultTestOnlyCertChain(productName string, creationTime time.Time) (*AmdSigner, error) {
	keys := DefaultAmdKeys()
	b := &AmdSignerBuilder{
		Keys:             keys,
		ProductName:      productName,
		CSPID:            "go-sev-guest",
		ArkCreationTime:  creationTime,
		AskCreationTime:  creationTime,
		AsvkCreationTime: creationTime,
		VcekCreationTime: creationTime,
		VlekCreationTime: creationTime,
	}
	return b.TestOnlyCertChain()
}

// CertTableBytes outputs the certificates in AMD's ABI format.
func (s *AmdSigner) CertTableBytes() ([]byte, error) {
	// Calculate the output size and the offset at which to copy each certificate.
	const baseEntries = 6 // ARK, ASK, VCEK, VLEK, ASVK, NULL
	entries := baseEntries + len(s.Extras)
	headers := make([]abi.CertTableHeaderEntry, entries)
	headers[0].GUID = uuid.MustParse(abi.ArkGUID)
	headers[0].Offset = uint32(len(headers) * abi.CertTableEntrySize)
	headers[0].Length = uint32(len(s.Ark.Raw))

	headers[1].GUID = uuid.MustParse(abi.AskGUID)
	headers[1].Offset = headers[0].Offset + headers[0].Length
	headers[1].Length = uint32(len(s.Ask.Raw))

	headers[2].GUID = uuid.MustParse(abi.VcekGUID)
	headers[2].Offset = headers[1].Offset + headers[1].Length
	headers[2].Length = uint32(len(s.Vcek.Raw))

	headers[3].GUID = uuid.MustParse(abi.VlekGUID)
	headers[3].Offset = headers[2].Offset + headers[2].Length
	headers[3].Length = uint32(len(s.Vlek.Raw))

	headers[4].GUID = uuid.MustParse(abi.AsvkGUID)
	headers[4].Offset = headers[3].Offset + headers[3].Length
	headers[4].Length = uint32(len(s.Asvk.Raw))

	index := 4
	blobs := [][]byte{s.Ark.Raw, s.Ask.Raw, s.Vcek.Raw, s.Vlek.Raw, s.Asvk.Raw}
	for guid, data := range s.Extras {
		prior := index
		index++
		headers[index].GUID = uuid.MustParse(guid)
		headers[index].Offset = headers[prior].Offset + headers[prior].Length
		headers[index].Length = uint32(len(data))
		blobs = append(blobs, data)
	}

	// Write out the headers and the certificates at the appropriate offsets.
	result := make([]byte, headers[index].Offset+headers[index].Length)
	for i, cert := range blobs {
		if err := (&headers[i]).Write(result[i*abi.CertTableEntrySize:]); err != nil {
			return nil, err
		}
		copy(result[headers[i].Offset:], cert)
	}
	return result, nil
}
