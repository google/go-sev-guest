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

// Package kds defines values specified for the AMD Key Distribution Service.
package kds

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/google/go-sev-guest/abi"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Encapsulates the rest of the fields after AMD's V{C,L}EK OID classifier prefix 1.3.6.1.4.1.3704.1.
type kdsOID struct {
	major int
	minor int
}

var (
	// OidStructVersion is the x509v3 extension for V[CL]EK certificate struct version.
	OidStructVersion = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 1})
	// OidProductName1 is the x509v3 extension for V[CL]EK certificate product name.
	OidProductName1 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 2})
	// OidBlSpl is the x509v3 extension for V[CL]EK certificate bootloader security patch level.
	OidBlSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 1})
	// OidTeeSpl is the x509v3 extension for V[CL]EK certificate TEE security patch level.
	OidTeeSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 2})
	// OidSnpSpl is the x509v3 extension for V[CL]EK certificate SNP security patch level.
	OidSnpSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 3})
	// OidSpl4 is the x509v3 extension for V[CL]EK certificate reserved security patch level.
	OidSpl4 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 4})
	// OidSpl5 is the x509v3 extension for V[CL]EK certificate reserved security patch level.
	OidSpl5 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 5})
	// OidSpl6 is the x509v3 extension for V[CL]EK certificate reserved security patch level.
	OidSpl6 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 6})
	// OidSpl7 is the x509v3 extension for V[CL]EK certificate reserved security patch level.
	OidSpl7 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 7})
	// OidUcodeSpl is the x509v3 extension for V[CL]EK microcode security patch level.
	OidUcodeSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 8})
	// OidHwid is the x509v3 extension for VCEK certificate associated hardware identifier.
	OidHwid = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 4})
	// OidCspID is the x509v3 extension for a VLEK certificate's Cloud Service Provider's
	// origin TLS key's certificate's subject key's CommonName.
	OidCspID = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 5})

	authorityKeyOid = asn1.ObjectIdentifier([]int{2, 5, 29, 35})
	// Short forms of the asn1 Object identifiers to use in map lookups, since []int are invalid key
	// types.
	kdsStructVersion = kdsOID{major: 1}
	kdsProductName1  = kdsOID{major: 2}
	kdsBlSpl         = kdsOID{major: 3, minor: 1}
	kdsTeeSpl        = kdsOID{major: 3, minor: 2}
	kdsSnpSpl        = kdsOID{major: 3, minor: 3}
	kdsSpl4          = kdsOID{major: 3, minor: 4}
	kdsSpl5          = kdsOID{major: 3, minor: 5}
	kdsSpl6          = kdsOID{major: 3, minor: 6}
	kdsSpl7          = kdsOID{major: 3, minor: 7}
	kdsUcodeSpl      = kdsOID{major: 3, minor: 8}
	kdsHwid          = kdsOID{major: 4}
	kdsCspID         = kdsOID{major: 5}

	kdsHostname = "kdsintf.amd.com"
	kdsBaseURL  = "https://" + kdsHostname
	kdsVcekPath = "/vcek/v1/"
	kdsVlekPath = "/vlek/v1/"

	uint0 = &wrapperspb.UInt32Value{Value: 0}
	uint1 = &wrapperspb.UInt32Value{Value: 1}
	uint2 = &wrapperspb.UInt32Value{Value: 2}
	// Chip manufacturers assign stepping versions strings that are <letter><number>
	// to describe a stepping number for a particular model chip. There is no way
	// other than documentation to map a stepping number to a stepping version and
	// vice versa.
	steppingDecoder = map[string]*pb.SevProduct{
		"Milan-B0": {Name: pb.SevProduct_SEV_PRODUCT_MILAN, MachineStepping: uint0},
		"Milan-B1": {Name: pb.SevProduct_SEV_PRODUCT_MILAN, MachineStepping: uint1},
		"Genoa":    {Name: pb.SevProduct_SEV_PRODUCT_GENOA, MachineStepping: uint0},
		"Genoa-B0": {Name: pb.SevProduct_SEV_PRODUCT_GENOA, MachineStepping: uint0},
		"Genoa-B1": {Name: pb.SevProduct_SEV_PRODUCT_GENOA, MachineStepping: uint1},
		"Genoa-B2": {Name: pb.SevProduct_SEV_PRODUCT_GENOA, MachineStepping: uint2},
		"Turin-B0": {Name: pb.SevProduct_SEV_PRODUCT_TURIN, MachineStepping: uint0},
		"Turin-B1": {Name: pb.SevProduct_SEV_PRODUCT_TURIN, MachineStepping: uint1},
	}
	milanSteppingVersions = []string{"B0", "B1"}
	genoaSteppingVersions = []string{"B0", "B1", "B2"}
	turinSteppingVersions = []string{"B0", "B1"}

	// ProductLineCpuid associates the CPUID_1_EAX value (Stepping 0) to its AMD product name.
	ProductLineCpuid = map[uint32]string{
		0x00a00f10: "Milan",
		0x00a10f10: "Genoa",
		0x00b00f20: "Turin",
	}
)

// TCBVersion is a 64-bit bitfield of different security patch levels of AMD firmware and microcode.
type TCBVersion uint64

// Extensions represents the information stored in the KDS-specified x509 extensions of a V{C,L}EK
// certificate.
type Extensions struct {
	StructVersion uint8
	ProductName   string
	// The host driver knows the difference between primary and secondary HWID.
	// Primary vs secondary is irrelevant to verification. Must be nil or
	// abi.ChipIDSize long.
	HWID       []byte
	TCBVersion TCBVersion
	CspID      string
}

func oidTokdsOID(id asn1.ObjectIdentifier) (kdsOID, error) {
	if id.Equal(OidStructVersion) {
		return kdsStructVersion, nil
	}
	if id.Equal(OidProductName1) {
		return kdsProductName1, nil
	}
	if id.Equal(OidBlSpl) {
		return kdsBlSpl, nil
	}
	if id.Equal(OidHwid) {
		return kdsHwid, nil
	}
	if id.Equal(OidTeeSpl) {
		return kdsTeeSpl, nil
	}
	if id.Equal(OidSnpSpl) {
		return kdsSnpSpl, nil
	}
	if id.Equal(OidSpl4) {
		return kdsSpl4, nil
	}
	if id.Equal(OidSpl5) {
		return kdsSpl5, nil
	}
	if id.Equal(OidSpl6) {
		return kdsSpl6, nil
	}
	if id.Equal(OidSpl7) {
		return kdsSpl7, nil
	}
	if id.Equal(OidUcodeSpl) {
		return kdsUcodeSpl, nil
	}
	if id.Equal(OidCspID) {
		return kdsCspID, nil
	}
	return kdsOID{}, fmt.Errorf("not an AMD KDS OID: %v", id)
}

func kdsOidMap(cert *x509.Certificate) (map[kdsOID]*pkix.Extension, error) {
	result := make(map[kdsOID]*pkix.Extension)
	for i, ext := range cert.Extensions {
		if ext.Id.Equal(authorityKeyOid) {
			// Since ASK is a CA, signing can impart the authority key extension.
			continue
		}
		oid, err := oidTokdsOID(ext.Id)
		if err != nil {
			return nil, err
		}
		if _, ok := result[oid]; ok {
			return nil, fmt.Errorf("duplicate AMD KDS extension: %v", ext)
		}
		result[oid] = &cert.Extensions[i]
	}
	return result, nil
}

// TCBParts represents all TCB field values in a given uint64 representation of
// an AMD secure processor firmware TCB version.
type TCBParts struct {
	// BlSpl is the bootloader security patch level.
	BlSpl uint8
	// TeeSpl is the TEE security patch level.
	TeeSpl uint8
	// Spl4 is reserved.
	Spl4 uint8
	// Spl5 is reserved.
	Spl5 uint8
	// Spl6 is reserved.
	Spl6 uint8
	// Spl7 is reserved.
	Spl7 uint8
	// SnpSpl is the SNP security patch level.
	SnpSpl uint8
	// UcodeSpl is the microcode security patch level.
	UcodeSpl uint8
}

// ComposeTCBParts returns an SEV-SNP TCB_VERSION from OID mapping values. The spl4-spl7 fields are
// reserved, but the KDS specification designates them as 4 byte-sized fields.
func ComposeTCBParts(parts TCBParts) (TCBVersion, error) {
	// Only UcodeSpl may be 0-255. All others must be 0-127.
	check127 := func(name string, value uint8) error {
		if value > 127 {
			return fmt.Errorf("%s TCB part is %d. Expect 0-127", name, value)
		}
		return nil
	}
	if err := multierr.Combine(check127("SnpSpl", parts.SnpSpl),
		check127("Spl7", parts.Spl7),
		check127("Spl6", parts.Spl6),
		check127("Spl5", parts.Spl5),
		check127("Spl4", parts.Spl4),
		check127("TeeSpl", parts.TeeSpl),
		check127("BlSpl", parts.BlSpl),
	); err != nil {
		return TCBVersion(0), err
	}
	return TCBVersion(
		(uint64(parts.UcodeSpl) << 56) |
			(uint64(parts.SnpSpl) << 48) |
			(uint64(parts.Spl7) << 40) |
			(uint64(parts.Spl6) << 32) |
			(uint64(parts.Spl5) << 24) |
			(uint64(parts.Spl4) << 16) |
			(uint64(parts.TeeSpl) << 8) |
			(uint64(parts.BlSpl) << 0)), nil
}

// DecomposeTCBVersion interprets the byte components of the AMD representation of the
// platform security patch levels into a struct.
func DecomposeTCBVersion(tcb TCBVersion) TCBParts {
	return TCBParts{
		UcodeSpl: uint8((uint64(tcb) >> 56) & 0xff),
		SnpSpl:   uint8((uint64(tcb) >> 48) & 0xff),
		Spl7:     uint8((uint64(tcb) >> 40) & 0xff),
		Spl6:     uint8((uint64(tcb) >> 32) & 0xff),
		Spl5:     uint8((uint64(tcb) >> 24) & 0xff),
		Spl4:     uint8((uint64(tcb) >> 16) & 0xff),
		TeeSpl:   uint8((uint64(tcb) >> 8) & 0xff),
		BlSpl:    uint8((uint64(tcb) >> 0) & 0xff),
	}
}

// TCBPartsLE returns true iff all TCB components of tcb0 are <= the corresponding tcb1 components.
func TCBPartsLE(tcb0, tcb1 TCBParts) bool {
	return (tcb0.UcodeSpl <= tcb1.UcodeSpl) &&
		(tcb0.SnpSpl <= tcb1.SnpSpl) &&
		(tcb0.Spl7 <= tcb1.Spl7) &&
		(tcb0.Spl6 <= tcb1.Spl6) &&
		(tcb0.Spl5 <= tcb1.Spl5) &&
		(tcb0.Spl4 <= tcb1.Spl4) &&
		(tcb0.TeeSpl <= tcb1.TeeSpl) &&
		(tcb0.BlSpl <= tcb1.BlSpl)
}

func asn1U8(ext *pkix.Extension, field string, out *uint8) error {
	if ext == nil {
		return fmt.Errorf("no extension for field %s", field)
	}
	var i int
	rest, err := asn1.Unmarshal(ext.Value, &i)
	if err != nil {
		return fmt.Errorf("could not parse extension as an integer %v: %v", *ext, err)
	}
	// Check that i is a valid uint8 value.
	if len(rest) != 0 {
		return fmt.Errorf("unexpected leftover bytes for U8 field %s", field)
	}
	if i < 0 || i > 255 {
		return fmt.Errorf("int value for field %s isn't a uint8: %d", field, i)
	}
	*out = uint8(i)
	return nil
}

func asn1IA5String(ext *pkix.Extension, field string, out *string) error {
	if ext == nil || len(ext.Value) == 0 {
		return fmt.Errorf("no extension for field %s", field)
	}
	// Even with the "ia5" params, Unmarshal is too lax about string tags.
	if ext.Value[0] != asn1.TagIA5String {
		return fmt.Errorf("value is not tagged as an IA5String: %d", ext.Value[0])
	}
	rest, err := asn1.UnmarshalWithParams(ext.Value, out, "ia5")
	if err != nil {
		return fmt.Errorf("could not parse extension as an IA5String %v: %v", *ext, err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("unexpected leftover bytes for IA5String field %s", field)
	}
	return nil
}

func asn1OctetString(ext *pkix.Extension, field string, size int) ([]byte, error) {
	if ext == nil {
		return nil, fmt.Errorf("no extension for field %s", field)
	}
	// ASN1 requires a type tag, but for some reason the KDS doesn't add that for the HWID.
	if len(ext.Value) == size {
		return ext.Value, nil
	}
	// In case AMD adds the type and the value's length increases to include the type tag, then try
	// to unmarshal here.
	var octet []byte
	rest, err := asn1.Unmarshal(ext.Value, &octet)
	if err != nil {
		return nil, fmt.Errorf("could not parse extension as an octet string %v (value %v): %v", *ext, ext.Value, err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("expected leftover bytes in extension value for field %v", field)
	}
	// Check the expected length.
	if size >= 0 && len(octet) != size {
		return nil, fmt.Errorf("size is %d, expected %d", len(octet), size)
	}
	return octet, nil
}

func kdsOidMapToExtensions(exts map[kdsOID]*pkix.Extension) (*Extensions, error) {
	var result Extensions

	if err := asn1U8(exts[kdsStructVersion], "StructVersion", &result.StructVersion); err != nil {
		return nil, err
	}
	if err := asn1IA5String(exts[kdsProductName1], "ProductName1", &result.ProductName); err != nil {
		return nil, err
	}
	hwidExt, ok := exts[kdsHwid]
	if ok {
		octet, err := asn1OctetString(hwidExt, "HWID", 64)
		if err != nil {
			return nil, err
		}
		result.HWID = octet
	}
	cspidExt := exts[kdsCspID]
	if cspidExt != nil {
		if err := asn1IA5String(cspidExt, "CSP_ID", &result.CspID); err != nil {
			return nil, err
		}
		if hwidExt != nil {
			return nil, fmt.Errorf("certificate has both HWID (%s) and CSP_ID (%s) extensions", hex.EncodeToString(result.HWID), result.CspID)
		}
	}
	var blspl, snpspl, teespl, spl4, spl5, spl6, spl7, ucodespl uint8
	if err := asn1U8(exts[kdsBlSpl], "BlSpl", &blspl); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[kdsTeeSpl], "TeeSpl", &teespl); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[kdsSnpSpl], "SnpSpl", &snpspl); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[kdsSpl4], "Spl4", &spl4); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[kdsSpl5], "Spl5", &spl5); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[kdsSpl6], "Spl6", &spl6); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[kdsSpl7], "Spl7", &spl7); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[kdsUcodeSpl], "UcodeSpl", &ucodespl); err != nil {
		return nil, err
	}
	tcb, err := ComposeTCBParts(TCBParts{
		BlSpl:    blspl,
		SnpSpl:   snpspl,
		TeeSpl:   teespl,
		Spl4:     spl4,
		Spl5:     spl5,
		Spl6:     spl6,
		Spl7:     spl7,
		UcodeSpl: ucodespl,
	})
	if err != nil {
		return nil, err
	}
	result.TCBVersion = tcb
	return &result, nil
}

// preEndorsementKeyCertificateExtensions returns the x509v3 extensions from the KDS specification interpreted
// into a struct type for either the VCEK or the VLEK
func preEndorsementKeyCertificateExtensions(cert *x509.Certificate) (*Extensions, error) {
	oidMap, err := kdsOidMap(cert)
	if err != nil {
		return nil, err
	}
	extensions, err := kdsOidMapToExtensions(oidMap)
	if err != nil {
		return nil, err
	}
	return extensions, nil
}

// VcekCertificateExtensions returns the x509v3 extensions from the KDS specification of a VCEK
// certificate interpreted into a struct type.
func VcekCertificateExtensions(cert *x509.Certificate) (*Extensions, error) {
	if cert == nil {
		return nil, fmt.Errorf("cert cannot be nil")
	}
	exts, err := preEndorsementKeyCertificateExtensions(cert)
	if err != nil {
		return nil, err
	}
	if exts.CspID != "" {
		return nil, fmt.Errorf("unexpected CSP_ID in VCEK certificate: %s", exts.CspID)
	}
	if len(exts.HWID) != abi.ChipIDSize {
		return nil, fmt.Errorf("missing HWID extension for VCEK certificate")
	}
	return exts, nil
}

// VlekCertificateExtensions returns the x509v3 extensions from the KDS specification of a VLEK
// certificate interpreted into a struct type.
func VlekCertificateExtensions(cert *x509.Certificate) (*Extensions, error) {
	if cert == nil {
		return nil, fmt.Errorf("cert cannot be nil")
	}
	exts, err := preEndorsementKeyCertificateExtensions(cert)
	if err != nil {
		return nil, err
	}
	if exts.CspID == "" {
		return nil, fmt.Errorf("missing CSP_ID in VLEK certificate")
	}
	if exts.HWID != nil {
		return nil, fmt.Errorf("unexpected HWID in VLEK certificate: %s", hex.EncodeToString(exts.HWID))
	}
	return exts, nil
}

// CertificateExtensions returns the x509v3 extensions from the KDS specification interpreted
// into a struct type.
func CertificateExtensions(cert *x509.Certificate, key abi.ReportSigner) (*Extensions, error) {
	switch key {
	case abi.VcekReportSigner:
		return VcekCertificateExtensions(cert)
	case abi.VlekReportSigner:
		return VlekCertificateExtensions(cert)
	case abi.NoneReportSigner:
		return &Extensions{}, nil
	}
	return nil, fmt.Errorf("unexpected endorsement key kind %v", key)
}

// ParseProductCertChain returns the DER-formatted certificates represented by the body
// of the ProductCertChain (cert_chain) endpoint, ASK and ARK in that order.
func ParseProductCertChain(pems []byte) ([]byte, []byte, error) {
	checkForm := func(name string, b *pem.Block) error {
		if b == nil {
			return fmt.Errorf("could not find %s PEM block", name)
		}
		if b.Type != "CERTIFICATE" {
			return fmt.Errorf("the %s PEM block type is %s. Expect CERTIFICATE", name, b.Type)
		}
		if len(b.Headers) != 0 {
			return fmt.Errorf("the %s PEM block has non-empty headers: %v", name, b.Headers)
		}
		return nil
	}
	askBlock, arkRest := pem.Decode(pems)
	arkBlock, noRest := pem.Decode(arkRest)
	if err := multierr.Combine(checkForm("ASK or ASVK", askBlock), checkForm("ARK", arkBlock)); err != nil {
		return nil, nil, err
	}
	if len(noRest) != 0 {
		return nil, nil, fmt.Errorf("unexpected trailing bytes: %d bytes", len(noRest))
	}
	return askBlock.Bytes, arkBlock.Bytes, nil
}

// productBaseURL returns the base URL for all certificate queries within a particular product for the
// given report signer kind.
func productBaseURL(s abi.ReportSigner, name string) string {
	path := "unknown"
	if s == abi.VcekReportSigner {
		path = kdsVcekPath
	}
	if s == abi.VlekReportSigner {
		path = kdsVlekPath
	}
	return fmt.Sprintf("%s%s%s", kdsBaseURL, path, name)
}

// ProductCertChainURL returns the AMD KDS URL for retrieving the ARK and AS(V)K
// certificates on the given product in ??? format.
func ProductCertChainURL(s abi.ReportSigner, productLine string) string {
	return fmt.Sprintf("%s/cert_chain", productBaseURL(s, productLine))
}

// VCEKCertURL returns the AMD KDS URL for retrieving the VCEK on a given product
// at a given TCB version. The hwid is the CHIP_ID field in an attestation report.
func VCEKCertURL(productLine string, hwid []byte, tcb TCBVersion) string {
	parts := DecomposeTCBVersion(tcb)
	return fmt.Sprintf("%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		productBaseURL(abi.VcekReportSigner, productLine),
		hex.EncodeToString(hwid),
		parts.BlSpl,
		parts.TeeSpl,
		parts.SnpSpl,
		parts.UcodeSpl,
	)
}

// VLEKCertURL returns the GET URL for retrieving a VLEK certificate, but without the necessary
// CSP secret in the HTTP headers that makes the request validate to the KDS.
func VLEKCertURL(productLine string, tcb TCBVersion) string {
	parts := DecomposeTCBVersion(tcb)
	return fmt.Sprintf("%s/cert?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		productBaseURL(abi.VlekReportSigner, productLine),
		parts.BlSpl,
		parts.TeeSpl,
		parts.SnpSpl,
		parts.UcodeSpl,
	)
}

// VCEKCert represents the attestation report components represented in a KDS VCEK certificate
// request URL.
type VCEKCert struct {
	// Product is the product string (no stepping value) present in the VCEK cert url
	//
	// Deprecated: Use ProductLine.
	Product     string
	ProductLine string
	HWID        []byte
	TCB         uint64
}

// VCEKCertProduct returns a VCEKCert with the product line set to productLine.
func VCEKCertProduct(productLine string) VCEKCert {
	return VCEKCert{
		Product:     productLine, // TODO(Issue#114): Remove
		ProductLine: productLine,
	}
}

// VLEKCert represents the attestation report components represented in a KDS VLEK certificate
// request URL.
type VLEKCert struct {
	// Product is the product string (no stepping value) present in the VCEK cert url
	//
	// Deprecated: Use ProductLine.
	Product     string
	ProductLine string
	TCB         uint64
}

// CertFunction is an enumeration of which endorsement key type is getting certified.
type CertFunction int

const (
	// UnknownCertFunction represents an unknown endpoint for parsing KDS URLs.
	UnknownCertFunction CertFunction = iota
	// VcekCertFunction represents the vcek endpoints for parsing KDS URLs.
	VcekCertFunction
	// VlekCertFunction represents the vlek endpoints for parsing KDS URLs.
	VlekCertFunction
)

type parsedURL struct {
	productLine string
	simpleURL   *url.URL
	function    CertFunction
}

// parseBaseProductURL returns the product name for a root certificate chain URL if it is one,
// with the parsed URL that has the product prefix trimmed.
func parseBaseProductURL(kdsurl string) (*parsedURL, error) {
	u, err := url.Parse(kdsurl)
	if err != nil {
		return nil, fmt.Errorf("invalid AMD KDS URL %q: %v", kdsurl, err)
	}
	if u.Scheme != "https" {
		return nil, fmt.Errorf("unexpected AMD KDS URL scheme %q, want \"https\"", u.Scheme)
	}
	if u.Host != kdsHostname {
		return nil, fmt.Errorf("unexpected AMD KDS URL host %q, want %q", u.Host, kdsHostname)
	}
	result := &parsedURL{}
	vcekFunc := strings.HasPrefix(u.Path, kdsVcekPath)
	vlekFunc := strings.HasPrefix(u.Path, kdsVlekPath)
	var function string
	if vcekFunc {
		function = strings.TrimPrefix(u.Path, kdsVcekPath)
		result.function = VcekCertFunction
	} else if vlekFunc {
		function = strings.TrimPrefix(u.Path, kdsVlekPath)
		result.function = VlekCertFunction
	} else {
		return nil, fmt.Errorf("unexpected AMD KDS URL path %q, want prefix %q or %q", u.Path, kdsVcekPath, kdsVlekPath)
	}

	// The following should be product/endpoint
	pieces := strings.Split(function, "/")
	if len(pieces) != 2 {
		return nil, fmt.Errorf("url has unexpected endpoint %q not product/endpoint", function)
	}

	result.productLine = pieces[0]
	// Set the URL's path to the rest of the path without the API or product prefix.
	u.Path = pieces[1]
	result.simpleURL = u
	return result, nil
}

// ParseProductCertChainURL returns the product name and either "vcek" or "vlek" for a KDS
// cert_chain url, or an error if the input is not a KDS cert_chain url.
func ParseProductCertChainURL(kdsurl string) (string, CertFunction, error) {
	parsed, err := parseBaseProductURL(kdsurl)
	if err != nil {
		return "", UnknownCertFunction, err
	}
	if parsed.simpleURL.Path != "cert_chain" {
		return "", UnknownCertFunction, fmt.Errorf("unexpected AMD KDS URL path %q, want \"cert_chain\"", parsed.simpleURL.Path)
	}
	return parsed.productLine, parsed.function, nil
}

func parseTCBURL(u *url.URL) (uint64, error) {
	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return 0, fmt.Errorf("invalid AMD KDS URL query %q: %v", u.RawQuery, err)
	}
	parts := TCBParts{}
	for key, valuelist := range values {
		var setter func(number uint8)
		switch key {
		case "blSPL":
			setter = func(number uint8) { parts.BlSpl = number }
		case "teeSPL":
			setter = func(number uint8) { parts.TeeSpl = number }
		case "snpSPL":
			setter = func(number uint8) { parts.SnpSpl = number }
		case "ucodeSPL":
			setter = func(number uint8) { parts.UcodeSpl = number }
		default:
			return 0, fmt.Errorf("unexpected KDS TCB version URL argument %q", key)
		}
		for _, val := range valuelist {
			number, err := strconv.Atoi(val)
			if err != nil || number < 0 || number > 255 {
				return 0, fmt.Errorf("invalid KDS TCB version URL argument value %q, want a value 0-255", val)
			}
			setter(uint8(number))
		}
	}
	tcb, err := ComposeTCBParts(parts)
	if err != nil {
		return 0, fmt.Errorf("invalid AMD KDS TCB arguments: %v", err)
	}
	return uint64(tcb), err
}

// ParseVCEKCertURL returns the attestation report components represented in the given KDS VCEK
// certificate request URL.
func ParseVCEKCertURL(kdsurl string) (VCEKCert, error) {
	result := VCEKCert{}
	parsed, err := parseBaseProductURL(kdsurl)
	if err != nil {
		return result, err
	}
	if parsed.function != VcekCertFunction {
		return result, fmt.Errorf("not a VCEK certificate URL: %s", kdsurl)
	}
	result.Product = parsed.productLine // TODO(Issue#114): Remove.
	result.ProductLine = parsed.productLine
	hwid, err := hex.DecodeString(parsed.simpleURL.Path)
	if err != nil {
		return result, fmt.Errorf("hwid component of KDS URL is not a hex string: %q", parsed.simpleURL.Path)
	}
	if len(hwid) != abi.ChipIDSize {
		return result, fmt.Errorf("hwid component of KDS URL has size %d, want %d", len(hwid), abi.ChipIDSize)
	}

	result.HWID = hwid

	result.TCB, err = parseTCBURL(parsed.simpleURL)
	return result, err
}

// ParseVLEKCertURL returns the attestation report components represented in the given KDS VLEK
// certificate request URL.
func ParseVLEKCertURL(kdsurl string) (VLEKCert, error) {
	result := VLEKCert{}
	parsed, err := parseBaseProductURL(kdsurl)
	if err != nil {
		return result, err
	}
	if parsed.function != VlekCertFunction {
		return result, fmt.Errorf("not a VLEK certificate URL: %s", kdsurl)
	}
	result.Product = parsed.productLine // TODO(Issue#114): Remove.
	result.ProductLine = parsed.productLine
	if parsed.simpleURL.Path != "cert" {
		return result, fmt.Errorf("vlek function is %q, want 'cert'", parsed.simpleURL.Path)
	}

	result.TCB, err = parseTCBURL(parsed.simpleURL)
	return result, err
}

// ProductString returns the KDS product argument to use for the product associated with
// an attestation report proto.
//
// Deprecated: Use ProductLine()
func ProductString(product *pb.SevProduct) string {
	return ProductLine(product)
}

// ProductLine returns the KDS product argument to use for the product associated with
// an attestation report proto.
func ProductLine(product *pb.SevProduct) string {
	if product == nil {
		product = abi.DefaultSevProduct()
	}
	switch product.Name {
	case pb.SevProduct_SEV_PRODUCT_MILAN:
		return "Milan"
	case pb.SevProduct_SEV_PRODUCT_GENOA:
		return "Genoa"
	case pb.SevProduct_SEV_PRODUCT_TURIN:
		return "Turin"
	default:
		return "Unknown"
	}
}

// ProductLineOfProductName returns the product represented by productNameOrProductLine, i.e.,
// without the stepping suffix.
func ProductLineOfProductName(productNameOrProductLine string) string {
	product, err := ParseProductLine(productNameOrProductLine)
	if err != nil {
		product, err = ParseProductName(productNameOrProductLine, abi.VcekReportSigner)
	}
	if err != nil {
		return "Unknown"
	}
	return ProductLine(product)
}

// DefaultProductString returns the product line of the default SEV product.
//
// Deprecated: Use DefaultProductLine()
func DefaultProductString() string {
	return DefaultProductLine()
}

// DefaultProductLine returns the product line of the default SEV product.
func DefaultProductLine() string {
	return ProductLine(abi.DefaultSevProduct())
}

// ProductName returns the expected productName extension value for the product associated
// with an attestation report proto.
func ProductName(product *pb.SevProduct) string {
	if product == nil {
		product = abi.DefaultSevProduct()
	}
	// Can't produce a product name without a stepping value.
	if product.MachineStepping == nil {
		return "UnknownStepping"
	}
	stepping := product.MachineStepping.Value
	if stepping > 15 {
		return "badstepping"
	}
	switch product.Name {
	case pb.SevProduct_SEV_PRODUCT_MILAN:
		if int(stepping) >= len(milanSteppingVersions) {
			return "unmappedMilanStepping"
		}
		return fmt.Sprintf("Milan-%s", milanSteppingVersions[stepping])
	case pb.SevProduct_SEV_PRODUCT_GENOA:
		if int(stepping) >= len(genoaSteppingVersions) {
			return "unmappedGenoaStepping"
		}
		return fmt.Sprintf("Genoa-%s", genoaSteppingVersions[stepping])
	case pb.SevProduct_SEV_PRODUCT_TURIN:
		if int(stepping) >= len(turinSteppingVersions) {
			return "unmappedTurinStepping"
		}
		return fmt.Sprintf("Turin-%s", turinSteppingVersions[stepping])
	default:
		return "Unknown"
	}
}

// ProductLineFromFms returns the product name used in the KDS endpoint to fetch VCEK certificates.
func ProductLineFromFms(fms uint32) string {
	return ProductLine(abi.SevProductFromCpuid1Eax(fms))
}

// ParseProduct returns the SevProductName for a product name without the stepping suffix.
//
// Deprecated: Use ParseProductLine
func ParseProduct(productLine string) (pb.SevProduct_SevProductName, error) {
	p, err := ParseProductLine(productLine)
	if err != nil {
		return pb.SevProduct_SEV_PRODUCT_UNKNOWN, nil
	}
	return p.Name, nil
}

// ParseProductLine returns the SevProductName for a product name without the stepping suffix.
func ParseProductLine(productLine string) (*pb.SevProduct, error) {
	switch productLine {
	case "Milan":
		return &pb.SevProduct{Name: pb.SevProduct_SEV_PRODUCT_MILAN}, nil
	case "Genoa":
		return &pb.SevProduct{Name: pb.SevProduct_SEV_PRODUCT_GENOA}, nil
	case "Turin":
		return &pb.SevProduct{Name: pb.SevProduct_SEV_PRODUCT_TURIN}, nil
	default:
		return nil, fmt.Errorf("unknown AMD SEV product: %q", productLine)
	}
}

// ParseProductName returns the KDS project input value, and the model, stepping numbers represented
// by a given V[CL]EK productName extension value, or an error.
func ParseProductName(productName string, key abi.ReportSigner) (*pb.SevProduct, error) {
	switch key {
	case abi.VcekReportSigner:
		product, ok := steppingDecoder[productName]
		if !ok {
			return nil, fmt.Errorf("unknown product name (new stepping published?): %q", productName)
		}
		return product, nil
	case abi.VlekReportSigner:
		// VLEK certificates don't carry the stepping value in productName.
		return ParseProductLine(productName)
	}
	return nil, fmt.Errorf("internal: unhandled reportSigner %v", key)
}

// CrlLinkByKey returns the CRL distribution point for the given key type's
// product. If key is VlekReportSigner, then we use the vlek endpoint. The ASK
// and ARK are both on the vcek endpoint.
func CrlLinkByKey(productLine string, key abi.ReportSigner) string {
	return fmt.Sprintf("%s/crl", productBaseURL(key, productLine))
}

// CrlLinkByRole returns the CRL distribution point for the given key role's
// product. If role is "ASVK", then we use the vlek endpoint. The ASK and ARK
// are both on the vcek endpoint.
func CrlLinkByRole(productLine, role string) string {
	key := abi.VcekReportSigner
	if role == "ASVK" {
		key = abi.VlekReportSigner
	}
	return CrlLinkByKey(productLine, key)
}
