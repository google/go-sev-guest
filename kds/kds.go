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
	"go.uber.org/multierr"
)

// Encapsulates the rest of the fields after AMD's VCEK OID classifier prefix 1.3.6.1.4.1.3704.1.
type vcekOID struct {
	major int
	minor int
}

var (
	// OidStructVersion is the x509v3 extension for VCEK certificate struct version.
	OidStructVersion = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 1})
	// OidProductName1 is the x509v3 extension for VCEK certificate product name.
	OidProductName1 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 2})
	// OidBlSpl is the x509v3 extension for VCEK certificate bootloader security patch level.
	OidBlSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 1})
	// OidTeeSpl is the x509v3 extension for VCEK certificate TEE security patch level.
	OidTeeSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 2})
	// OidSnpSpl is the x509v3 extension for VCEK certificate SNP security patch level.
	OidSnpSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 3})
	// OidSpl4 is the x509v3 extension for VCEK certificate reserved security patch level.
	OidSpl4 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 4})
	// OidSpl5 is the x509v3 extension for VCEK certificate reserved security patch level.
	OidSpl5 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 5})
	// OidSpl6 is the x509v3 extension for VCEK certificate reserved security patch level.
	OidSpl6 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 6})
	// OidSpl7 is the x509v3 extension for VCEK certificate reserved security patch level.
	OidSpl7 = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 7})
	// OidUcodeSpl is the x509v3 extension for VCEK microcode security patch level.
	OidUcodeSpl = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 3, 8})
	// OidHwid is the x509v3 extension for VCEK certificate associated hardware identifier.
	OidHwid         = asn1.ObjectIdentifier([]int{1, 3, 6, 1, 4, 1, 3704, 1, 4})
	authorityKeyOid = asn1.ObjectIdentifier([]int{2, 5, 29, 35})
	// Short forms of the asn1 Object identifiers to use in map lookups, since []int are invalid key
	// types.
	vcekStructVersion = vcekOID{major: 1}
	vcekProductName1  = vcekOID{major: 2}
	vcekBlSpl         = vcekOID{major: 3, minor: 1}
	vcekTeeSpl        = vcekOID{major: 3, minor: 2}
	vcekSnpSpl        = vcekOID{major: 3, minor: 3}
	vcekSpl4          = vcekOID{major: 3, minor: 4}
	vcekSpl5          = vcekOID{major: 3, minor: 5}
	vcekSpl6          = vcekOID{major: 3, minor: 6}
	vcekSpl7          = vcekOID{major: 3, minor: 7}
	vcekUcodeSpl      = vcekOID{major: 3, minor: 8}
	vcekHwid          = vcekOID{major: 4}

	kdsHostname = "kdsintf.amd.com"
	kdsBaseURL  = "https://" + kdsHostname
	kdsVcekPath = "/vcek/v1/"
)

// TCBVersion is a 64-bit bitfield of different security patch levels of AMD firmware and microcode.
type TCBVersion uint64

// VcekExtensions represents the information stored in the KDS-specified x509 extensions of a VCEK
// certificate.
type VcekExtensions struct {
	StructVersion uint8
	ProductName   string
	// The host driver knows the difference between primary and secondary HWID.
	// Primary vs secondary is irrelevant to verification.
	HWID       [64]byte
	TCBVersion TCBVersion
}

func oidTovcekOID(id asn1.ObjectIdentifier) (vcekOID, error) {
	if id.Equal(OidStructVersion) {
		return vcekStructVersion, nil
	}
	if id.Equal(OidProductName1) {
		return vcekProductName1, nil
	}
	if id.Equal(OidBlSpl) {
		return vcekBlSpl, nil
	}
	if id.Equal(OidHwid) {
		return vcekHwid, nil
	}
	if id.Equal(OidTeeSpl) {
		return vcekTeeSpl, nil
	}
	if id.Equal(OidSnpSpl) {
		return vcekSnpSpl, nil
	}
	if id.Equal(OidSpl4) {
		return vcekSpl4, nil
	}
	if id.Equal(OidSpl5) {
		return vcekSpl5, nil
	}
	if id.Equal(OidSpl6) {
		return vcekSpl6, nil
	}
	if id.Equal(OidSpl7) {
		return vcekSpl7, nil
	}
	if id.Equal(OidUcodeSpl) {
		return vcekUcodeSpl, nil
	}
	return vcekOID{}, fmt.Errorf("not an AMD VCEK OID: %v", id)
}

func vcekOidMap(cert *x509.Certificate) (map[vcekOID]*pkix.Extension, error) {
	result := make(map[vcekOID]*pkix.Extension)
	for i, ext := range cert.Extensions {
		if ext.Id.Equal(authorityKeyOid) {
			// Since ASK is a CA, signing can impart the authority key extension.
			continue
		}
		oid, err := oidTovcekOID(ext.Id)
		if err != nil {
			return nil, err
		}
		if _, ok := result[oid]; ok {
			return nil, fmt.Errorf("duplicate VCEK extension: %v", ext)
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
	if ext == nil {
		return fmt.Errorf("no extension for field %s", field)
	}
	rest, err := asn1.Unmarshal(ext.Value, out)
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

func vcekOidMapToVcekExtensions(exts map[vcekOID]*pkix.Extension) (*VcekExtensions, error) {
	var result VcekExtensions

	if err := asn1U8(exts[vcekStructVersion], "StructVersion", &result.StructVersion); err != nil {
		return nil, err
	}
	if err := asn1IA5String(exts[vcekProductName1], "ProductName1", &result.ProductName); err != nil {
		return nil, err
	}
	octet, err := asn1OctetString(exts[vcekHwid], "HWID", 64)
	if err != nil {
		return nil, err
	}
	copy(result.HWID[:], octet)
	var blspl, snpspl, teespl, spl4, spl5, spl6, spl7, ucodespl uint8
	if err := asn1U8(exts[vcekBlSpl], "BlSpl", &blspl); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[vcekTeeSpl], "TeeSpl", &teespl); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[vcekSnpSpl], "SnpSpl", &snpspl); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[vcekSpl4], "Spl4", &spl4); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[vcekSpl5], "Spl5", &spl5); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[vcekSpl6], "Spl6", &spl6); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[vcekSpl7], "Spl7", &spl7); err != nil {
		return nil, err
	}
	if err := asn1U8(exts[vcekUcodeSpl], "UcodeSpl", &ucodespl); err != nil {
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

// VcekCertificateExtensions returns the x509v3 extensions from the KDS specification interpreted
// into a struct type.
func VcekCertificateExtensions(cert *x509.Certificate) (*VcekExtensions, error) {
	oidMap, err := vcekOidMap(cert)
	if err != nil {
		return nil, err
	}
	extensions, err := vcekOidMapToVcekExtensions(oidMap)
	if err != nil {
		return nil, err
	}
	return extensions, nil
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
	if err := multierr.Combine(checkForm("ASK", askBlock), checkForm("ARK", arkBlock)); err != nil {
		return nil, nil, err
	}
	if len(noRest) != 0 {
		return nil, nil, fmt.Errorf("unexpected trailing bytes: %d bytes", len(noRest))
	}
	return askBlock.Bytes, arkBlock.Bytes, nil
}

// productBaseURL returns the base URL for all certificate queries within a particular product.
func productBaseURL(name string) string {
	return fmt.Sprintf("%s/vcek/v1/%s", kdsBaseURL, name)
}

// ProductCertChainURL returns the AMD KDS URL for retrieving the ARK and ASK
// certificates on the given product in PEM format.
func ProductCertChainURL(product string) string {
	return fmt.Sprintf("%s/cert_chain", productBaseURL(product))
}

// VCEKCertURL returns the AMD KDS URL for retrieving the VCEK on a given product
// at a given TCB version. The hwid is the CHIP_ID field in an attestation report.
func VCEKCertURL(product string, hwid []byte, tcb TCBVersion) string {
	parts := DecomposeTCBVersion(tcb)
	return fmt.Sprintf("%s/%s?blSPL=%d&teeSPL=%d&snpSPL=%d&ucodeSPL=%d",
		productBaseURL(product),
		hex.EncodeToString(hwid),
		parts.BlSpl,
		parts.TeeSpl,
		parts.SnpSpl,
		parts.UcodeSpl,
	)
}

// VCEKCert represents the attestation report components represented in a KDS VCEK certificate
// request URL.
type VCEKCert struct {
	Product string
	HWID    []byte
	TCB     uint64
}

// parseBaseProductURL returns the product name for a root certificate chain URL if it is one,
// with the parsed URL that has the product prefix trimmed.
func parseBaseProductURL(kdsurl string) (string, *url.URL, error) {
	u, err := url.Parse(kdsurl)
	if err != nil {
		return "", nil, fmt.Errorf("invalid AMD KDS URL %q: %v", kdsurl, err)
	}
	if u.Scheme != "https" {
		return "", nil, fmt.Errorf("unexpected AMD KDS URL scheme %q, want \"https\"", u.Scheme)
	}
	if u.Host != kdsHostname {
		return "", nil, fmt.Errorf("unexpected AMD KDS URL host %q, want %q", u.Host, kdsHostname)
	}
	if !strings.HasPrefix(u.Path, kdsVcekPath) {
		return "", nil, fmt.Errorf("unexpected AMD KDS URL path %q, want prefix %q", u.Path, kdsVcekPath)
	}
	function := strings.TrimPrefix(u.Path, kdsVcekPath)

	// The following should be product/endpoint
	pieces := strings.Split(function, "/")
	if len(pieces) != 2 {
		return "", nil, fmt.Errorf("url has unexpected endpoint %q not product/endpoint", function)
	}

	product := pieces[0]
	// Set the URL's path to the rest of the path without the API or product prefix.
	u.Path = pieces[1]
	return product, u, nil
}

// ParseProductCertChainURL returns the product name for a KDS cert_chain url, or an error if the
// input is not a KDS cert_chain url.
func ParseProductCertChainURL(kdsurl string) (string, error) {
	product, u, err := parseBaseProductURL(kdsurl)
	if err != nil {
		return "", err
	}
	if u.Path != "cert_chain" {
		return "", fmt.Errorf("unexpected AMD KDS URL path %q, want \"cert_chain\"", u.Path)
	}
	return product, nil
}

// ParseVCEKCertURL returns the attestation report components represented in the given KDS VCEK
// certificate request URL.
func ParseVCEKCertURL(kdsurl string) (VCEKCert, error) {
	result := VCEKCert{}
	product, u, err := parseBaseProductURL(kdsurl)
	if err != nil {
		return result, err
	}
	result.Product = product
	hwid, err := hex.DecodeString(u.Path)
	if err != nil {
		return result, fmt.Errorf("hwid component of KDS URL is not a hex string: %q", u.Path)
	}
	if len(hwid) != abi.ChipIDSize {
		return result, fmt.Errorf("hwid component of KDS URL has size %d, want %d", len(hwid), abi.ChipIDSize)
	}

	result.HWID = hwid

	values, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return result, fmt.Errorf("invalid AMD KDS URL query %q: %v", u.RawQuery, err)
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
			return result, fmt.Errorf("unexpected KDS VCEK URL argument %q", key)
		}
		for _, val := range valuelist {
			number, err := strconv.Atoi(val)
			if err != nil || number < 0 || number > 255 {
				return result, fmt.Errorf("invalid KDS VCEK URL argument value %q, want a value 0-255", val)
			}
			setter(uint8(number))
		}
	}
	tcb, err := ComposeTCBParts(parts)
	if err != nil {
		return result, fmt.Errorf("invalid AMD KDS TCB arguments: %v", err)
	}
	result.TCB = uint64(tcb)
	return result, nil
}
