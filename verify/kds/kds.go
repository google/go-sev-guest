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
	"fmt"
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

// makeTCBVersion returns an SEV-SNP TCB_VERSION from OID mapping values. The spl4-spl7 fields are
// reserved, but the KDS specification designates them as 4 byte-sized fields.
func makeTCBVersion(blspl, snpspl, teespl, spl4, spl5, spl6, spl7, ucodespl uint8) TCBVersion {
	return TCBVersion(
		(uint64(ucodespl) << 56) |
			(uint64(snpspl) << 48) |
			(uint64(spl7) << 40) |
			(uint64(spl6) << 32) |
			(uint64(spl5) << 24) |
			(uint64(spl4) << 16) |
			(uint64(teespl) << 8) |
			(uint64(blspl) << 0))
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
	result.TCBVersion = makeTCBVersion(blspl, snpspl, teespl, spl4, spl5, spl6, spl7, ucodespl)
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
