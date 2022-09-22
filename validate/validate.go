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

// Package validate is for checking attestation report properties other than signature verification.
package validate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"go.uber.org/multierr"
)

// Options represents verification options for an SEV-SNP attestation report.
type Options struct {
	// GuestPolicy is the maximum of acceptable guest policies.
	GuestPolicy abi.SnpPolicy
	// UserData is the expected REPORT_DATA field. Must be nil or 64 bytes long. Not checked if nil.
	UserData []byte
	// HostData is the expected HOST_DATA field. Must be nil or 32 bytes long. Not checked if nil.
	HostData []byte
	// ImageID is the expected IMAGE_ID field. Must be nil or 16 bytes long. Not checked if nil.
	ImageID []byte
	// FamilyID is the expected FAMILY_ID field. Must be nil or 16 bytes long. Not checked if nil.
	FamilyID []byte
	// ReportID is the expected REPORT_ID field. Must be nil or 32 bytes long. Not checked if nil.
	ReportID []byte
	// ReportIDMA is the expected REPORT_ID_MA field. Must be nil or 32 bytes long. Not checked if nil.
	ReportIDMA []byte
	// Measurement is the expected MEASUREMENT field. Must be nil or 48 bytes long. Not checked if nil.
	Measurement []byte
	// ChipID is the expected CHIP_ID field. Must be nil or 64 bytes long. Not checked if nil.
	ChipID []byte
	// MinimumBuild is the minimum firmware build version reported in the attestation report.
	MinimumBuild uint8
	// MinimumVersion is the minimum firmware API version reported in the attestation report,
	// where the MSB is the major number and the LSB is the minor number.
	MinimumVersion uint16
	// MinimumTCB is the component-wise minimum TCB reported in the attestation report. This
	// does not include the LaunchTCB.
	MinimumTCB kds.TCBParts
	// MinimumLaunchTCB is the component-wise minimum for the attestation report LaunchTCB.
	MinimumLaunchTCB kds.TCBParts
	// PermitProvisionalFirmware if true, allows the committed TCB, build, and API values to be less
	// than or equal to the current values. If false, committed and current values must be equal.
	PermitProvisionalFirmware bool
	// PlatformInfo is the maximum of acceptable PLATFORM_INFO data. Not checked if nil.
	PlatformInfo *abi.SnpPlatformInfo
	// RequireAuthorKey if true, will not validate a report without AUTHOR_KEY_EN equal to 1.
	RequireAuthorKey bool
	// RequireIDBlock if true, will not validate a report if it does not have an ID_KEY_DIGEST that
	// is trusted through all keys in TrustedIDKeys or TrustedIDKeyHashes, or any ID key whose hash
	// was signed by a key in TrustedAuthorKeys or TrustedIDKeyHashes. No signatures are checked,
	// since presence in the attestation report implies that the AMD firmware successfully verified
	// the signature at VM launch. If false, ID_KEY_DIGEST and AUTHOR_KEY_DIGEST are not checked.
	RequireIDBlock bool
	// Certificates of keys that are permitted to sign ID keys. Any ID key signed by a trusted author
	// key is implicitly trusted. Not required if TrustedAuthorKeyHashes is provided.
	TrustedAuthorKeys []*x509.Certificate
	// TrustedAuthorKeys is an array of SHA-384 hashes of trusted author keys's public key in SEV-SNP
	// API format. Not required if TrustedAuthorKeys is provided.
	TrustedAuthorKeyHashes [][]byte
	// Certificates of keys that are permitted to sign IDBlocks. Not required if TrustedIDKeyHashes is
	// provided.
	TrustedIDKeys []*x509.Certificate
	// TrustedIDKeyHashes is an array of SHA-384 hashes of trusted ID signer keys's public key in
	// SEV-SNP API format. Not required if TrustedKeyKeys is provided.
	TrustedIDKeyHashes [][]byte
}

// <0 if p0 < p1. 0 if p0 = p1. >0 if p0 > p1.
func compareByteVersions(major0, minor0, major1, minor1 uint8) int64 {
	version0 := (uint16(major0) << 8) | uint16(minor0)
	version1 := (uint16(major1) << 8) | uint16(minor1)
	return int64(version0) - int64(version1)
}

func comparePolicyVersions(p0 abi.SnpPolicy, p1 abi.SnpPolicy) int64 {
	return compareByteVersions(p0.ABIMajor, p0.ABIMinor, p1.ABIMajor, p1.ABIMinor)
}

func validatePolicy(reportPolicy uint64, required abi.SnpPolicy) error {
	policy, err := abi.ParseSnpPolicy(reportPolicy)
	if err != nil {
		return fmt.Errorf("could not parse SNP policy: %v", err)
	}
	if comparePolicyVersions(required, policy) > 0 {
		return fmt.Errorf(
			"required policy ABI version (%d.%d) is greater than the report's ABI version (%d.%d)",
			required.ABIMajor, required.ABIMinor, policy.ABIMajor, policy.ABIMinor)
	}
	if !required.MigrateMA && policy.MigrateMA {
		return errors.New("found unauthorized migration agent capability")
	}
	if !required.Debug && policy.Debug {
		return errors.New("found unauthorized debug capability")
	}
	if !required.SMT && policy.SMT {
		return errors.New("found unauthorized symmetric multithreading (SMT) capability")
	}
	if required.SingleSocket && !policy.SingleSocket {
		return errors.New("required single socket restriction not present")
	}
	return nil
}

func validateByteField(option, field string, size int, given, required []byte) error {
	if len(required) == 0 {
		return nil
	}
	if len(required) != size {
		return fmt.Errorf("option %s must be nil or %d bytes", option, size)
	}
	if !bytes.Equal(required, given) {
		return fmt.Errorf("report field %s is %s. Expect %s",
			field, hex.EncodeToString(given), hex.EncodeToString(required))
	}
	return nil
}

func validateVerbatimFields(report *spb.Report, options *Options) error {
	return multierr.Combine(
		validateByteField("UserData", "REPORT_DATA", abi.ReportDataSize, report.GetReportData(), options.UserData),
		validateByteField("HostData", "HOST_DATA", abi.HostDataSize, report.GetHostData(), options.HostData),
		validateByteField("FamilyID", "FAMILY_ID", abi.FamilyIDSize, report.GetFamilyId(), options.FamilyID),
		validateByteField("ImageID", "IMAGE_ID", abi.ImageIDSize, report.GetImageId(), options.ImageID),
		validateByteField("ReportID", "REPORT_ID", abi.ReportIDSize, report.GetReportId(), options.ReportID),
		validateByteField("ReportIDMA", "REPORT_ID_MA", abi.ReportIDMASize, report.GetReportIdMa(), options.ReportIDMA),
		validateByteField("Measurement", "MEASUREMENT", abi.MeasurementSize, report.GetMeasurement(), options.Measurement),
		validateByteField("ChipID", "CHIP_ID", abi.ChipIDSize, report.GetChipId(), options.ChipID),
	)
}

func validateTcb(report *spb.Report, vcekTcb kds.TCBVersion, options *Options) error {
	// Any change to the TCB means that the VCEK certificate at an earlier TCB is no longer valid. The
	// host must make sure that the up-to-date certificate is provisioned and delivered alongside the
	// report that contains the new reported TCB value.
	// If the certificate's TCB is greater than the report's TCB, then the host has not provisioned
	// a certificate for the machine's actual state and should also not be accepted.
	if kds.TCBVersion(report.GetReportedTcb()) != vcekTcb {
		return fmt.Errorf("chip's VCEK TCB %x does not match the REPORTED_TCB %x",
			vcekTcb, report.GetReportedTcb())
	}
	if !options.PermitProvisionalFirmware {
		if kds.TCBVersion(report.GetCurrentTcb()) != vcekTcb {
			return fmt.Errorf("chip's VCEK TCB %x does not match the CURRENT_TCB %x",
				vcekTcb, report.GetReportedTcb())
		}
		if report.GetCurrentTcb() != report.GetCommittedTcb() {
			return fmt.Errorf("firmware's committed TCB %x does not match the current TCB %x",
				report.GetCommittedTcb(), report.GetCurrentTcb())
		}
	} else if kds.TCBVersion(report.GetCurrentTcb()) < vcekTcb {
		return fmt.Errorf("firmware's current TCB %x is less than the TCB the VCEK is certified for %x",
			report.GetCurrentTcb(), vcekTcb)
	}
	min, err := kds.ComposeTCBParts(options.MinimumTCB)
	if err != nil {
		return fmt.Errorf("option MinimumTCB error: %v", err)
	}
	if kds.TCBVersion(report.GetCurrentTcb()) < min {
		return fmt.Errorf("firmware's current TCB %x is less than required %x",
			report.GetCurrentTcb(), min)
	}
	minLaunch, err := kds.ComposeTCBParts(options.MinimumLaunchTCB)
	if err != nil {
		return fmt.Errorf("option MinimumLaunchTCB error: %v", err)
	}
	if kds.TCBVersion(report.GetLaunchTcb()) < minLaunch {
		return fmt.Errorf("the VM's launch TCB %x was less than required %x",
			report.GetCurrentTcb(), minLaunch)
	}
	// The launch TCB should be less than or equal to the reported TCB on the machine
	if report.GetLaunchTcb() > report.GetReportedTcb() {
		return fmt.Errorf("report field LAUNCH_TCB %x is greater than its REPORTED_TCB %x",
			report.GetLaunchTcb(), report.GetReportedTcb())
	}
	// Since the launch TCB should be less than or equal to the reported TCB, we should be safe and
	// also require that the committed TCB is also good enough.
	if report.GetLaunchTcb() > report.GetCommittedTcb() {
		return fmt.Errorf("report field LAUNCH_TCB %x is greater than its COMMITTED_TCB %x",
			report.GetLaunchTcb(), report.GetCommittedTcb())
	}
	// The committed TCB means that a firmware installation cannot backslide before that number.
	if report.GetCommittedTcb() > report.GetReportedTcb() {
		return fmt.Errorf("report field COMMITTED_TCB %x is greater than its REPORTED_TCB %x",
			report.GetLaunchTcb(), report.GetReportedTcb())
	}
	return nil
}

func validateVersion(report *spb.Report, options *Options) error {
	if options.MinimumBuild > uint8(report.GetCurrentBuild()) {
		return fmt.Errorf("firmware build number %d is less than the required minimum %d",
			report.GetCurrentBuild(), options.MinimumBuild)
	}
	if options.MinimumVersion > (uint16(report.GetCurrentMajor()<<8) | uint16(report.GetCurrentMinor())) {
		return fmt.Errorf("firmware API version (%d.%d) is less than the required minimum (%d.%d)",
			report.GetCurrentMajor(), report.GetCurrentMinor(),
			options.MinimumVersion>>8, options.MinimumVersion&0xff)
	}
	buildCmp := int(report.GetCommittedBuild()) - int(report.GetCurrentBuild())
	versionCmp := compareByteVersions(uint8(report.GetCommittedMajor()),
		uint8(report.GetCommittedMinor()),
		uint8(report.GetCurrentMajor()),
		uint8(report.GetCurrentMinor()))
	if !options.PermitProvisionalFirmware {
		if buildCmp != 0 {
			return fmt.Errorf("committed build number %d does not match the current build number %d",
				report.GetCommittedBuild(), report.GetCurrentBuild())
		}
		if versionCmp != 0 {
			return fmt.Errorf("committed API version (%d.%d) does not match the current API version (%d.%d)",
				report.GetCommittedMajor(), report.GetCommittedMinor(),
				report.GetCurrentMajor(), report.GetCurrentMinor())
		}
	} else {
		if buildCmp > 0 {
			return fmt.Errorf("committed build number %d is greater than the current build number %d",
				report.GetCommittedBuild(), report.GetCurrentBuild())
		}
		if versionCmp > 0 {
			return fmt.Errorf("committed API version (%d.%d) is greater than the current API version (%d.%d)",
				report.GetCommittedMajor(), report.GetCommittedMinor(),
				report.GetCurrentMinor(), report.GetCurrentMinor())
		}
	}
	return nil
}

func allZero(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

func validatePlatformInfo(platformInfo uint64, required *abi.SnpPlatformInfo) error {
	if required == nil {
		return nil
	}
	reportInfo, err := abi.ParseSnpPlatformInfo(platformInfo)
	if err != nil {
		return fmt.Errorf("could not parse SNP platform info %x: %v", platformInfo, err)
	}
	if reportInfo.TSMEEnabled && !required.TSMEEnabled {
		return errors.New("unauthorized platform feature TSME enabled")
	}
	if reportInfo.SMTEnabled && !required.SMTEnabled {
		return errors.New("unauthorized platform feature SMT enabled")
	}
	return nil
}

func addKeyHashesFromCerts(hashes [][]byte, certs []*x509.Certificate) [][]byte {
	for _, c := range certs {
		// Only add ECDSA P-384 keys
		switch key := c.PublicKey.(type) {
		case *ecdsa.PublicKey:
			pubkey, err := abi.EcdsaPublicKeyToBytes(key)
			if err != nil {
				// Wrong key type.
				continue
			}
			h := crypto.SHA384.New()
			h.Write(pubkey)
			hashes = append(hashes, h.Sum(nil))
		}
	}
	return hashes
}

func consolidateKeyHashes(options *Options) error {
	validateHashes := func(hashes [][]byte, size int) error {
		for _, hash := range hashes {
			if len(hash) != size {
				return fmt.Errorf("found hash with length %d. Expect %d", len(hash), size)
			}
		}
		return nil
	}

	if err := validateHashes(options.TrustedIDKeyHashes, abi.IDKeyDigestSize); err != nil {
		return fmt.Errorf("bad hash size in TrustedIDKeyHashes: %v", err)
	}

	if err := validateHashes(options.TrustedAuthorKeyHashes, abi.AuthorKeyDigestSize); err != nil {
		return fmt.Errorf("bad hash size in TrustedAuthorKeyHashes: %v", err)
	}

	options.TrustedIDKeyHashes = addKeyHashesFromCerts(options.TrustedIDKeyHashes,
		options.TrustedIDKeys)
	options.TrustedAuthorKeyHashes = addKeyHashesFromCerts(options.TrustedAuthorKeyHashes,
		options.TrustedAuthorKeys)
	return nil
}

func validateKeys(report *spb.Report, options *Options) error {
	if options.RequireAuthorKey && report.GetAuthorKeyEn() == 0 {
		return errors.New("author key missing when required")
	}

	if !options.RequireIDBlock {
		return nil
	}

	if err := consolidateKeyHashes(options); err != nil {
		return err
	}

	bytesContained := func(hashes [][]byte, digest []byte) bool {
		for _, hash := range hashes {
			if bytes.Equal(hash, digest) {
				return true
			}
		}
		return false
	}

	authorKeyTrusted := report.GetAuthorKeyEn() != 0 && bytesContained(options.TrustedAuthorKeyHashes,
		report.GetAuthorKeyDigest())

	if options.RequireAuthorKey && !authorKeyTrusted {
		return fmt.Errorf("report author key not trusted: %v",
			hex.EncodeToString(report.GetAuthorKeyDigest()))
	}

	// If the author key isn't required, check if the ID key itself is trusted.
	if !authorKeyTrusted && !bytesContained(options.TrustedIDKeyHashes, report.GetIdKeyDigest()) {
		return fmt.Errorf("report ID key not trusted: %s", hex.EncodeToString(report.GetIdKeyDigest()))
	}
	return nil
}

func validateSnpAttestation(report *spb.Report, vcek []byte, options *Options) error {
	vcekCert, err := x509.ParseCertificate(vcek)
	if err != nil {
		return fmt.Errorf("could not parse VCEK certificate: %v", err)
	}
	// Get the TCB values of the VCEK
	exts, err := kds.VcekCertificateExtensions(vcekCert)
	if err != nil {
		return fmt.Errorf("could not get VCEK certificate extensions: %v", err)
	}

	if err := multierr.Combine(
		validatePolicy(report.GetPolicy(), options.GuestPolicy),
		validateVerbatimFields(report, options),
		validateTcb(report, exts.TCBVersion, options),
		validateVersion(report, options),
		validatePlatformInfo(report.GetPlatformInfo(), options.PlatformInfo),
		validateKeys(report, options)); err != nil {
		return err
	}

	// MaskChipId might be 1 for the host, so only check if the the CHIP_ID is not all zeros.
	if !allZero(report.GetChipId()) && !bytes.Equal(report.GetChipId(), exts.HWID[:]) {
		return fmt.Errorf("report field CHIP_ID %s is not the same as the VCEK certificate's HWID %s",
			hex.EncodeToString(report.GetChipId()), hex.EncodeToString(exts.HWID[:]))
	}
	return nil
}

// SnpAttestation validates fields of the protobuf representation of an attestation report against
// expectations. Does not check the attestation certificates or signature.
func SnpAttestation(attestation *spb.Attestation, options *Options) error {
	return validateSnpAttestation(attestation.GetReport(),
		attestation.GetCertificateChain().GetVcekCert(), options)
}

// RawSnpAttestation validates fields of a raw attestation report against expectations. Does not
// check the attestation certificates or signature.
func RawSnpAttestation(report []byte, certTable []byte, options *Options) error {
	certs := new(abi.CertTable)
	if err := certs.Unmarshal(certTable); err != nil {
		return fmt.Errorf("could not unmarshal SNP certificate table: %v", err)
	}

	vcek, err := certs.GetByGUIDString(abi.VcekGUID)
	if err != nil {
		return fmt.Errorf("could not get VCEK certificate: %v", err)
	}

	proto, err := abi.ReportToProto(report)
	if err != nil {
		return fmt.Errorf("could not parse attestation report: %v", err)
	}
	return validateSnpAttestation(proto, vcek, options)
}
