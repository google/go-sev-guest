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
	"strconv"
	"strings"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	cpb "github.com/google/go-sev-guest/proto/check"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/logger"
	"go.uber.org/multierr"
)

// Options represents verification options for an SEV-SNP attestation report.
type Options struct {
	// GuestPolicy is the maximum of acceptable guest policies.
	GuestPolicy abi.SnpPolicy
	// MinimumGuestSvn is the minimum guest security version number.
	MinimumGuestSvn uint32
	// ReportData is the expected REPORT_DATA field. Must be nil or 64 bytes long. Not checked if nil.
	ReportData []byte
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
	// Implies RequireIDBlock is true.
	RequireAuthorKey bool
	// VMPL is the expected VMPL value, 0-3. Unchecked if nil.
	VMPL *int
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
	// SEV-SNP API format. Not required if TrustedIDKeys is provided.
	TrustedIDKeyHashes [][]byte
	// CertTableOptions allows the caller to specify extra validation conditions on non-standard
	// UUID entries in the certificate table returned by GetExtendedReport.
	CertTableOptions map[string]*CertEntryOption
}

// CertEntryKind represents a simple policy kind for cert table entries. If a UUID string key is
// present in the CertTableOptions, then the Validate function must not error when given both the
// attestation and the blob associated with the UUID. If a UUID is missing, then the kind matters:
// should missing entries be considered an error, or an allowed omission?
type CertEntryKind int

const (
	// CertEntryAllowMissing will only error if the key is present in the certificate table and
	// Validate returns an error.
	CertEntryAllowMissing = iota
	// CertEntryRequire will cause an error if the certificate table does not include the key.
	CertEntryRequire
)

// CertEntryOption represents a pluggable validation option for CertTable entries. This allows for
// golden measurements (RIMs and the like) to be injected into the guest about various provided
// infrastructure.
type CertEntryOption struct {
	Kind     CertEntryKind
	Validate func(attestation *spb.Attestation, blob []byte) error
}

func lengthCheck(name string, length int, value []byte) error {
	if value != nil && len(value) != length {
		return fmt.Errorf("option %q length is %d. Want %d", name, len(value), length)
	}
	return nil
}

func checkOptionsLengths(opts *Options) error {
	return multierr.Combine(
		lengthCheck("family_id", abi.FamilyIDSize, opts.FamilyID),
		lengthCheck("image_id", abi.ImageIDSize, opts.ImageID),
		lengthCheck("report_data", abi.ReportDataSize, opts.ReportData),
		lengthCheck("measurement", abi.MeasurementSize, opts.Measurement),
		lengthCheck("host_data", abi.HostDataSize, opts.HostData),
		lengthCheck("report_id", abi.ReportIDSize, opts.ReportID),
		lengthCheck("report_id_ma", abi.ReportIDMASize, opts.ReportIDMA),
		lengthCheck("chip_id", abi.ChipIDSize, opts.ChipID))
}

// Converts "maj.min" to its uint16 representation or errors.
func parseVersion(v string) (uint16, error) {
	parseU8 := func(name, s string) (uint8, error) {
		n, err := strconv.Atoi(s)
		if err != nil {
			return 0, fmt.Errorf("error parsing %s number: %v", name, err)
		}
		if n < 0 || n > 255 {
			return 0, fmt.Errorf("%s is %d, which is not a uint8", name, n)
		}
		return uint8(n), nil
	}
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return 0, fmt.Errorf("expect major.minor, got %q", v)
	}
	maj, err := parseU8("major", parts[0])
	if err != nil {
		return 0, err
	}
	min, err := parseU8("minor", parts[1])
	if err != nil {
		return 0, err
	}
	return (uint16(maj) << 8) | uint16(min), nil
}

// PolicyToOptions returns an Options object that is represented by a Policy message.
func PolicyToOptions(policy *cpb.Policy) (*Options, error) {
	guestPolicy, err := abi.ParseSnpPolicy(policy.GetPolicy())
	if err != nil {
		return nil, err
	}
	var platformInfo *abi.SnpPlatformInfo
	if policy.GetPlatformInfo() != nil {
		platformInfoValue, err := abi.ParseSnpPlatformInfo(policy.GetPlatformInfo().GetValue())
		if err != nil {
			return nil, err
		}
		platformInfo = &platformInfoValue
	}
	var vmpl *int
	if policy.GetVmpl() != nil {
		vmplUint32 := policy.GetVmpl().GetValue()
		if vmplUint32 > 3 {
			return nil, fmt.Errorf("vmpl is %d. Expect 0-3", vmplUint32)
		}
		vmplInt := int(vmplUint32)
		vmpl = &vmplInt
	}
	if policy.GetMinimumBuild() > 255 {
		return nil, fmt.Errorf("minimum_build is %d. Expect 0-255", policy.GetMinimumBuild())
	}
	minVersion := uint16(0) // Allow an empty minimum version to mean "0.0"
	if policy.GetMinimumVersion() != "" {
		minVersion, err = parseVersion(policy.GetMinimumVersion())
		if err != nil {
			return nil, fmt.Errorf("invalid minimum_version, %q: %v", policy.GetMinimumVersion(), err)
		}
	}
	for _, authorKeyHash := range policy.GetTrustedAuthorKeyHashes() {
		if err := lengthCheck("trusted_author_key_hashes", abi.AuthorKeyDigestSize, authorKeyHash); err != nil {
			return nil, err
		}
	}
	for _, idKeyHash := range policy.GetTrustedIdKeyHashes() {
		if err := lengthCheck("trusted_id_key_hashes", abi.IDKeyDigestSize, idKeyHash); err != nil {
			return nil, err
		}
	}
	parseCerts := func(name string, certs [][]byte) (result []*x509.Certificate, _ error) {
		for _, certBytes := range certs {
			cert, err := x509.ParseCertificate(certBytes)
			if err != nil {
				return nil, fmt.Errorf("could not parse %s key certificate: %v", name, err)
			}
			result = append(result, cert)
		}
		return result, nil
	}
	authorKeys, err := parseCerts("author", policy.GetTrustedAuthorKeys())
	if err != nil {
		return nil, err
	}
	idKeys, err := parseCerts("id", policy.GetTrustedIdKeys())
	if err != nil {
		return nil, err
	}
	opts := &Options{
		MinimumGuestSvn:           policy.GetMinimumGuestSvn(),
		GuestPolicy:               guestPolicy,
		FamilyID:                  policy.GetFamilyId(),
		ImageID:                   policy.GetImageId(),
		ReportID:                  policy.GetReportId(),
		ReportIDMA:                policy.GetReportIdMa(),
		ChipID:                    policy.GetChipId(),
		Measurement:               policy.GetMeasurement(),
		HostData:                  policy.GetHostData(),
		ReportData:                policy.GetReportData(),
		PlatformInfo:              platformInfo,
		MinimumTCB:                kds.DecomposeTCBVersion(kds.TCBVersion(policy.GetMinimumTcb())),
		MinimumLaunchTCB:          kds.DecomposeTCBVersion(kds.TCBVersion(policy.GetMinimumLaunchTcb())),
		MinimumBuild:              uint8(policy.GetMinimumBuild()),
		MinimumVersion:            minVersion,
		RequireAuthorKey:          policy.GetRequireAuthorKey(),
		RequireIDBlock:            policy.GetRequireIdBlock(),
		PermitProvisionalFirmware: policy.GetPermitProvisionalFirmware(),
		TrustedAuthorKeys:         authorKeys,
		TrustedAuthorKeyHashes:    policy.GetTrustedAuthorKeyHashes(),
		TrustedIDKeys:             idKeys,
		TrustedIDKeyHashes:        policy.GetTrustedIdKeyHashes(),
		VMPL:                      vmpl,
	}
	if err := checkOptionsLengths(opts); err != nil {
		return nil, err
	}
	return opts, nil
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
	if !required.CXLAllowed && policy.CXLAllowed {
		return errors.New("found unauthorized CXL capability")
	}
	if required.MemAES256XTS && !policy.MemAES256XTS {
		return errors.New("found unauthorized memory encryption mode")
	}
	if required.RAPLDis && !policy.RAPLDis {
		return errors.New("found unauthorized RAPL capability")
	}
	if required.CipherTextHidingDRAM && !policy.CipherTextHidingDRAM {
		return errors.New("chiphertext hiding in DRAM isn't enforced")
	}
	if required.PageSwapDisable && !policy.PageSwapDisable {
		return errors.New("found unauthorized page swap capability")
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
		validateByteField("ReportData", "REPORT_DATA", abi.ReportDataSize, report.GetReportData(), options.ReportData),
		validateByteField("HostData", "HOST_DATA", abi.HostDataSize, report.GetHostData(), options.HostData),
		validateByteField("FamilyID", "FAMILY_ID", abi.FamilyIDSize, report.GetFamilyId(), options.FamilyID),
		validateByteField("ImageID", "IMAGE_ID", abi.ImageIDSize, report.GetImageId(), options.ImageID),
		validateByteField("ReportID", "REPORT_ID", abi.ReportIDSize, report.GetReportId(), options.ReportID),
		validateByteField("ReportIDMA", "REPORT_ID_MA", abi.ReportIDMASize, report.GetReportIdMa(), options.ReportIDMA),
		validateByteField("Measurement", "MEASUREMENT", abi.MeasurementSize, report.GetMeasurement(), options.Measurement),
		validateByteField("ChipID", "CHIP_ID", abi.ChipIDSize, report.GetChipId(), options.ChipID),
	)
}

// partDescription combines a TCB decomposition with a short description. It enables concise
// comparisons with high quality error messages.
type partDescription struct {
	parts kds.TCBParts
	desc  string
}

// reportTcbDescriptions is a collection of all TCB kinds that are within or about a report itself.
type reportTcbDescriptions struct {
	// The host operator's reported TCB, which may not be higher than the current TCB.
	// May be lower than the current TCB, e.g., if the host wants to ensure a lower bound
	// TCB across multiple machines, and this one is just ahead of the curve with a newer version.
	reported partDescription
	// The firmware version of the VM host machine at the time the report was constructed.
	current partDescription
	// When a firmware version is installed and also ensured to not get overwritten with a
	// firmware with a lower TCB than this.
	committed partDescription
	// The CURRENT_TCB version of the machine at the time of launch.
	launch partDescription
	// The TCB that the VCEK certificate is certified for. Embedded as x509v3 extensions from
	// AMD's Key Distribution Service (KDS).
	cert partDescription
}

func getReportTcbs(report *spb.Report, certTcb kds.TCBVersion) *reportTcbDescriptions {
	return &reportTcbDescriptions{
		reported: partDescription{
			parts: kds.DecomposeTCBVersion(kds.TCBVersion(report.GetReportedTcb())),
			desc:  "report's REPORTED_TCB",
		},
		current: partDescription{
			parts: kds.DecomposeTCBVersion(kds.TCBVersion(report.GetCurrentTcb())),
			desc:  "report's CURRENT_TCB",
		},
		committed: partDescription{
			parts: kds.DecomposeTCBVersion(kds.TCBVersion(report.GetCommittedTcb())),
			desc:  "report's COMMITTED_TCB",
		},
		launch: partDescription{
			parts: kds.DecomposeTCBVersion(kds.TCBVersion(report.GetLaunchTcb())),
			desc:  "report's LAUNCH_TCB",
		},
		cert: partDescription{
			parts: kds.DecomposeTCBVersion(certTcb),
			desc:  "TCB of the V[CL]EK certificate",
		},
	}
}

// policyTcbDescriptions is a collection of all TCB kinds that the validation policy specifies.
type policyTcbDescriptions struct {
	// The validator policy's specified minimum TCB for both reported
	minimum partDescription
	// The validator policy's sp
	minLaunch partDescription
}

func getPolicyTcbs(options *Options) *policyTcbDescriptions {
	return &policyTcbDescriptions{
		minimum: partDescription{
			parts: options.MinimumTCB,
			desc:  "policy minimum TCB",
		},
		minLaunch: partDescription{
			parts: options.MinimumLaunchTCB,
			desc:  "policy minimum launch TCB",
		},
	}
}

// tcbNeError return an error if the two TCBs are not equal
func tcbNeError(left, right partDescription) error {
	ltcb, _ := kds.ComposeTCBParts(left.parts)
	rtcb, _ := kds.ComposeTCBParts(right.parts)
	if ltcb == rtcb {
		return nil
	}
	return fmt.Errorf("the %s 0x%x does not match the %s 0x%x", left.desc, ltcb, right.desc, rtcb)
}

// tcbGtError returns an error if wantLower is greater than (in part) wantHigher. It enforces
// the property wantLower <= wantHigher.
func tcbGtError(wantLower, wantHigher partDescription) error {
	if kds.TCBPartsLE(wantLower.parts, wantHigher.parts) {
		return nil
	}
	return fmt.Errorf("the %s %+v is lower than the %s %+v in at least one component",
		wantHigher.desc, wantHigher.parts, wantLower.desc, wantLower.parts)
}

// validateTcb returns an error if the TCB values present in the report and V[CL]EK certificate do not
// obey expected relationships with respect to the given validation policy, or with respect to
// internal consistency checks.
func validateTcb(report *spb.Report, certTcb kds.TCBVersion, options *Options) error {
	reportTcbs := getReportTcbs(report, certTcb)
	policyTcbs := getPolicyTcbs(options)

	var provisionalErr error
	if options.PermitProvisionalFirmware {
		provisionalErr = tcbGtError(reportTcbs.committed, reportTcbs.current)
	} else {
		provisionalErr = tcbNeError(reportTcbs.committed, reportTcbs.current)
	}

	return multierr.Combine(provisionalErr,
		tcbGtError(policyTcbs.minLaunch, reportTcbs.launch),
		// Any change to the TCB means that the V[CL]EK certificate at an earlier TCB is no
		// longer valid. The host must make sure that the up-to-date certificate is provisioned
		// and delivered alongside the report that contains the new reported TCB value.
		// If the certificate's TCB is greater than the report's TCB, then the host has not
		// provisioned a certificate for the machine's actual state and should also not be
		// accepted.
		tcbNeError(reportTcbs.reported, reportTcbs.cert),
		tcbGtError(reportTcbs.cert, reportTcbs.current),
		tcbGtError(policyTcbs.minimum, reportTcbs.reported))
	// Note:
	//   * by transitivity of <=, if we're here, then minimum <= current
	//   * since cert == reported, reported <= current

	// Checks that could make sense but don't:
	//
	//  * tcbGtError(reportTcbs.launch, reportTcbs.reported)
	//    Since LAUNCH_TCB on a single node is CURRENT_TCB, we expect the opposite ordering.
	//    One only needs to pay attention to LAUNCH_TCB if permitting provisional firmware
	//    but not permitting backsliding the firmware when the VM launched at a higher TCB.
	//    We have no strong recommendations on how such a policy should be enforced.
	//
	// * tcbGtError(reportTcbs.launch, reportTcbs.committed),
	//    This seems to be a safe assertion, but the VM Absorb guest message from a migration
	//    agent would allow violation of the ordering. The launch tcb may come from node 1,
	//    where current_tcb and committed_tcb are both higher than node 2's current and
	//    committed tcbs, but the two share the same reported tcb due to a fleetwide commitment
	//    to administer all machines to have a least common TCB in the reported tcb field.
	//
	// * tcbGt(reportTcbs.committed, reportTcbs.reported),
	//    The committed TCB <= reported TCB only if you want to have a high standard for
	//    what TCB you report on the machine, but it doesn't match up with previous comments
	//    that we think it reasonable for the reported TCB to be the lowest of the bunch.
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
	if reportInfo.SMTEnabled && !required.SMTEnabled {
		return errors.New("unauthorized platform feature SMT enabled")
	}
	if reportInfo.TSMEEnabled && !required.TSMEEnabled {
		return errors.New("unauthorized platform feature TSME enabled")
	}
	if !reportInfo.ECCEnabled && required.ECCEnabled {
		return errors.New("required platform feature ECC not enabled")
	}
	if !reportInfo.RAPLDisabled && required.RAPLDisabled {
		return errors.New("unauthorized platform feature RAPL enabled")
	}
	if !reportInfo.CiphertextHidingDRAMEnabled && required.CiphertextHidingDRAMEnabled {
		return errors.New("required ciphertext hiding in DRAM not enforced")
	}
	if !reportInfo.AliasCheckComplete && required.AliasCheckComplete {
		return errors.New("required memory alias check hasn't been completed")
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
	info, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return err
	}
	if options.RequireAuthorKey && !info.AuthorKeyEn {
		return errors.New("author key missing when required")
	}

	// RequireAuthorKey implies RequireIDBlock.
	idblock := options.RequireAuthorKey || options.RequireIDBlock
	if !idblock {
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

	authorKeyTrusted := info.AuthorKeyEn && bytesContained(options.TrustedAuthorKeyHashes,
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

func validateKeyKind(report *spb.Attestation) (*x509.Certificate, error) {
	if report == nil {
		return nil, fmt.Errorf("attestation cannot be nil")
	}
	if report.GetReport() == nil {
		return nil, fmt.Errorf("attestation report cannot be nil")
	}
	if report.GetCertificateChain() == nil {
		return nil, fmt.Errorf("attestation certificate chain cannot be nil")
	}

	info, err := abi.ParseSignerInfo(report.GetReport().GetSignerInfo())
	if err != nil {
		return nil, err
	}

	switch info.SigningKey {
	case abi.VcekReportSigner:
		if len(report.GetCertificateChain().VcekCert) != 0 {
			return x509.ParseCertificate(report.GetCertificateChain().VcekCert)
		}
	case abi.VlekReportSigner:
		if len(report.GetCertificateChain().VlekCert) != 0 {
			return x509.ParseCertificate(report.GetCertificateChain().VlekCert)
		}
	case abi.NoneReportSigner:
		return nil, nil
	}
	return nil, fmt.Errorf("unsupported key kind %v", info.SigningKey)
}

func certTableOptions(attestation *spb.Attestation, options map[string]*CertEntryOption) error {
	extras := attestation.GetCertificateChain().GetExtras()
	for key, opt := range options {
		if opt.Validate == nil {
			return fmt.Errorf("invalid argument: option for %s missing Validate function", key)
		}
		if err := opt.Validate(attestation, extras[key]); err != nil {
			if opt.Kind == CertEntryRequire {
				return err
			}
			logger.Warningf("Missing or invalid cert entry for %s", key)
		}
	}
	return nil
}

// SnpAttestation validates fields of the protobuf representation of an attestation report against
// expectations. Does not check the attestation certificates or signature.
func SnpAttestation(attestation *spb.Attestation, options *Options) error {
	endorsementKeyCert, err := validateKeyKind(attestation)
	if err != nil {
		return err
	}
	report := attestation.GetReport()
	info, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return err
	}
	// Get the TCB values of the V[CL]EK
	exts, err := kds.CertificateExtensions(endorsementKeyCert, info.SigningKey)
	if err != nil {
		return fmt.Errorf("could not get %v certificate extensions: %v", info.SigningKey, err)
	}

	if report.GetGuestSvn() < options.MinimumGuestSvn {
		return fmt.Errorf("report's GUEST_SVN %d is less than the required minimum %d",
			report.GetGuestSvn(), options.MinimumGuestSvn)
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

	if options.VMPL != nil && uint32(*options.VMPL) != report.GetVmpl() {
		return fmt.Errorf("report VMPL %d is not %d", report.GetVmpl(), *options.VMPL)
	}

	// MaskChipId might be 1 for the host, so only check if the the CHIP_ID is not all zeros.
	if info.SigningKey == abi.VcekReportSigner && !allZero(report.GetChipId()) && !bytes.Equal(report.GetChipId(), exts.HWID[:]) {
		return fmt.Errorf("report field CHIP_ID %s is not the same as the VCEK certificate's HWID %s",
			hex.EncodeToString(report.GetChipId()), hex.EncodeToString(exts.HWID[:]))
	}

	return certTableOptions(attestation, options.CertTableOptions)
}

// RawSnpAttestation validates fields of a raw attestation report against expectations. Does not
// check the attestation certificates or signature.
func RawSnpAttestation(report []byte, certTable []byte, options *Options) error {
	certs := new(abi.CertTable)
	if err := certs.Unmarshal(certTable); err != nil {
		return fmt.Errorf("could not unmarshal SNP certificate table: %v", err)
	}

	proto, err := abi.ReportToProto(report)
	if err != nil {
		return fmt.Errorf("could not parse attestation report: %v", err)
	}
	return SnpAttestation(&spb.Attestation{Report: proto, CertificateChain: certs.Proto()},
		options)
}
