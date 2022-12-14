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

// Package main implements a CLI tool for checking SEV-SNP attestation reports.
package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-sev-guest/abi"
	checkpb "github.com/google/go-sev-guest/proto/check"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/tools/lib/cmdline"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/logger"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// This is the default guest_policy value only if -policy is not provided. This prevents
	// the default value from overwriting the message.
	defaultGuestPolicy               = (1 << 17)
	defaultMinBuild                  = 0
	defaultMinVersion                = "0.0"
	defaultMinTcb                    = 0
	defaultMinLaunchTcb              = 0
	defaultProduct                   = "Milan"
	defaultCheckCrl                  = false
	defaultNetwork                   = true
	defaultRequireAuthorKey          = false
	defaultRequireIDBlock            = false
	defaultPermitProvisionalFirmware = false

	// Exit code 1 - tool usage error.
	exitTool = 1
	// Exit code 2 - the report signature did not verify.
	exitVerify = 2
	// Exit code 3 - problem downloading AMD certificates.
	exitCerts = 3
	// Exit code 4 - problem downloading the AMD CRL.
	exitCrl = 4
	// Exit code 5 - the report did not validate according to policy.
	exitPolicy = 5
)

var (
	infile = flag.String("in", "-", "Path to the attestation report to check. Stdin is \"-\".")
	inform = flag.String("inform", "bin", "The input format for the attestation report. One of \"bin\", \"proto\", \"textproto\".")

	configProto = flag.String("config", "",
		("A path to a serialized check.Config protobuf. Any individual field flags will" +
			"overwrite the message's associated field. Default unmarshalled as binary. Paths" +
			" ending in .textproto will be unmarshalled as prototext."))
	quiet = flag.Bool("quiet", false, "If true, writes nothing the stdout or stderr. Success is exit code 0, failure exit code 1.")

	reportdataS  = flag.String("report_data", "", "The expected REPORT_DATA field as a hex string. Must encode 64 bytes. Unchecked if unset.")
	reportdata   = cmdline.Bytes("-report_data", abi.ReportDataSize, reportdataS)
	hostdataS    = flag.String("host_data", "", "The expected HOST_DATA field as a hex string. Must encode 32 bytes. Unchecked if unset.")
	hostdata     = cmdline.Bytes("-host_data", abi.HostDataSize, hostdataS)
	familyidS    = flag.String("family_id", "", "The expected FAMILY_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.")
	familyid     = cmdline.Bytes("-family_id", abi.FamilyIDSize, familyidS)
	imageidS     = flag.String("image_id", "", "The expected IMAGE_ID field as a hex string. Must encode 16 bytes. Unchecked if unset.")
	imageid      = cmdline.Bytes("-image_id", abi.ImageIDSize, imageidS)
	reportidS    = flag.String("report_id", "", "The expected REPORT_ID field as a hex string. Must encode 32 bytes. Unchecked if unset.")
	reportid     = cmdline.Bytes("-report_id", abi.ReportIDSize, reportidS)
	reportidmaS  = flag.String("report_id_ma", "", "The expected REPORT_ID_MA field as a hex string. Must encode 32 bytes. Unchecked if unset.")
	reportidma   = cmdline.Bytes("-report_id_ma", abi.ReportIDMASize, reportidmaS)
	measurementS = flag.String("measurement", "", "The expected MEASUREMENT field as a hex string. Must encode 48 bytes. Unchecked if unset.")
	measurement  = cmdline.Bytes("-measurement", abi.MeasurementSize, measurementS)
	chipidS      = flag.String("chip_id", "", "The expected CHIP_ID field as a hex string. Must encode 64 bytes. Unchecked if unset.")
	chipid       = cmdline.Bytes("-chip_id", abi.ChipIDSize, chipidS)

	// Optional Uint64. We don't want 0 to override the policy message, so instead of parsing
	// as Uint64 up front, we keep the flag a string and parse later if given.
	mintcb       = flag.String("minimum_tcb", "", "The minimum acceptable value for CURRENT_TCB, COMMITTED_TCB, and REPORTED_TCB.")
	minlaunchtcb = flag.String("minimum_launch_tcb", "", "The minimum acceptable value for LAUNCH_TCB.")
	guestPolicy  = flag.String("guest_policy", "", "The most acceptable SnpPolicy component-wise in its 64-bit format.")
	// Optional Uint8. Similar to above.
	minbuild = flag.String("min_build", "", "The 8-bit minimum build number for AMD-SP firmware")
	// Optional Bool.
	checkcrl       = flag.String("check_crl", "", "Download and check the CRL for revoked certificates.")
	network        = flag.String("network", "", "If true, then permitted to download necessary files for verification.")
	retries        = flag.Int("retries", 10, "Number of times to retry a failed HTTP request.")
	retryRate      = flag.Duration("retry_rate", 2*time.Second, "Duration to wait between HTTP request retries.")
	requireauthor  = flag.String("require_author_key", "", "Require that AUTHOR_KEY_EN is 1.")
	requireidblock = flag.String("require_idblock", "", "Require that the VM was launch with an ID_BLOCK signed by a trusted id key or author key")
	provisional    = flag.String("provisional", "", "Permit provisional firmware (i.e., committed values may be less than current values).")

	// Optional nibble.
	vmpl         = flag.String("vmpl", "", "The expected VMPL value of the report [0-3].")
	platforminfo = flag.String("platform_info", "", "The maximum acceptable PLATFORM_INFO field bit-wise. May be empty or a 64-bit unsigned integer")
	minversion   = flag.String("min_version", "", "Minimum AMD-SP firmware API version (major.minor). Each number must be 8-bit non-negative.")

	trustedauthors      = flag.String("trusted_author_keys", "", "Colon-separated paths to x.509 certificates of trusted author keys")
	trustedauthorhashes = flag.String("trusted_author_key_hashes", "", "Comma-separated hex-encoded SHA-384 hash values of trusted author keys in AMD public key format")
	trustedidkeys       = flag.String("trusted_id_keys", "", "Colon-separated paths to x.509 certificates of trusted author keys")
	trustedidkeyhashes  = flag.String("trusted_id_key_hashes", "", "Comma-separated hex-encoded SHA-384 hash values of trusted identity keys in AMD public key format")

	product   = flag.String("product", "", "The AMD product name for the chip that generated the attestation report.")
	cabundles = flag.String("product_key_path", "",
		"Colon-separated paths to CA bundles for the AMD product. Must be in PEM format, ASK, then ARK certificates. If unset, uses embedded root certificates.")
	verbose = flag.Bool("v", false, "Enable verbose logging.")

	config = &checkpb.Config{
		RootOfTrust: &checkpb.RootOfTrust{},
		Policy:      &checkpb.Policy{},
	}
)

func parseAttestationBytes(b []byte) (*spb.Attestation, error) {
	// This format is the attestation report in AMD's specified ABI format, immediately
	// followed by the certificate table bytes.
	if len(b) < abi.ReportSize {
		return nil, fmt.Errorf("attestation contents too small (0x%x bytes). Want at least 0x%x bytes", len(b), abi.ReportSize)
	}
	reportBytes := b[0:abi.ReportSize]
	certBytes := b[abi.ReportSize:]

	report, err := abi.ReportToProto(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse attestation report: %v", err)
	}

	certs := new(abi.CertTable)
	if err := certs.Unmarshal(certBytes); err != nil {
		return nil, fmt.Errorf("could not parse certificate table: %v", err)
	}
	return &spb.Attestation{Report: report, CertificateChain: certs.Proto()}, nil
}

func parseAttestation(b []byte) (*spb.Attestation, error) {
	switch *inform {
	case "bin":
		return parseAttestationBytes(b)
	case "proto":
		result := &spb.Attestation{}
		if err := proto.Unmarshal(b, result); err != nil {
			return nil, fmt.Errorf("could not parse %q as proto: %v", *infile, err)
		}
	case "textproto":
		result := &spb.Attestation{}
		if err := prototext.Unmarshal(b, result); err != nil {
			return nil, fmt.Errorf("could not parse %q as textproto: %v", *infile, err)
		}
	default:
		return nil, fmt.Errorf("unknown value -inform=%s", *inform)
	}
	// This should be impossible.
	return nil, errors.New("internal error")
}

func getAttestation() (*spb.Attestation, error) {
	var in io.Reader
	var f *os.File
	if *infile == "-" {
		in = os.Stdin
	} else {
		file, err := os.Open(*infile)
		if err != nil {
			return nil, fmt.Errorf("could not open %q: %v", *infile, err)
		}
		f = file
		in = file
	}
	defer func() {
		if f != nil {
			f.Close()
		}
	}()

	contents, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("could not read %q: %v", *infile, err)
	}
	return parseAttestation(contents)
}

func parseHashes(s string) ([][]byte, error) {
	hexhashes := strings.Split(s, ",")
	if len(hexhashes) == 1 && hexhashes[0] == "" {
		return nil, nil
	}
	var result [][]byte
	for _, hexhash := range hexhashes {
		h, err := hex.DecodeString(strings.TrimSpace(hexhash))
		if err != nil {
			return nil, fmt.Errorf("could not parse hash value as hex-encoded string: %q", hexhash)
		}
		result = append(result, h)
	}
	return result, nil
}

func parsePaths(s string) ([]string, error) {
	paths := strings.Split(s, ":")
	if len(paths) == 1 && paths[0] == "" {
		return nil, nil
	}
	var result []string
	for _, path := range paths {
		p := strings.TrimSpace(path)
		stat, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("path error for %q: %v", p, err)
		}
		if stat.IsDir() {
			return nil, fmt.Errorf("path is not a file: %q", p)
		}
		result = append(result, p)
	}
	return result, nil
}

func getCertBytes(s string) (result [][]byte, err error) {
	paths, err := parsePaths(s)
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("could not read file %q: %v", path, err)
		}
		result = append(result, contents)

	}
	return result, nil
}

func parseUint(p string, bits int) (uint64, error) {
	base := 10
	prepped := p
	if strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X") {
		base = 16
		prepped = prepped[2:]
	} else if strings.HasPrefix(p, "0o") || strings.HasPrefix(p, "0O") {
		base = 8
		prepped = prepped[2:]
	} else if strings.HasPrefix(p, "0b") || strings.HasPrefix(p, "0B") {
		base = 2
		prepped = prepped[2:]
	}
	info64, err := strconv.ParseUint(prepped, base, bits)
	if err != nil {
		return 0, fmt.Errorf("%q must be empty or a %d-bit number: %v", p, bits, err)
	}
	return info64, nil
}

func dieWith(err error, exitCode int) {
	if !*quiet {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
	os.Exit(exitCode)
}

func die(err error) {
	dieWith(err, exitTool)
}

func parseConfig(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("could not open %q: %v", path, err)
	}
	defer f.Close()

	contents, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("could not read %q: %v", path, err)
	}
	if strings.HasSuffix(path, ".textproto") {
		err = prototext.Unmarshal(contents, config)
	} else {
		err = proto.Unmarshal(contents, config)
	}
	if err != nil {
		return fmt.Errorf("could not deserialize %q: %v", path, err)
	}
	return nil
}

func override() bool {
	return *configProto != ""
}

func setBool(value *bool, name, flag string, defaultValue bool) error {
	if flag == "" {
		if !override() {
			*value = defaultValue
		}
	} else if flag == "true" {
		*value = true
	} else if flag == "false" {
		*value = false
	} else {
		return fmt.Errorf("flag -%s=%s invalid. Must be one of unset, \"true\", or \"false\"",
			name, flag)
	}
	return nil
}

func setUint(value *uint64, bits int, name, flag string, defaultValue uint64) error {
	if flag == "" {
		if !override() {
			*value = defaultValue
		}
	} else {
		u, err := parseUint(flag, bits)
		if err != nil {
			return fmt.Errorf("invalid -%s=%s: %v", name, flag, err)
		}
		*value = u
	}
	return nil
}

func setUint64(value *uint64, name, flag string, defaultValue uint64) error {
	return setUint(value, 64, name, flag, defaultValue)
}

func setUint32(value *uint32, name, flag string, defaultValue uint64) error {
	v := uint64(*value)
	if err := setUint(&v, 32, name, flag, defaultValue); err != nil {
		return err
	}
	*value = uint32(v)
	return nil
}

func getUIntValue(bits int, name, flag string) (*uint64, error) {
	if flag == "" {
		return nil, nil
	}
	var u uint64
	if err := setUint(&u, bits, name, flag, 0); err != nil {
		return nil, err
	}
	return &u, nil
}

func setUInt64Value(value **wrapperspb.UInt64Value, name, flag string) error {
	v, err := getUIntValue(64, name, flag)
	if v != nil {
		*value = &wrapperspb.UInt64Value{Value: *v}
	}
	return err
}

func setUInt32Value(value **wrapperspb.UInt32Value, name, flag string) error {
	v, err := getUIntValue(32, name, flag)
	if v != nil {
		*value = &wrapperspb.UInt32Value{Value: uint32(*v)}
	}
	return err
}

func setString(dest *string, name, flag string, defaultValue string) {
	if flag == "" {
		if !override() {
			*dest = defaultValue
		}
	} else {
		*dest = flag
	}
}

func populateRootOfTrust() error {
	rot := config.RootOfTrust
	if err := setBool(&rot.CheckCrl, "check_crl", *checkcrl, defaultCheckCrl); err != nil {
		return err
	}

	// The disallow_network field is opposite the network flag since we can't
	// specify default values in proto3.
	networkValue := !rot.DisallowNetwork
	if err := setBool(&networkValue, "network", *network, defaultNetwork); err != nil {
		return err
	}
	rot.DisallowNetwork = !networkValue

	setString(&rot.Product, "product", *product, defaultProduct)

	paths, err := parsePaths(*cabundles)
	if err != nil {
		return err
	}
	if len(paths) > 0 {
		rot.CabundlePaths = paths
	}

	return nil
}

// Populate fields of the config proto from flags if they override.
func populateConfig() error {
	policy := config.Policy

	setHashes := func(dest *[][]byte, name, flag string) error {
		if flag != "" {
			hashes, err := parseHashes(flag)
			if err != nil {
				return err
			}
			*dest = hashes
		}
		return nil
	}
	setCertBytes := func(dest *[][]byte, name, flag string) error {
		if flag != "" {
			bytes, err := getCertBytes(flag)
			if err != nil {
				return err
			}
			*dest = bytes
		}
		return nil
	}

	setString(&policy.MinimumVersion, "min_version", *minversion, defaultMinVersion)

	setNonNil := func(dest *[]byte, value []byte) {
		if value != nil {
			*dest = value
		}
	}
	setNonNil(&policy.FamilyId, *familyid)
	setNonNil(&policy.ImageId, *imageid)
	setNonNil(&policy.ReportData, *reportdata)
	setNonNil(&policy.Measurement, *measurement)
	setNonNil(&policy.HostData, *hostdata)
	setNonNil(&policy.ReportId, *reportid)
	setNonNil(&policy.ReportIdMa, *reportidma)
	setNonNil(&policy.ChipId, *chipid)

	return multierr.Combine(
		setUint64(&policy.Policy, "guest_policy", *guestPolicy, defaultGuestPolicy),
		setUint64(&policy.MinimumTcb, "minimum_tcb",
			*mintcb, defaultMinTcb),
		setUint64(&policy.MinimumLaunchTcb, "minimum_launch_tcb",
			*minlaunchtcb, defaultMinLaunchTcb),
		setUint32(&policy.MinimumBuild, "min_build", *minbuild, defaultMinBuild),
		setUInt32Value(&policy.Vmpl, "vmpl", *vmpl),
		setUInt64Value(&policy.PlatformInfo, "platform_info", *platforminfo),
		setBool(&policy.RequireAuthorKey, "require_author_key",
			*requireauthor, defaultRequireAuthorKey),
		setBool(&policy.RequireIdBlock, "require_idblock",
			*requireidblock, defaultRequireIDBlock),
		setBool(&policy.PermitProvisionalFirmware, "permit_provisional_firmware",
			*provisional, defaultPermitProvisionalFirmware),
		setHashes(&policy.TrustedAuthorKeyHashes, "trusted_author_key_hashes",
			*trustedauthorhashes),
		setHashes(&policy.TrustedIdKeyHashes, "trusted_id_key_hashes",
			*trustedidkeyhashes),
		setCertBytes(&policy.TrustedAuthorKeys, "trusted_author_keys",
			*trustedauthors),
		setCertBytes(&policy.TrustedIdKeys, "trusted_id_keys",
			*trustedidkeys))
}

func main() {
	logger.Init("", *verbose, false, os.Stderr)
	flag.Parse()
	cmdline.Parse("auto")

	if err := parseConfig(*configProto); err != nil {
		die(err)
	}

	if err := multierr.Combine(populateRootOfTrust(),
		populateConfig()); err != nil {
		die(err)
	}

	if config.RootOfTrust.CheckCrl && config.RootOfTrust.DisallowNetwork {
		die(errors.New("cannot specify both -check_crl=true and -network=false"))
	}

	attestation, err := getAttestation()
	if err != nil {
		die(err)
	}

	sopts, err := verify.RootOfTrustToOptions(config.RootOfTrust)
	if err != nil {
		die(err)
	}
	sopts.Getter = &trust.RetryHTTPSGetter{
		Retries:   *retries,
		RetryRate: *retryRate,
		Getter:    &trust.SimpleHTTPSGetter{},
	}
	if err := verify.SnpAttestation(attestation, sopts); err != nil {
		// Make the exit code more helpful when there are network errors
		// that affected the result.
		exitCode := exitVerify
		clarify := func(err error) bool {
			if err == nil {
				return false
			}
			if errors.As(err, &verify.AttestationRecreationErr{}) {
				exitCode = exitCerts
				return true
			} else if errors.As(err, &verify.CRLUnavailableErr{}) {
				exitCode = exitCrl
				return true
			}
			return false
		}
		if !clarify(err) {
			clarify(errors.Unwrap(err))
		}
		dieWith(fmt.Errorf("could not verify attestation signature: %v", err), exitCode)
	}

	opts, err := validate.PolicyToOptions(config.Policy)
	if err != nil {
		die(err)
	}
	if err := validate.SnpAttestation(attestation, opts); err != nil {
		dieWith(fmt.Errorf("error validating attestation: %v", err), exitPolicy)
	}
}
