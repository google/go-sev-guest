package main

import (
	"bytes"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	checkpb "github.com/google/go-sev-guest/proto/check"
	kpb "github.com/google/go-sev-guest/proto/fakekds"
	fakesev "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/testdata"
	"github.com/google/logger"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Returns true if the test should be skipped for the protobuf case since the field
// can't be set to the expected value.
type setterFn func(p *checkpb.Policy, value string, t *testing.T) bool

// Represents a test case that will set a flag or config field to a good or bad value.
// We use this data to check that
//
//   - flags alone lead to expected check success or failure,
//   - a config alone leads to expected check success or failure,
//   - a config set to a bad value and a flag set to a good value leads
//     to an expected override and success.
//   - a config set to a good value and a flag set to a bad value leads
//     to an expected override and failure.
type testCase struct {
	flag   string
	good   string
	bad    []string
	setter setterFn
}

var goodPolicy = abi.SnpPolicyToBytes(abi.SnpPolicy{
	Debug: true,
	SMT:   true,
})

const (
	goodChipID = "3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d"
	goodTcb    = 4901323769462652930
)

var check string
var kdsdatabase string

func TestMain(m *testing.M) {
	if output, err := exec.Command("go", "build", ".").CombinedOutput(); err != nil {
		die(fmt.Errorf("could not build check tool: %v, %s", err, output))
	}
	check = "./check"

	// Create a kdsdatabase using testdata for the attestation-producer's VCEK:
	dbfile, err := os.CreateTemp(".", "kdsdatabase.bin")
	if err != nil {
		die(err)
	}
	chipid, _ := hex.DecodeString(goodChipID)
	db := &kpb.Certificates{ChipCerts: []*kpb.Certificates_ChipTCBCerts{
		{
			ChipId: chipid,
			TcbCerts: map[uint64][]byte{
				goodTcb: testdata.VcekBytes,
			},
		},
	}}
	dbbytes, err := proto.Marshal(db)
	if err != nil {
		die(err)
	}
	n, err := dbfile.Write(dbbytes)
	if err != nil {
		die(err)
	}
	if n != len(dbbytes) {
		die(fmt.Errorf("kdsdatabase not fully written"))
	}
	kdsdatabase = dbfile.Name()
	logger.Init("CheckTestLog", false, false, os.Stderr)
	defer os.Remove(dbfile.Name())
	os.Exit(m.Run())
}

// Work around the fact that Golang ellipsis unpacking doesn't also pack up
// extra singular arguments prior to the unpack.
// This means given
//
//	func f(...T)
//	var a, b T
//	var c []T
//
// then
//
//	f(a, b, c...) doesn't typecheck.
//
// We'd expect the arguments to pack like f([]T{a, b, c...}...) but nope. The array
// expression []T{a, b, c...} is also invalid.
func withBaseArgs(config string, args ...string) []string {
	base := []string{
		"-in", "../../verify/testdata/attestation.bin",
		"-kdsdatabase", kdsdatabase,
	}
	if config != "" {
		base = append(base, fmt.Sprintf("-config=%s", config))
	} else {
		base = append(base, fmt.Sprintf("-guest_policy=%d", goodPolicy))
	}

	result := make([]string, len(args)+len(base))
	copy(result, base)
	copy(result[len(base):], args)
	return result
}

func setField(p *checkpb.Policy, name string, value any) {
	r := p.ProtoReflect()
	ty := r.Descriptor()
	r.Set(ty.Fields().ByName(protoreflect.Name(name)), protoreflect.ValueOf(value))
}

func bytesSetter(name string) setterFn {
	return func(p *checkpb.Policy, value string, t *testing.T) bool {
		v, err := hex.DecodeString(value)
		if err != nil {
			return true
		}
		setField(p, name, v)
		return false
	}
}

func stringSetter(name string) setterFn {
	return func(p *checkpb.Policy, value string, t *testing.T) bool {
		setField(p, name, value)
		return false
	}
}

func boolSetter(name string) setterFn {
	return func(p *checkpb.Policy, value string, t *testing.T) bool {
		switch value {
		case "true":
			setField(p, name, true)
		case "false":
			setField(p, name, false)
		default:
			return true
		}
		return false

	}
}

func uint64setter(name string) setterFn {
	return func(p *checkpb.Policy, value string, t *testing.T) bool {
		u, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return true
		}
		setField(p, name, u)
		return false
	}
}

func uint32setter(name string) setterFn {
	return func(p *checkpb.Policy, value string, t *testing.T) bool {
		u, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return true
		}
		setField(p, name, uint32(u))
		return false
	}
}

func uint32valueSetter(name string) setterFn {
	return func(p *checkpb.Policy, value string, t *testing.T) bool {
		u, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return true
		}
		setField(p, name, wrapperspb.UInt32(uint32(u)).ProtoReflect())
		return false
	}
}

func uint64valueSetter(name string) setterFn {
	return func(p *checkpb.Policy, value string, t *testing.T) bool {
		u, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return true
		}
		setField(p, name, wrapperspb.UInt64(u).ProtoReflect())
		return false
	}
}

func testCases() []testCase {
	return []testCase{
		{
			flag: "report_data",
			good: "01020304050000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
			bad: []string{
				"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001",
				"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100",
				"not even hex",
			},
			setter: bytesSetter("report_data"),
		},
		{
			flag: "host_data",
			good: "0000000000000000000000000000000000000000000000000000000000000000",
			bad: []string{
				"0000000000000000000000000000000000000000000000000000000000000001",   // right size
				"000000000000000000000000000000000000000000000000000000000000000001", // wrong size
			},
			setter: bytesSetter("host_data"),
		},
		{
			flag:   "family_id",
			good:   "00000000000000000000000000000000",
			bad:    []string{"00000000000000000000000000000001"},
			setter: bytesSetter("family_id"),
		},
		{
			flag:   "image_id",
			good:   "00000000000000000000000000000000",
			bad:    []string{"00000000000000000000000000000001"},
			setter: bytesSetter("image_id"),
		},
		{
			flag:   "report_id",
			good:   "8edc638e1857c555d21f6b11bda3c8b1b5a09dba4852b4c8ee7aa2f16f22cc0a",
			bad:    []string{},
			setter: bytesSetter("report_id"),
		},
		{
			flag:   "report_id_ma",
			good:   "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			bad:    []string{},
			setter: bytesSetter("report_id_ma"),
		},
		{
			flag:   "measurement",
			good:   "b07af9620f3b839b47996422ddec6058338951d984e312115131ea82705eaf5b6bdf8a9ece31a5a608eb0cf2e4872b01",
			bad:    []string{},
			setter: bytesSetter("measurement"),
		},
		{
			flag: "chip_id",
			good: goodChipID,
			bad: []string{
				"3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5d00",
				"3ac3fe21e13fb0990eb28a802e3fb6a29483a6b0753590c951bdd3b8e53786184ca39e359669a2b76a1936776b564ea464cdce40c05f63c9b610c5068b006b5e",
			},
			setter: bytesSetter("chip_id"),
		},
		{
			flag:   "minimum_tcb",
			good:   "4901323769462652930",
			bad:    []string{"4901323769462652931"},
			setter: uint64setter("minimum_tcb"),
		},
		{
			flag:   "minimum_launch_tcb",
			good:   "4901323769462652930",
			bad:    []string{"4901323769462652931"},
			setter: uint64setter("minimum_launch_tcb"),
		},
		{
			flag:   "guest_policy",
			good:   fmt.Sprintf("%d", goodPolicy),
			bad:    []string{"0", "debug"},
			setter: uint64setter("policy"),
		},
		{
			flag:   "min_build",
			good:   "0",
			bad:    []string{"257", "90"},
			setter: uint32setter("minimum_build"),
		},
		{
			flag:   "min_version",
			good:   "1.49",
			bad:    []string{"0.0.0", "1.50", "0.", ".0"},
			setter: stringSetter("minimum_version"),
		},
		{
			flag:   "provisional",
			good:   "true",
			bad:    nil, // The example doesn't have provional firmware
			setter: boolSetter("permit_provisional_firmware"),
		},
		{
			flag:   "require_author_key",
			good:   "false",
			bad:    []string{"true"},
			setter: boolSetter("require_author_key"),
		},
		{
			flag:   "require_idblock",
			good:   "false", // The example doesn't have an IDBLOCK.
			bad:    []string{"true", "yes"},
			setter: boolSetter("require_id_block"),
		},
		{
			flag:   "vmpl",
			good:   "0",
			bad:    []string{"1", "4", "wrong", "-1"},
			setter: uint32valueSetter("vmpl"),
		},
		{
			flag:   "platform_info",
			good:   "1",
			bad:    []string{"0"},
			setter: uint64valueSetter("platform_info"),
		},
	}
}

// Writes contents to a file that the runner gets a path to and can use, then deletes the file.
func withTempFile(contents []byte, t *testing.T, runner func(path string)) {
	file, err := os.CreateTemp(".", "temp")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	n, err := file.Write(contents)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(contents) {
		t.Fatalf("incomplete write to %q. Wrote %d, want %d", file.Name(), n, len(contents))
	}
	runner(file.Name())
}

func withTestConfig(p *checkpb.Policy, t *testing.T, runner func(path string)) {
	config := &checkpb.Config{Policy: p}

	out, err := proto.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	withTempFile(out, t, runner)
}

func TestCheckGoodFlags(t *testing.T) {
	for _, tc := range testCases() {
		// Singular good flag
		t.Run(tc.flag, func(t *testing.T) {
			cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", tc.flag, tc.good), "--product_name=Milan-B0")...)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("%s failed unexpectedly: %v (%s)", cmd, err, output)
			}
		})
	}
}

func TestCheckBadFlags(t *testing.T) {
	for _, tc := range testCases() {
		// Singular bad flags
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s[%d]", tc.flag, i+1), func(t *testing.T) {
				cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-%s=%s", tc.flag, bad), "--product_name=Milan-B0")...)
				if output, err := cmd.CombinedOutput(); err == nil {
					t.Errorf("%s succeeded unexpectedly: %s", cmd, output)
				}
			})
		}
	}
}

func TestCheckGoodFields(t *testing.T) {
	for _, tc := range testCases() {
		t.Run(tc.flag, func(t *testing.T) {
			p := &checkpb.Policy{Policy: goodPolicy}
			if tc.setter(p, tc.good, t) {
				t.Fatal("unexpected parse failure")
			}
			withTestConfig(p, t, func(path string) {
				cmd := exec.Command(check, withBaseArgs(path, "--product_name=Milan-B0")...)
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Errorf("%s (%v) failed unexpectedly: %v, %s", cmd, p, err, output)
				}
			})
		})
	}
}

func TestCheckBadFields(t *testing.T) {
	for _, tc := range testCases() {
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s_bad[%d]", tc.flag, i+1), func(t *testing.T) {
				p := &checkpb.Policy{Policy: goodPolicy}
				if tc.setter(p, bad, t) {
					return
				}
				withTestConfig(p, t, func(path string) {
					cmd := exec.Command(check, withBaseArgs(path, "--product_name=Milan-B0")...)
					if output, err := cmd.CombinedOutput(); err == nil {
						t.Errorf("%s (%v) succeeded unexpectedly: %s", cmd, p, output)
					}
				})
			})
		}
	}
}

func TestCheckGoodFlagOverridesBadField(t *testing.T) {
	for _, tc := range testCases() {
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s_bad[%d]", tc.flag, i+1), func(t *testing.T) {
				p := &checkpb.Policy{Policy: goodPolicy}
				if tc.setter(p, bad, t) {
					return
				}
				withTestConfig(p, t, func(path string) {
					cmd := exec.Command(check, withBaseArgs(path, fmt.Sprintf("-%s=%s", tc.flag, tc.good), "--product_name=Milan-B0")...)
					if output, err := cmd.CombinedOutput(); err != nil {
						t.Errorf("%s (%v) failed unexpectedly: %v, %s", cmd, p, err, output)
					}
				})
			})
		}
	}
}

func TestCheckBadFlagOverridesGoodField(t *testing.T) {
	for _, tc := range testCases() {
		for i, bad := range tc.bad {
			t.Run(fmt.Sprintf("%s_bad[%d]", tc.flag, i+1), func(t *testing.T) {
				p := &checkpb.Policy{Policy: goodPolicy}
				if tc.setter(p, tc.good, t) {
					t.Fatal("unexpected parse failure")
				}
				withTestConfig(p, t, func(path string) {
					cmd := exec.Command(check, withBaseArgs(path, fmt.Sprintf("-%s=%s", tc.flag, bad), "--product_name=Milan-B0")...)
					if output, err := cmd.CombinedOutput(); err == nil {
						t.Errorf("%s (%v) succeeded unexpectedly: %s", cmd, p, output)
					}
				})
			})
		}
	}
}

func TestCaBundles(t *testing.T) {
	signer, err := fakesev.DefaultTestOnlyCertChain(kds.DefaultProductString(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	fakebundle := &bytes.Buffer{}
	if err := multierr.Combine(
		pem.Encode(fakebundle, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ask.Raw}),
		pem.Encode(fakebundle, &pem.Block{Type: "CERTIFICATE", Bytes: signer.Ark.Raw}),
	); err != nil {
		t.Fatal(err)
	}
	// -product only has meaning when provided with a custom product_key_path, so test together.
	goodbad := func(n int, name string) string {
		if n == 0 {
			return fmt.Sprintf("good%s", name)
		}
		return fmt.Sprintf("bad%s[%d]", name, n+1)
	}

	withTempFile(fakebundle.Bytes(), t, func(fakePath string) {
		products := []string{"Milan", "None"}
		cabundles := []string{"../../verify/testdata/milan.testcer", fakePath, "doesNotExist"}
		for i, product := range products {
			for j, cabundle := range cabundles {
				t.Run(fmt.Sprintf("%s_%s", goodbad(i, "product"), goodbad(j, "cabundle")), func(t *testing.T) {
					cmd := exec.Command(check, withBaseArgs("", fmt.Sprintf("-product=%s", product),
						fmt.Sprintf("-product_key_path=%s", cabundle))...)
					output, err := cmd.CombinedOutput()
					// Only the first pair of the cartesian product is good.
					if i == 0 && j == 0 && err != nil {
						t.Errorf("%s errored unexpectedly: %v, %s", cmd, err, output)
					} else if !(i == 0 && j == 0) && err == nil {
						t.Errorf("%s succeeded unexpectedly: %s", cmd, output)
					}
				})
			}
		}
	})
}
