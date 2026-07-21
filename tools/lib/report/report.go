// Copyright 2024-2025 Google LLC
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

// Package report provides functions for reading and writing attestation reports of various formats.
package report

import (
	"fmt"
	"io"
	"os"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"go.uber.org/multierr"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"

	spb "github.com/google/go-sev-guest/proto/sevsnp"
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

// ParseAttestation parses an attestation report from a byte slice as a given format.
func ParseAttestation(b []byte, inform string) (*spb.Attestation, error) {
	switch inform {
	case "bin":
		// May have empty certificate buffer to be just a report.
		return parseAttestationBytes(b)
	case "proto":
		result := &spb.Attestation{}
		aerr := proto.Unmarshal(b, result)
		var rerr error
		if aerr != nil {
			result.Report = &spb.Report{}
			rerr = proto.Unmarshal(b, result.Report)
			if rerr != nil {
				return nil, fmt.Errorf("could not parse as proto: %v", multierr.Append(aerr, rerr))
			}
		}
		return result, nil
	case "textproto":
		result := &spb.Attestation{}
		aerr := prototext.Unmarshal(b, result)
		var rerr error
		if aerr != nil {
			result.Report = &spb.Report{}
			rerr = prototext.Unmarshal(b, result.Report)
			if rerr != nil {
				return nil, fmt.Errorf("could not parse as textproto: %v", multierr.Append(aerr, rerr))
			}
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unknown inform: %q", inform)
	}
}

// ReadAttestation reads an attestation report from a file.
func ReadAttestation(infile, inform string) (*spb.Attestation, error) {
	var in io.Reader
	var f *os.File
	if infile == "-" {
		in = os.Stdin
	} else {
		file, err := os.Open(infile)
		if err != nil {
			return nil, fmt.Errorf("could not open %q: %v", infile, err)
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
		return nil, fmt.Errorf("could not read %q: %v", infile, err)
	}
	return ParseAttestation(contents, inform)
}

func asBin(report *spb.Attestation) ([]byte, error) {
	r, err := abi.ReportToAbiBytes(report.Report)
	if err != nil {
		return nil, err
	}
	certs := abi.CertsFromProto(report.CertificateChain).Marshal()
	return append(r, certs...), nil
}

func tcbBreakdown(productLine string, tcb uint64) (string, error) {
	tcbVersionStruct, err := kds.NewTCBVersionStruct(productLine, tcb)
	if err != nil {
		return "", err
	}

	parts, err := kds.DecomposeTCBVersionStruct(tcbVersionStruct)
	if err != nil {
		return "", err
	}

	return parts.String(), nil
}

func tcbText(report *spb.Attestation) ([]byte, error) {
	fms := report.GetReport().GetCpuid1EaxFms()

	currentTcb, currentTcbErr := tcbBreakdown(kds.ProductLineFromFms(fms), report.Report.GetCurrentTcb())
	committedTcb, committedTcbErr := tcbBreakdown(kds.ProductLineFromFms(fms), report.Report.GetCommittedTcb())
	launchTcb, launchTcbErr := tcbBreakdown(kds.ProductLineFromFms(fms), report.Report.GetLaunchTcb())
	err := multierr.Combine(currentTcbErr, committedTcbErr, launchTcbErr)
	if err != nil {
		return nil, err
	}

	return []byte(fmt.Sprintf("current_tcb=%s\ncommitted_tcb=%s\nlaunch_tcb=%s\n",
		currentTcb, committedTcb, launchTcb)), nil
}

// Transform returns the attestation in the outform marshalled format.
func Transform(report *spb.Attestation, outform string) ([]byte, error) {
	switch outform {
	case "bin":
		return asBin(report)
	case "proto":
		return proto.Marshal(report)
	case "textproto":
		return prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(report)
	case "tcb":
		return tcbText(report)
	default:
		return nil, fmt.Errorf("unknown outform: %q", outform)
	}
}
