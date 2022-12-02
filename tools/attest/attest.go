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

// Package main implements a CLI tool for collecting attestation reports.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/tools/lib/cmdline"
	"github.com/google/logger"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var (
	inform = flag.String("inform", "auto", "The format of the reportData input. One of bin, hex, base64, or auto. "+
		"Input forms that are not \"bin\" or \"auto\" with a file input will be zero-padded on the right to fill "+
		"the expected byte size. If \"bin\" or \"auto\" from a file, then the size must be exact.")
	outform = flag.String("outform", "bin",
		"The format of the output attestation report. "+
			"One of \"bin\", \"proto\", \"textproto\". "+
			"The bin form is for AMD's specified data structures in binary.")
	extended = flag.Bool("extended", false,
		"Get both the attestation report and "+
			"the host-provided certificate chain. "+
			"If -outform=bin, then the binary appears in that order.")
	reportDataStr = flag.String("in", "",
		"A string of 64 bytes REPORT_DATA to include in the output attestation. "+
			"Big-endian hex, octal, or binary start with 0x, 0o, or 0b respectively, detected with -inform=auto."+
			"Little-endian base64 starts with 64x for auto to detect it, or without if -inform=base64. "+
			"Little-endian hex is tried last with auto. Default -inform=auto. It is an error to use -inform=bin1")
	reportData     = cmdline.Bytes("-in", abi.ReportDataSize, reportDataStr)
	reportDataFile = flag.String("infile", "",
		"Path to a file containing 64 bytes of REPORT_DATA to include "+
			"in the output attestation. Stdin is \"-\". Default -inform=bin.")
	vmpl = flag.Int("vmpl", 0, "The VMPL at which to collect an attestation report")
	out  = flag.String("out", "", "Path to output file to write attestation report to. "+
		"If unset, outputs to stdout.")
	verbose = flag.Bool("v", false, "Enable verbose logging.")
)

func indata() ([]byte, error) {
	if len(*reportData) == 0 && len(*reportDataFile) == 0 {
		// Default to stdin
		*reportDataFile = "-"
	}
	if len(*reportData) != 0 && len(*reportDataFile) != 0 {
		return nil, errors.New("cannot specify both of -in and -infile")
	}
	if len(*reportData) != 0 {
		return []byte(*reportData), nil
	}
	if *reportDataFile == "-" {
		return cmdline.ParseBytes("stdin", abi.ReportDataSize, os.Stdin, *inform, cmdline.Filey)
	}
	file, err := os.Open(*reportDataFile)
	if err != nil {
		return nil, fmt.Errorf("could not open %q: %v", *reportDataFile, err)
	}
	defer file.Close()
	return cmdline.ParseBytes("stdin", abi.ReportDataSize, file, *inform, cmdline.Filey)
}

func nonBinOut() func(proto.Message) ([]byte, error) {
	switch *outform {
	case "proto":
		return proto.Marshal
	case "textproto":
		return prototext.Marshal
		// unreachable panic since outform is checked in main
	default:
		panic(fmt.Sprintf("unknown -outform: %s", *outform))
	}
}

func outputExtendedReport(device client.Device, data [abi.ReportDataSize]byte, out io.Writer) error {
	if *outform == "bin" {
		report, certs, err := client.GetRawExtendedReportAtVmpl(device, data, *vmpl)
		if err != nil {
			return err
		}
		out.Write(report)
		out.Write(certs)
		return nil
	}
	attestation, err := client.GetExtendedReportAtVmpl(device, data, *vmpl)
	if err != nil {
		return err
	}
	bytes, err := nonBinOut()(attestation)
	if err != nil {
		return err
	}
	out.Write(bytes)
	return nil
}

func outputReport(device client.Device, data [abi.ReportDataSize]byte, out io.Writer) error {
	if *outform == "bin" {
		bytes, err := client.GetRawReportAtVmpl(device, data, *vmpl)
		if err != nil {
			return err
		}
		out.Write(bytes)
		return nil
	}
	report, err := client.GetReportAtVmpl(device, data, *vmpl)
	if err != nil {
		return err
	}
	bytes, err := nonBinOut()(report)
	if err != nil {
		return err
	}
	out.Write(bytes)
	return nil
}

func outWriter() (io.Writer, *os.File, error) {
	if *out == "" {
		return os.Stdout, nil, nil
	}
	file, err := os.Create(*out)
	if err != nil {
		return nil, nil, err
	}
	return file, file, nil
}

func main() {
	logger.Init("", *verbose, false, os.Stderr)
	flag.Parse()
	// Second phase of parsing.
	cmdline.Parse(*inform)

	reportData, err := indata()
	if err != nil {
		logger.Fatal(err)
	}

	if !(*outform == "bin" || *outform == "proto" || *outform == "textproto") {
		log.Fatalf("-outform is %s. Expect \"bin\", \"proto\", or \"textproto\"",
			*outform)
	}

	if *vmpl < 0 || *vmpl > 3 {
		log.Fatalf("-vmpl is %d. Expect 0-3.", *vmpl)
	}

	outwriter, filetoclose, err := outWriter()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if filetoclose != nil {
			filetoclose.Close()
		}
	}()

	device, err := client.OpenDevice()
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()
	var reportData64 [abi.ReportDataSize]byte
	copy(reportData64[:], reportData)
	if *extended {
		if err := outputExtendedReport(device, reportData64, outwriter); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := outputReport(device, reportData64, outwriter); err != nil {
			log.Fatal(err)
		}
	}
}
