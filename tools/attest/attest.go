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
	"os"
	"strconv"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
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
	vmpl = flag.String("vmpl", "default", "The VMPL at which to collect an attestation report")
	out  = flag.String("out", "", "Path to output file to write attestation report to. "+
		"If unset, outputs to stdout.")
	verbose = flag.Bool("v", false, "Enable verbose logging.")
	vmplInt uint
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

func outputExtendedReport(data [abi.ReportDataSize]byte, out io.Writer) error {
	if *outform == "bin" {
		bin, err := getRaw(data)
		if err != nil {
			return err
		}
		out.Write(bin)
		return nil
	}
	attestation, err := getProto(data)
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

func getVmpl() (uint, error) {
	if *vmpl == "default" {
		return 0, fmt.Errorf("getVmpl should not be called on \"default\"")
	}
	vmplInt, err := strconv.ParseUint(*vmpl, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("--vmpl must be a non-negative integer or \"default\"")
	}
	return uint(vmplInt), nil
}

func getRaw(data [abi.ReportDataSize]byte) ([]byte, error) {
	if *vmpl == "default" {
		qp, err := client.GetQuoteProvider()
		if err != nil {
			return nil, err
		}
		return qp.GetRawQuote(data)
	}
	qp, err := client.GetLeveledQuoteProvider()
	if err != nil {
		return nil, err
	}
	return qp.GetRawQuoteAtLevel(data, vmplInt)
}

func getProto(data [abi.ReportDataSize]byte) (*pb.Attestation, error) {
	if *vmpl == "default" {
		qp, err := client.GetQuoteProvider()
		if err != nil {
			return nil, err
		}
		return client.GetQuoteProto(qp, data)
	}
	qp, err := client.GetLeveledQuoteProvider()
	if err != nil {
		return nil, err
	}
	return client.GetQuoteProtoAtLevel(qp, data, vmplInt)
}

func outputReport(data [abi.ReportDataSize]byte, out io.Writer) error {
	if *outform == "bin" {
		bytes, err := getRaw(data)
		if err != nil {
			return err
		}
		if len(bytes) > abi.ReportSize {
			bytes = bytes[:abi.ReportSize]
		}
		out.Write(bytes)
		return nil
	}
	attestation, err := getProto(data)
	if err != nil {
		return err
	}
	bytes, err := nonBinOut()(attestation.Report)
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
		logger.Fatalf("-outform is %s. Expect \"bin\", \"proto\", or \"textproto\"",
			*outform)
	}

	if *vmpl != "default" {
		vint, err := getVmpl()
		if err != nil || vint > 3 {
			logger.Fatalf("--vmpl=%s. Expect 0-3 or \"default\"", *vmpl)
		}
		vmplInt = vint
	}

	outwriter, filetoclose, err := outWriter()
	if err != nil {
		logger.Fatal(err)
	}
	defer func() {
		if filetoclose != nil {
			filetoclose.Close()
		}
	}()

	var reportData64 [abi.ReportDataSize]byte
	copy(reportData64[:], reportData)
	if *extended {
		if err := outputExtendedReport(reportData64, outwriter); err != nil {
			logger.Fatal(err)
		}
	} else {
		if err := outputReport(reportData64, outwriter); err != nil {
			logger.Fatal(err)
		}
	}
}
