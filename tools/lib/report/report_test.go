// Copyright 2024 Google LLC
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

package report

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	test "github.com/google/go-sev-guest/testing"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

var qp client.QuoteProvider
var mu sync.Once

type reports struct {
	attestation *spb.Attestation
	bincerts    []byte
	binreport   []byte
	protocerts  []byte
	protoreport []byte
	textcerts   []byte
	textreport  []byte
}

var input *reports

func initDevice() {
	now := time.Date(2022, time.May, 3, 9, 0, 0, 0, time.UTC)
	tests := test.TestCases()
	ones32 := make([]byte, 32)
	for i := range ones32 {
		ones32[i] = 1
	}
	opts := &test.DeviceOptions{Now: now, Product: abi.DefaultSevProduct()}
	tcqp, err := test.TcQuoteProvider(tests, opts)
	if err != nil {
		panic(fmt.Sprintf("failed to create test device: %v", err))
	}
	qp = tcqp

	var zeros [abi.ReportDataSize]byte
	bincerts, err := qp.GetRawQuote(zeros)
	if err != nil {
		panic(fmt.Errorf("mock failed to quote: %v", err))
	}
	if len(bincerts) < abi.ReportSize+abi.CertTableEntrySize {
		panic("mock failed to return cert table")
	}
	binreport := bincerts[:abi.ReportSize]
	attestation, err := ParseAttestation(bincerts, "bin")
	if err != nil {
		panic(fmt.Errorf("marshal failure: %v", err))
	}
	protocerts, err := proto.Marshal(attestation)
	if err != nil {
		panic(fmt.Errorf("marshal failure: %v", err))
	}
	protoreport, err := proto.Marshal(attestation.Report)
	if err != nil {
		panic(fmt.Errorf("marshal failure: %v", err))
	}
	textcerts, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(attestation)
	if err != nil {
		panic(fmt.Errorf("marshal failure: %v", err))
	}
	textreport, err := prototext.MarshalOptions{Multiline: true, Indent: "  "}.Marshal(attestation.Report)
	if err != nil {
		panic(fmt.Errorf("marshal failure: %v", err))
	}
	input = &reports{
		attestation: attestation,
		bincerts:    bincerts,
		binreport:   binreport,
		protocerts:  protocerts,
		protoreport: protoreport,
		textcerts:   textcerts,
		textreport:  textreport,
	}
}

func TestParseAttestation(t *testing.T) {
	mu.Do(initDevice)
	type testcase struct {
		input  []byte
		inform string
	}
	good := []testcase{
		{input.bincerts, "bin"},
		{input.binreport, "bin"},
		{input.protocerts, "proto"},
		{input.protoreport, "proto"},
		{input.textcerts, "textproto"},
		{input.textreport, "textproto"},
	}
	bad := []testcase{
		{input.bincerts, "proto"},
		{input.textcerts, "bin"},
		{input.protoreport, "textproto"},
	}
	for _, tc := range good {
		if _, err := ParseAttestation(tc.input, tc.inform); err != nil {
			t.Fatalf("ParseAttestation(_, %q) = _, %v. Expect nil", tc.inform, err)
		}
	}
	for _, tc := range bad {
		if _, err := ParseAttestation(tc.input, tc.inform); err == nil {
			t.Fatalf("ParseAttestation(_, %q) = _, nil. Expected an error", tc.inform)
		}
	}
}

func TestReadAttestation(t *testing.T) {
	mu.Do(initDevice)
	type testcase struct {
		input  []byte
		inform string
	}
	good := []testcase{
		{input.bincerts, "bin"},
		{input.binreport, "bin"},
		{input.protocerts, "proto"},
		{input.protoreport, "proto"},
		{input.textcerts, "textproto"},
		{input.textreport, "textproto"},
	}
	bad := []testcase{
		{input.bincerts, "proto"},
		{input.textcerts, "bin"},
		{input.protoreport, "textproto"},
	}
	for _, tc := range good {
		p := path.Join(t.TempDir(), "input")
		if err := os.WriteFile(p, tc.input, 0644); err != nil {
			t.Fatalf("Could not write test file %q: %v", p, err)
		}
		if _, err := ReadAttestation(p, tc.inform); err != nil {
			t.Fatalf("ParseAttestation(_, %q) = _, %v. Expect nil", tc.inform, err)
		}
	}
	for _, tc := range bad {
		p := path.Join(t.TempDir(), "input")
		if err := os.WriteFile(p, tc.input, 0644); err != nil {
			t.Fatalf("Could not write test file %q: %v", p, err)
		}
		if _, err := ReadAttestation(p, tc.inform); err == nil {
			t.Fatalf("ReadAttestation(_, %q) = _, nil. Expected an error", tc.inform)
		}
	}
}

func TestTransform(t *testing.T) {
	mu.Do(initDevice)
	t.Run("bin", func(t *testing.T) {
		binout, err := Transform(input.attestation, "bin")
		if err != nil {
			t.Fatalf("Transform(_, \"bin\") = _, %v. Expect nil.", err)
		}
		if !bytes.Equal(binout, input.bincerts) {
			t.Fatalf("Transform(_, \"bin\") = %v, nil. Expect %v.", binout, input.bincerts)
		}
	})
	t.Run("proto", func(t *testing.T) {
		protoout, err := Transform(input.attestation, "proto")
		if err != nil {
			t.Fatalf("Transform(_, \"proto\") = _, %v. Expect nil.", err)
		}
		if !bytes.Equal(protoout, input.protocerts) {
			t.Fatalf("Transform(_, \"proto\") = %v, nil. Expect %v.", protoout, input.protocerts)
		}
	})
	t.Run("textproto", func(t *testing.T) {
		textout, err := Transform(input.attestation, "textproto")
		if err != nil {
			t.Fatalf("Transform(_, \"textproto\") = _, %v. Expect nil.", err)
		}
		if !bytes.Equal(textout, input.textcerts) {
			t.Fatalf("Transform(_, \"textproto\") = %v, nil. Expect %v.", string(textout), string(input.textcerts))
		}
	})
}
