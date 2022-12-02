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

// Package cmdline implements command-line utilities for tools.
package cmdline

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// InputType represents how data is coming in, either via file or string.
type InputType int

var allFlags []func(inform string) error

const (
	// Stringy indicates the input is coming from an argument string.
	// "auto" behavior prefers hexadecimal.
	Stringy = iota
	// Filey indicates the input is coming from a file.
	// "auto" behavior prefers binary.
	Filey
)

func sizedBytes(flag, value string, byteSize int, decode func(string) ([]byte, error)) ([]byte, error) {
	bytes, err := decode(value)
	if err != nil {
		return nil, fmt.Errorf("%s=%s could not be decoded: %v", flag, value, err)
	}
	if len(bytes) > byteSize {
		return nil, fmt.Errorf("%s=%s (%v) is not representable in %d bytes", flag, value, bytes, byteSize)
	}
	sized := make([]byte, byteSize)
	copy(sized, bytes)
	return sized, nil
}

func parseBytesFromString(name string, byteSize int, in string, inform string) ([]byte, error) {
	if !utf8.ValidString(in) {
		return nil, fmt.Errorf("could not decode %s contents as a UTF-8 string. Try -inform=bin", name)
	}
	// Strict forms first.
	switch inform {
	case "hex":
		return sizedBytes(name, in, byteSize, hex.DecodeString)
	case "base64":
		return sizedBytes(name, in, byteSize, base64.StdEncoding.DecodeString)
	case "auto":
		// "auto" means to try hex encoding first, then base64.
		if b, err := sizedBytes(name, in, byteSize, hex.DecodeString); err == nil {
			return b, nil
		}
		return sizedBytes(name, in, byteSize, base64.StdEncoding.DecodeString)
	default:
		return nil, fmt.Errorf("unknown -inform=%s", inform)
	}
}

func isBinForm(inform string, intype InputType) bool {
	if inform == "bin" {
		return true
	}
	return (intype == Filey && inform == "auto")
}

// ParseBytes returns the denoted bytes from the reader `in` or an error.
func ParseBytes(name string, byteSize int, in io.Reader, inform string, intype InputType) ([]byte, error) {
	inbytes, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	// Empty input is treated as an empty array, not a zero-filled byteSize array.
	// This allows initial values of nil to be distinguishable from 0.
	if len(inbytes) == 0 {
		return nil, nil
	}
	if isBinForm(inform, intype) {
		if len(inbytes) != byteSize {
			return nil, fmt.Errorf("binary input type had %d bytes. Expect exactly %d bytes",
				len(inbytes), byteSize)
		}
		return inbytes, nil
	}
	return parseBytesFromString(name, byteSize, strings.TrimSpace(string(inbytes)), inform)
}

// Bytes is a flag.Func parsing function that translates a string into
// a specific byte-width array.
//
// A byte string can be represented as
// *  hexadecimal encoded string if -inform=hex or -inform=auto.
// *  base64 if -inform=base64 or -inform=auto
//
// Hex string decoding is attempted first with auto. The base64 encoding grammar
// intersects with the hex encoding grammar, so -inform=auto can misbehave.
func Bytes(name string, byteSize int, in *string) *[]byte {
	var empty []byte
	result := &empty
	allFlags = append(allFlags, func(inform string) error {
		// No input means to keep the initial value.
		if *in == "" {
			return nil
		}
		bytes, err := ParseBytes(name, byteSize, strings.NewReader(*in), inform, Stringy)
		if err != nil {
			return err
		}
		*result = bytes
		return nil
	})
	return result
}

// Parse processes all flag data given the input format and the precondition
// that all input flags have been parsed.
func Parse(inform string) {
	for _, thunk := range allFlags {
		if err := thunk(inform); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n\n", err)
			flag.Usage()
			os.Exit(1)
		}
	}
}
