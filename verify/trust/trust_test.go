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

package trust_test

import (
	"bytes"
	"errors"
	"testing"
	"time"

	test "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/verify/trust"
)

func TestRetryHTTPSGetterSuccess(t *testing.T) {
	r := &trust.RetryHTTPSGetter{
		Timeout:       2 * time.Second,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter: &test.VariableResponseGetter{
			ResponseBody:  test.StringsToByteSlice("content"),
			ResponseError: []error{nil},
		},
	}

	body, err := r.Get("https://any.url")
	if !bytes.Equal(body, []byte("content")) {
		t.Errorf("expected '%s' but got '%s'", "content", body)
	}
	if err != nil {
		t.Errorf("expected no error, but got %s", err.Error())
	}
}

func TestRetryHTTPSGetterSecondSuccess(t *testing.T) {
	r := &trust.RetryHTTPSGetter{
		Timeout:       2 * time.Second,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter: &test.VariableResponseGetter{
			ResponseBody:  test.StringsToByteSlice("", "content"),
			ResponseError: []error{errors.New("failed"), nil},
		},
	}

	body, err := r.Get("https://any.url")
	if !bytes.Equal(body, []byte("content")) {
		t.Errorf("expected '%s' but got '%s'", "content", body)
	}
	if err != nil {
		t.Errorf("expected no error, but got %s", err.Error())
	}
}

func TestRetryHTTPSGetterAllFail(t *testing.T) {
	fail := errors.New("failed")
	r := &trust.RetryHTTPSGetter{
		Timeout:       1 * time.Millisecond,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter: &test.VariableResponseGetter{
			ResponseBody:  test.StringsToByteSlice("", "", ""),
			ResponseError: []error{fail, fail, fail},
		},
	}

	body, err := r.Get("https://any.url")
	if !bytes.Equal(body, []byte("")) {
		t.Errorf("expected '%s' but got '%s'", "content", body)
	}
	if err == nil {
		t.Errorf("expected error, but got none")
	}
}
