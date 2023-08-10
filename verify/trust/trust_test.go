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

func TestRetryHTTPSGetter(t *testing.T) {
	testCases := map[string]struct {
		getter        *test.Getter
		timeout       time.Duration
		maxRetryDelay time.Duration
	}{
		"immediate success": {
			getter: &test.Getter{
				Responses: map[string][]test.GetResponse{
					"https://fetch.me": {
						{
							Occurances: 1,
							Body:       []byte("content"),
							Error:      nil,
						},
					},
				},
			},
			timeout:       time.Second,
			maxRetryDelay: time.Millisecond,
		},
		"second success": {
			getter: &test.Getter{
				Responses: map[string][]test.GetResponse{
					"https://fetch.me": {
						{
							Occurances: 1,
							Body:       []byte(""),
							Error:      errors.New("fail"),
						},
						{
							Occurances: 1,
							Body:       []byte("content"),
							Error:      nil,
						},
					},
				},
			},
			timeout:       time.Second,
			maxRetryDelay: time.Millisecond,
		},
		"third success": {
			getter: &test.Getter{
				Responses: map[string][]test.GetResponse{
					"https://fetch.me": {
						{
							Occurances: 2,
							Body:       []byte(""),
							Error:      errors.New("fail"),
						},
						{
							Occurances: 1,
							Body:       []byte("content"),
							Error:      nil,
						},
					},
				},
			},
			timeout:       time.Second,
			maxRetryDelay: time.Millisecond,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			r := &trust.RetryHTTPSGetter{
				Timeout:       tc.timeout,
				MaxRetryDelay: tc.maxRetryDelay,
				Getter:        tc.getter,
			}

			body, err := r.Get("https://fetch.me")
			if !bytes.Equal(body, []byte("content")) {
				t.Errorf("expected '%s' but got '%s'", "content", body)
			}
			if err != nil {
				t.Errorf("expected no error, but got %s", err.Error())
			}
			tc.getter.Done(t)
		})
	}
}

func TestRetryHTTPSGetterAllFail(t *testing.T) {
	testGetter := &test.Getter{
		Responses: map[string][]test.GetResponse{
			"https://fetch.me": {
				{
					Occurances: 1,
					Body:       []byte(""),
					Error:      errors.New("fail"),
				},
			},
		},
	}
	r := &trust.RetryHTTPSGetter{
		Timeout:       1 * time.Millisecond,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter:        testGetter,
	}

	body, err := r.Get("https://fetch.me")
	if !bytes.Equal(body, []byte("")) {
		t.Errorf("expected '%s' but got '%s'", "content", body)
	}
	if err == nil {
		t.Errorf("expected error, but got none")
	}
	testGetter.Done(t)
}
