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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-sev-guest/abi"
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
							Occurrences: 1,
							Body:        []byte("content"),
							Error:       nil,
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
							Occurrences: 1,
							Body:        []byte(""),
							Error:       errors.New("fail"),
						},
						{
							Occurrences: 1,
							Body:        []byte("content"),
							Error:       nil,
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
							Occurrences: 2,
							Body:        []byte(""),
							Error:       errors.New("fail"),
						},
						{
							Occurrences: 1,
							Body:        []byte("content"),
							Error:       nil,
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
					Occurrences: 1,
					Body:        []byte(""),
					Error:       errors.New("fail"),
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
		t.Errorf("expected empty body but got %q", body)
	}
	if err == nil {
		t.Errorf("expected error, but got none")
	}
	testGetter.Done(t)
}

func TestRetryHTTPSGetterContext(t *testing.T) {
	testGetter := &test.Getter{
		Responses: map[string][]test.GetResponse{
			"https://fetch.me": {
				{
					Occurrences: 1,
					Body:        []byte("content"),
					Error:       nil,
				},
			},
		},
	}
	r := &trust.RetryHTTPSGetter{
		MaxRetryDelay: 1 * time.Millisecond,
		Getter:        testGetter,
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body, err := r.GetContext(ctx, "https://fetch.me")
	if !bytes.Equal(body, []byte("")) {
		t.Errorf("expected empty body but got %q", body)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected error %q, but got %q", context.Canceled, err)
	}
}

func TestGetProductChainForRaceDetector(t *testing.T) {
	testGetter := &test.Getter{
		Responses: map[string][]test.GetResponse{
			"https://kdsintf.amd.com/vcek/v1/test/cert_chain": {
				{
					Occurrences: 2,
					Body:        trust.AskArkMilanVcekBytes,
				},
			},
		},
	}

	// run GetProductChain concurrently to see if the race detector is triggered.
	errCh := make(chan error)
	go func() {
		_, err := trust.GetProductChain("test", abi.VcekReportSigner, testGetter)
		errCh <- err
	}()

	go func() {
		_, err := trust.GetProductChain("test", abi.VcekReportSigner, testGetter)
		errCh <- err
	}()

	var err error
	for i := 0; i < 2; i++ {
		err = errors.Join(err, <-errCh)
	}
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type recordingGetter struct {
	getCalls int
}

func (r *recordingGetter) Get(_ string) ([]byte, error) {
	r.getCalls++
	return []byte{}, nil
}

type recordingContextGetter struct {
	recordingGetter
	getContextCalls int
}

func (r *recordingContextGetter) GetContext(_ context.Context, _ string) ([]byte, error) {
	r.getContextCalls++
	return []byte{}, nil
}

func TestGetWith(t *testing.T) {
	url := ""
	t.Run("HTTPSGetter uses Get", func(t *testing.T) {
		contextGetter := recordingContextGetter{}
		if _, err := trust.GetWith(context.Background(), &contextGetter.recordingGetter, url); err != nil {
			t.Fatalf("trust.GetWith returned an unexpected error: %v", err)
		}
		if contextGetter.getContextCalls != 0 {
			t.Errorf("wrong number of calls to GetContext: got %d, want 0", contextGetter.getContextCalls)
		}
		if contextGetter.recordingGetter.getCalls != 1 {
			t.Errorf("wrong number of calls to Get: got %d, want 1", contextGetter.getCalls)
		}
	})
	t.Run("ContextHTTPSGetter uses GetContext", func(t *testing.T) {
		contextGetter := recordingContextGetter{}
		if _, err := trust.GetWith(context.Background(), &contextGetter, url); err != nil {
			t.Fatalf("trust.GetWith returned an unexpected error: %v", err)
		}
		if contextGetter.getContextCalls != 1 {
			t.Errorf("wrong number of calls to GetContext: got %d, want 1", contextGetter.getContextCalls)
		}
		if contextGetter.recordingGetter.getCalls != 0 {
			t.Errorf("wrong number of calls to Get: got %d, want 0", contextGetter.getCalls)
		}
	})

}

// Ensure that the HTTPSGetters implement the expected interfaces.
var (
	_ = trust.HTTPSGetter(&trust.SimpleHTTPSGetter{})
	_ = trust.HTTPSGetter(&trust.RetryHTTPSGetter{})
	_ = trust.ContextHTTPSGetter(&trust.SimpleHTTPSGetter{})
	_ = trust.ContextHTTPSGetter(&trust.RetryHTTPSGetter{})
)
