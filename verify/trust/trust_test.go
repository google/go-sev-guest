package trust

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// FakeHTTPSGetter is a test double for HTTPSGetter. It can hold a slice
// of body and error responses so Get can be called multiple times and return
// different values, as to simulate different scenarios.
type FakeHTTPSGetter struct {
	// callCount is used to return the respective responses
	callCount     int
	ResponseBody  [][]byte
	ResponseError []error
}

// Get the next configured response body and error.
func (f *FakeHTTPSGetter) Get(url string) ([]byte, error) {
	body := f.ResponseBody[f.callCount]
	err := f.ResponseError[f.callCount]
	f.callCount++
	return body, err
}

func stringsToByteSlice(strings ...string) [][]byte {
	var result [][]byte
	for idx := range strings {
		s := strings[idx]
		result = append(result, []byte(s))
	}
	return result
}

func TestRetryHTTPSGetterSuccess(t *testing.T) {
	r := &RetryHTTPSGetter{
		Timeout:       2 * time.Second,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter: &FakeHTTPSGetter{
			ResponseBody:  stringsToByteSlice("content"),
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
	r := &RetryHTTPSGetter{
		Timeout:       2 * time.Second,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter: &FakeHTTPSGetter{
			ResponseBody:  stringsToByteSlice("", "content"),
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
	r := &RetryHTTPSGetter{
		Timeout:       1 * time.Millisecond,
		MaxRetryDelay: 1 * time.Millisecond,
		Getter: &FakeHTTPSGetter{
			ResponseBody:  stringsToByteSlice("", "", ""),
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
