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

// Package trust defines core trust types and values for attestation verification.
package trust

import (
	"context"
	"crypto/x509"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/logger"
)

var (
	// DefaultRootCerts holds AMD's SEV API certificate format for ASK and ARK keys as published here
	// https://developer.amd.com/wp-content/resources/ask_ark_milan.cert
	DefaultRootCerts map[string]*AMDRootCerts

	// The ASK and ARK certificates are embedded since they do not have an expiration date. The KDS
	// documents them having a lifetime of 25 years. The X.509 certificate that this cert's signature
	// is over cannot be reconstructed from the SEV certificate format. The X.509 certificate with its
	// expiration dates is at https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
	//go:embed ask_ark_milan.sevcert
	askArkMilanBytes []byte
)

// AMDRootCerts encapsulates the certificates that represent root of trust in AMD.
type AMDRootCerts struct {
	// Product is the expected CPU product name, e.g., Milan, Turin, Genoa.
	Product string
	// AskX509 is an X.509 certificate for the AMD SEV signing key (ASK)
	AskX509 *x509.Certificate
	// ArkX509 is an X.509 certificate for the AMD root key (ARK).
	ArkX509 *x509.Certificate
	// AskSev is the AMD certificate representation of the AMD signing key that certifies
	// versioned chip endoresement keys. If present, the information must match AskX509.
	AskSev *abi.AskCert
	// ArkSev is the AMD certificate representation of the self-signed AMD root key that
	// certifies the AMD signing key. If present, the information must match ArkX509.
	ArkSev *abi.AskCert
	// Mu protects concurrent accesses to CRL.
	Mu sync.Mutex
	// CRL is the certificate revocation list for this AMD product. Populated once, only when a
	// revocation is checked.
	CRL *x509.RevocationList
}

// HTTPSGetter represents the ability to fetch data from the internet from an HTTP URL.
// Used particularly for fetching certificates.
type HTTPSGetter interface {
	Get(url string) ([]byte, error)
}

// SimpleHTTPSGetter implements the HTTPSGetter interface with http.Get.
type SimpleHTTPSGetter struct{}

// Get uses http.Get to return the HTTPS response body as a byte array.
func (n *SimpleHTTPSGetter) Get(url string) ([]byte, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("failed to retrieve %s", url)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return body, nil
}

// RetryHTTPSGetter is a meta-HTTPS getter that will retry on failure a given number of times.
type RetryHTTPSGetter struct {
	// Timeout is how long to retry before failure.
	Timeout time.Duration
	// MaxRetryDelay is the maximum amount of time to wait between retries.
	MaxRetryDelay time.Duration
	// Getter is the non-retrying way of getting a URL.
	Getter HTTPSGetter
}

// Get fetches the body of the URL, retrying a given amount of times on failure.
func (n *RetryHTTPSGetter) Get(url string) ([]byte, error) {
	delay := 2 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), n.Timeout)
	for {
		body, err := n.Getter.Get(url)
		if err == nil {
			cancel()
			return body, nil
		}
		delay = delay + delay
		if delay > n.MaxRetryDelay {
			delay = n.MaxRetryDelay
		}
		select {
		case <-ctx.Done():
			cancel()
			return nil, fmt.Errorf("timeout") // context cancelled
		case <-time.After(delay): // wait to retry
		}
	}
}

// DefaultHTTPSGetter returns the library's default getter implementation. It will
// retry slowly due to the AMD KDS's rate limiting.
func DefaultHTTPSGetter() HTTPSGetter {
	return &RetryHTTPSGetter{
		Timeout:       2 * time.Minute,
		MaxRetryDelay: 30 * time.Second,
		Getter:        &SimpleHTTPSGetter{},
	}
}

// Unmarshal populates ASK and ARK certificates from AMD SEV format certificates in data.
func (r *AMDRootCerts) Unmarshal(data []byte) error {
	ask, index, err := abi.ParseAskCert(data)
	if err != nil {
		return fmt.Errorf("could not parse ASK certificate in SEV certificate format: %v", err)
	}
	r.AskSev = ask
	ark, _, err := abi.ParseAskCert(data[index:])
	if err != nil {
		return fmt.Errorf("could not parse ARK certificate in SEV certificate format: %v", err)
	}
	r.ArkSev = ark
	return nil
}

// FromDER populates the AMDRootCerts from DER-formatted certificates for both the ASK and the ARK.
func (r *AMDRootCerts) FromDER(ask []byte, ark []byte) error {
	askCert, err := x509.ParseCertificate(ask)
	if err != nil {
		return fmt.Errorf("could not parse ASK certificate: %v", err)
	}
	r.AskX509 = askCert

	arkCert, err := x509.ParseCertificate(ark)
	if err != nil {
		logger.Errorf("could not parse ARK certificate: %v", err)
	}
	r.ArkX509 = arkCert
	return nil
}

// FromKDSCertBytes populates r's AskX509 and ArkX509 certificates from the two PEM-encoded
// certificates in data. This is the format the Key Distribution Service (KDS) uses, e.g.,
// https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
func (r *AMDRootCerts) FromKDSCertBytes(data []byte) error {
	ask, ark, err := kds.ParseProductCertChain(data)
	if err != nil {
		return err
	}
	return r.FromDER(ask, ark)
}

// FromKDSCert populates r's AskX509 and ArkX509 certificates from the certificate format AMD's Key
// Distribution Service (KDS) uses, e.g., https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
func (r *AMDRootCerts) FromKDSCert(path string) error {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return r.FromKDSCertBytes(certBytes)
}

// X509Options returns the ASK and ARK as the only intermediate and root certificates of an x509
// verification options object, or nil if either key's x509 certificate is not present in r.
func (r *AMDRootCerts) X509Options() *x509.VerifyOptions {
	if r.AskX509 == nil || r.ArkX509 == nil {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.ArkX509)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(r.AskX509)
	return &x509.VerifyOptions{Roots: roots, Intermediates: intermediates}
}

// Parse ASK, ARK certificates from the embedded AMD certificate file.
func init() {
	milanCerts := new(AMDRootCerts)
	milanCerts.Unmarshal(askArkMilanBytes)
	DefaultRootCerts = map[string]*AMDRootCerts{
		"Milan": milanCerts,
	}
}
