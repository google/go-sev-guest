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
	"encoding/pem"
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

	// A cache of product certificate KDS results per product.
	prodCacheMu      sync.Mutex
	productCertCache map[string]*ProductCerts
)

// Communication with AMD suggests repeat requests of the same arguments will
// be throttled to once per 10 seconds.
const initialDelay = 10 * time.Second

// ProductCerts contains the root key and signing key devoted to a given product line.
type ProductCerts struct {
	Ask *x509.Certificate
	Ark *x509.Certificate
}

// AMDRootCerts encapsulates the certificates that represent root of trust in AMD.
type AMDRootCerts struct {
	// Product is the expected CPU product name, e.g., Milan, Turin, Genoa.
	Product string
	// ProductCerts contains the root key and signing key devoted to a given product line.
	ProductCerts *ProductCerts
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

// AttestationRecreationErr represents a problem with fetching or interpreting associated
// certificates for a given attestation report. This is typically due to network unreliability.
type AttestationRecreationErr struct {
	Msg string
}

func (e *AttestationRecreationErr) Error() string {
	return e.Msg
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
	delay := initialDelay
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

// ParseCert returns an X.509 Certificate type for a PEM[CERTIFICATE]- or DER-encoded cert.
func ParseCert(cert []byte) (*x509.Certificate, error) {
	raw := cert
	b, rest := pem.Decode(cert)
	if b != nil {
		if len(rest) > 0 || b.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("bad type %q or trailing bytes (%d). Expected a single certificate when in PEM format",
				b.Type, len(rest))
		}
		raw = b.Bytes
	}
	return x509.ParseCertificate(raw)
}

// Decode populates the ProductCerts from DER-formatted certificates for both the ASK and the ARK.
func (r *ProductCerts) Decode(ask []byte, ark []byte) error {
	askCert, err := ParseCert(ask)
	if err != nil {
		return fmt.Errorf("could not parse ASK certificate: %v", err)
	}
	r.Ask = askCert

	arkCert, err := ParseCert(ark)
	if err != nil {
		logger.Errorf("could not parse ARK certificate: %v", err)
	}
	r.Ark = arkCert
	return nil
}

// FromKDSCertBytes populates r's AskX509 and ArkX509 certificates from the two PEM-encoded
// certificates in data. This is the format the Key Distribution Service (KDS) uses, e.g.,
// https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
func (r *ProductCerts) FromKDSCertBytes(data []byte) error {
	ask, ark, err := kds.ParseProductCertChain(data)
	if err != nil {
		return err
	}
	return r.Decode(ask, ark)
}

// FromKDSCert populates r's AskX509 and ArkX509 certificates from the certificate format AMD's Key
// Distribution Service (KDS) uses, e.g., https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
func (r *ProductCerts) FromKDSCert(path string) error {
	certBytes, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return r.FromKDSCertBytes(certBytes)
}

// X509Options returns the ASK and ARK as the only intermediate and root certificates of an x509
// verification options object, or nil if either key's x509 certificate is not present in r.
func (r *ProductCerts) X509Options(now time.Time) *x509.VerifyOptions {
	if r.Ask == nil || r.Ark == nil {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.Ark)
	intermediates := x509.NewCertPool()
	intermediates.AddCert(r.Ask)
	return &x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now}
}

// ClearProductCertCache clears the product certificate cache. This is useful for testing with
// multiple roots of trust.
func ClearProductCertCache() {
	prodCacheMu.Lock()
	productCertCache = nil
	prodCacheMu.Unlock()
}

// GetProductChain returns the ASK and ARK certificates of the given product, either from getter
// or from a cache of the results from the last successful call.
func GetProductChain(product string, getter HTTPSGetter) (*ProductCerts, error) {
	if productCertCache == nil {
		prodCacheMu.Lock()
		productCertCache = make(map[string]*ProductCerts)
		prodCacheMu.Unlock()
	}
	result, ok := productCertCache[product]
	if !ok {
		askark, err := getter.Get(kds.ProductCertChainURL(product))
		if err != nil {
			return nil, &AttestationRecreationErr{
				Msg: fmt.Sprintf("could not download ASK and ARK certificates: %v", err),
			}
		}

		ask, ark, err := kds.ParseProductCertChain(askark)
		if err != nil {
			// Treat a bad parse as a network error since it's likely due to an incomplete transfer.
			return nil, &AttestationRecreationErr{Msg: fmt.Sprintf("could not parse root cert_chain: %v", err)}
		}
		askCert, err := x509.ParseCertificate(ask)
		if err != nil {
			return nil, &AttestationRecreationErr{Msg: fmt.Sprintf("could not parse ASK cert: %v", err)}
		}
		arkCert, err := x509.ParseCertificate(ark)
		if err != nil {
			return nil, &AttestationRecreationErr{Msg: fmt.Sprintf("could not parse ARK cert: %v", err)}
		}
		result = &ProductCerts{Ask: askCert, Ark: arkCert}
		prodCacheMu.Lock()
		productCertCache[product] = result
		prodCacheMu.Unlock()
	}
	return result, nil
}

// Forward all the ProductCerts operations from the AMDRootCerts struct to follow the
// Law of Demeter.

// Decode populates the AMDRootCerts from DER-formatted certificates for both the ASK and the ARK.
func (r *AMDRootCerts) Decode(ask []byte, ark []byte) error {
	r.ProductCerts = &ProductCerts{}
	return r.ProductCerts.Decode(ask, ark)
}

// FromKDSCertBytes populates r's AskX509 and ArkX509 certificates from the two PEM-encoded
// certificates in data. This is the format the Key Distribution Service (KDS) uses, e.g.,
// https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
func (r *AMDRootCerts) FromKDSCertBytes(data []byte) error {
	r.ProductCerts = &ProductCerts{}
	return r.ProductCerts.FromKDSCertBytes(data)
}

// FromKDSCert populates r's AskX509 and ArkX509 certificates from the certificate format AMD's Key
// Distribution Service (KDS) uses, e.g., https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
func (r *AMDRootCerts) FromKDSCert(path string) error {
	r.ProductCerts = &ProductCerts{}
	return r.ProductCerts.FromKDSCert(path)
}

// X509Options returns the ASK and ARK as the only intermediate and root certificates of an x509
// verification options object, or nil if either key's x509 certificate is not present in r.
func (r *AMDRootCerts) X509Options(now time.Time) *x509.VerifyOptions {
	if r.ProductCerts == nil {
		return nil
	}
	return r.ProductCerts.X509Options(now)
}

// Parse ASK, ARK certificates from the embedded AMD certificate file.
func init() {
	milanCerts := new(AMDRootCerts)
	milanCerts.Unmarshal(askArkMilanBytes)
	DefaultRootCerts = map[string]*AMDRootCerts{
		"Milan": milanCerts,
	}
}
