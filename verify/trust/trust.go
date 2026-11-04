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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/logger"
	"go.uber.org/multierr"
)

var (
	// DefaultRootCerts holds AMD's SEV API certificate format for ASK and ARK keys as published here
	// https://download.amd.com/developer/eula/sev/ask_ark_milan.cert
	DefaultRootCerts map[string]*AMDRootCerts

	// AskArkMilanVcekBytes is a CA bundle for Milan.
	// source: https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
	//go:embed ask_ark_milan.pem
	AskArkMilanVcekBytes []byte

	// AskArkMilanVlekBytes is a CA bundle for VLEK certs on Milan.
	// source: https://kdsintf.amd.com/vlek/v1/Milan/cert_chain
	//go:embed ask_ark_milan_vlek.pem
	AskArkMilanVlekBytes []byte

	// AskArkGenoaVcekBytes is a CA bundle for Genoa.
	// source: https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
	//go:embed ask_ark_genoa.pem
	AskArkGenoaVcekBytes []byte

	// AskArkGenoaVlekBytes is a CA bundle for VLEK certs on Genoa.
	// source: https://kdsintf.amd.com/vlek/v1/Genoa/cert_chain
	//go:embed ask_ark_genoa_vlek.pem
	AskArkGenoaVlekBytes []byte

	// AskArkTurinVcekBytes is a CA bundle for VCEK certs on Turin.
	// source: https://kdsintf.amd.com/vcek/v1/Turin/cert_chain
	//go:embed ask_ark_turin_vcek.pem
	AskArkTurinVcekBytes []byte

	// AskArkTurinVlekBytes is a CA bundle for VLEK certs on Turin.
	// source: https://kdsintf.amd.com/vcek/v1/Turin/cert_chain
	//go:embed ask_ark_turin_vlek.pem
	AskArkTurinVlekBytes []byte

	// A cache of product certificate KDS results per product.
	prodCacheMu          sync.RWMutex
	productLineCertCache map[string]*ProductCerts
)

// Communication with AMD suggests repeat requests of the same arguments will
// be throttled to once per 10 seconds.
const initialDelay = 10 * time.Second

// ProductCerts contains the root key and signing key devoted to a given product line.
type ProductCerts struct {
	Ask  *x509.Certificate
	Asvk *x509.Certificate
	Ark  *x509.Certificate
}

// AMDRootCerts encapsulates the certificates that represent root of trust in AMD.
type AMDRootCerts struct {
	// Product is the expected CPU product line, e.g., Milan, Turin, Genoa.
	//
	// Deprecated: Use ProductLine.
	Product string
	// Product is the expected CPU product line, e.g., Milan, Turin, Genoa.
	ProductLine string
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

// GetProductLine returns the product line the certificate chain is associated with.
func (r *AMDRootCerts) GetProductLine() string {
	if r.ProductLine != "" {
		return r.ProductLine
	}
	return r.Product
}

// AMDRootCertsProduct returns a new *AMDRootCerts for a given product line.
func AMDRootCertsProduct(productLine string) *AMDRootCerts {
	return &AMDRootCerts{
		Product:     productLine, // TODO(Issue#114): Remove,
		ProductLine: productLine,
	}
}

// HTTPSGetter represents the ability to fetch data from the internet from an HTTP URL.
// Used particularly for fetching certificates.
type HTTPSGetter interface {
	Get(url string) ([]byte, error)
}

// ContextHTTPSGetter is an HTTPSGetter that accepts a context.Context.
type ContextHTTPSGetter interface {
	GetContext(ctx context.Context, url string) ([]byte, error)
}

// GetWith gets a resource from a URL using an HTTPSGetter.
// If the HTTPSGetter implements ContextHTTPSGetter, the GetContext method will be used.
func GetWith(ctx context.Context, getter HTTPSGetter, url string) ([]byte, error) {
	if contextGetter, ok := getter.(ContextHTTPSGetter); ok {
		return contextGetter.GetContext(ctx, url)
	}
	return getter.Get(url)
}

// AttestationRecreationErr represents a problem with fetching or interpreting associated
// certificates for a given attestation report. This is typically due to network unreliability.
type AttestationRecreationErr struct {
	Msg string
}

func (e *AttestationRecreationErr) Error() string {
	return e.Msg
}

// defaultMaxResponseBytes is the response body limit when SimpleHTTPSGetter.MaxResponseBytes
// is zero. AMD KDS responses are much smaller: a VCEK certificate is about 1.5 KiB and a
// certificate chain is about 4 KiB.
const defaultMaxResponseBytes = 1 << 20

// SimpleHTTPSGetter implements the HTTPSGetter interface with http.Get.
type SimpleHTTPSGetter struct {
	// MaxResponseBytes is the largest response body that Get accepts. If zero, the limit
	// is 1 MiB.
	MaxResponseBytes int64
}

// errResponseTooLarge is returned when a response body exceeds the MaxResponseBytes limit.
var errResponseTooLarge = errors.New("response body too large")

// HTTPStatusError is returned by SimpleHTTPSGetter when the server responds with a status code
// outside the 2xx range.
type HTTPStatusError struct {
	// URL is the URL that was requested.
	URL string
	// StatusCode is the HTTP status code of the response.
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("failed to retrieve '%s' status %d", e.URL, e.StatusCode)
}

// Get uses http.Get to return the HTTPS response body as a byte array.
func (n *SimpleHTTPSGetter) Get(url string) ([]byte, error) {
	return n.GetContext(context.TODO(), url)
}

// GetContext behaves like get, but forwards the context to the http package.
// It returns an *HTTPStatusError for a non-2xx response, and an error for a response body
// larger than n.MaxResponseBytes.
func (n *SimpleHTTPSGetter) GetContext(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPStatusError{URL: url, StatusCode: resp.StatusCode}
	}

	limit := n.MaxResponseBytes
	if limit == 0 {
		limit = defaultMaxResponseBytes
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("failed to retrieve '%s': %w: more than %d bytes", url, errResponseTooLarge, limit)
	}
	return body, nil
}

// RetryHTTPSGetter is a meta-HTTPS getter that will retry on failure a given number of times.
//
// It retries only errors that can succeed later: an *HTTPStatusError with status 429 (Too Many
// Requests) or 5xx, and errors that are not an HTTP status, such as network errors. It returns
// immediately for other HTTP statuses (for example 404 for an unknown chip ID), for a response
// body that is too large, and for context cancellation or deadline errors.
type RetryHTTPSGetter struct {
	// Timeout is how long to retry before failure.
	// If Timeout is zero, the Get method will retry indefinitely and the GetContext method will
	// retry until the input context expires.
	Timeout time.Duration
	// MaxRetryDelay is the maximum amount of time to wait between retries.
	MaxRetryDelay time.Duration
	// Getter is the non-retrying way of getting a URL.
	Getter HTTPSGetter
}

// isRetryable reports whether a later request can succeed after err.
func isRetryable(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	if errors.Is(err, errResponseTooLarge) {
		return false
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		return statusErr.StatusCode == http.StatusTooManyRequests || statusErr.StatusCode >= 500
	}
	return true
}

// Get fetches the body of the URL, retrying a given amount of times on failure.
func (n *RetryHTTPSGetter) Get(url string) ([]byte, error) {
	return n.GetContext(context.TODO(), url)
}

// GetContext behaves like get, but forwards the context to the Getter and stops retrying when the
// context expired. It stops retrying immediately on an error that cannot succeed later; see
// RetryHTTPSGetter.
func (n *RetryHTTPSGetter) GetContext(ctx context.Context, url string) ([]byte, error) {
	delay := initialDelay
	cancel := func() {}
	if n.Timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, n.Timeout)
	}
	var returnedError error
	for {
		body, err := GetWith(ctx, n.Getter, url)
		if err == nil {
			cancel()
			return body, nil
		}
		returnedError = multierr.Append(returnedError, err)
		if !isRetryable(err) {
			cancel()
			return nil, returnedError
		}
		delay = delay + delay
		if delay > n.MaxRetryDelay {
			delay = n.MaxRetryDelay
		}
		select {
		case <-ctx.Done():
			cancel()
			return nil, multierr.Append(returnedError, ctx.Err())
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
		return fmt.Errorf("could not parse intermediate ASK certificate in SEV certificate format: %v", err)
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

// Decode populates the ProductCerts from DER-formatted certificates for both the AS[V]K and the ARK.
func (r *ProductCerts) Decode(ask []byte, ark []byte) error {
	ica, err := ParseCert(ask)
	if err != nil {
		return fmt.Errorf("could not parse intermediate certificate: %v", err)
	}
	if strings.HasPrefix(ica.Subject.CommonName, "SEV-VLEK") {
		r.Asvk = ica
	} else {
		r.Ask = ica
	}

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

// X509Options returns the AS[V]K and ARK as the only intermediate and root certificates of an x509
// verification options object, or nil if either key's x509 certificate is not present in r.
// The choice between ASK and ASVK is determined bey key.
func (r *ProductCerts) X509Options(now time.Time, key abi.ReportSigner) *x509.VerifyOptions {
	if r.Ark == nil {
		return nil
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.Ark)
	intermediates := x509.NewCertPool()
	switch key {
	case abi.VcekReportSigner:
		if r.Ask == nil {
			return nil
		}
		intermediates.AddCert(r.Ask)
	case abi.VlekReportSigner:
		if r.Asvk == nil {
			return nil
		}
		intermediates.AddCert(r.Asvk)
	}
	return &x509.VerifyOptions{Roots: roots, Intermediates: intermediates, CurrentTime: now}
}

// ClearProductCertCache clears the product certificate cache. This is useful for testing with
// multiple roots of trust.
func ClearProductCertCache() {
	prodCacheMu.Lock()
	productLineCertCache = nil
	prodCacheMu.Unlock()
}

// GetProductChain returns the ASK and ARK certificates of the given product line, either from getter
// or from a cache of the results from the last successful call.
func GetProductChain(productLine string, s abi.ReportSigner, getter HTTPSGetter) (*ProductCerts, error) {
	return GetProductChainContext(context.TODO(), productLine, s, getter)
}

// GetProductChainContext behaves like GetProductChain but forwards the context to the HTTPSGetter.
func GetProductChainContext(ctx context.Context, productLine string, s abi.ReportSigner, getter HTTPSGetter) (*ProductCerts, error) {
	ensureCache()

	prodCacheMu.RLock()
	result, ok := productLineCertCache[productLine]
	prodCacheMu.RUnlock()
	if !ok {
		askark, err := GetWith(ctx, getter, kds.ProductCertChainURL(s, productLine))
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
		productLineCertCache[productLine] = result
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

// X509Options returns the AS[V]K and ARK as the only intermediate and root certificates of an x509
// verification options object, or nil if either key's x509 certificate is not present in r.
// Choice between ASK and ASVK is determined by key.
func (r *AMDRootCerts) X509Options(now time.Time, key abi.ReportSigner) *x509.VerifyOptions {
	if r.ProductCerts == nil {
		return nil
	}
	return r.ProductCerts.X509Options(now, key)
}

// Parse ASK, ARK certificates from the embedded AMD certificate file.
func init() {
	milanCerts := new(AMDRootCerts)
	if err := milanCerts.FromKDSCertBytes(AskArkMilanVcekBytes); err != nil {
		panic(err)
	}
	milanCerts.ProductLine = "Milan"
	genoaCerts := new(AMDRootCerts)
	if err := genoaCerts.FromKDSCertBytes(AskArkGenoaVcekBytes); err != nil {
		panic(err)
	}
	genoaCerts.ProductLine = "Genoa"
	turinCerts := new(AMDRootCerts)
	turinCerts.ProductLine = "Turin"
	if err := turinCerts.FromKDSCertBytes(AskArkTurinVcekBytes); err != nil {
		panic(err)
	}
	DefaultRootCerts = map[string]*AMDRootCerts{
		"Milan": milanCerts,
		"Genoa": genoaCerts,
		"Turin": turinCerts,
	}
}

func ensureCache() {
	prodCacheMu.RLock()
	if productLineCertCache == nil {
		prodCacheMu.RUnlock()

		prodCacheMu.Lock()
		productLineCertCache = make(map[string]*ProductCerts)
		prodCacheMu.Unlock()
	} else {
		prodCacheMu.RUnlock()
	}
}

// GetDefaultRootCerts returns a safe copy of the official default trusted roots.
// This prevents external validation logic from accidentally mutating the global static trust store.
func GetDefaultRootCerts(productLine string) (*AMDRootCerts, error) {
	defaultRoot, ok := DefaultRootCerts[productLine]
	if !ok || defaultRoot == nil {
		return nil, fmt.Errorf("no embedded roots available for product line: %q", productLine)
	}

	// Perform a shallow copy to protect the global variables from being mutated.
	// We trust that the Ask and Ark here are the authentic AMD official certificates.
	safeClone := &AMDRootCerts{
		ProductLine:  defaultRoot.ProductLine,
		ProductCerts: defaultRoot.ProductCerts,
	}

	return safeClone, nil
}
