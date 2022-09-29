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

// Package verify includes logic and embedded AMD keys to check attestation report signatures.
package verify

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

var (
	// The ASK and ARK certificates are embedded since they do not have an expiration date. The KDS
	// documents them having a lifetime of 25 years. The X.509 certificate that this cert's signature
	// is over cannot be reconstructed from the SEV certificate format. The X.509 certificate with its
	// expiration dates is at https://kdsintf.amd.com/vcek/v1/Milan/cert_chain
	//go:embed data/ask_ark_milan.sevcert
	askArkMilanBytes []byte
)

const (
	askVersion     = 1
	askKeyUsage    = 0x13
	arkVersion     = 1
	arkKeyUsage    = 0x0
	askX509Version = 3
	arkX509Version = 3
)

// The VCEK productName in includes the specific silicon stepping
// corresponding to the supplied hwID. For example, “Milan-B0”.
// The product should inform what product keys we expect the key to be certified by.
var vcekProductMap = map[string]string{
	"Milan-B0": "Milan",
}

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
	// Protects concurrent updates to CRL.
	mu sync.Mutex
	// CRL is the certificate revocation list for this AMD product. Populated once, only when a
	// revocation is checked.
	CRL *x509.RevocationList
}

// DefaultRootCerts holds AMD's SEV API certificate format for ASK and ARK keys as published here
// https://developer.amd.com/wp-content/resources/ask_ark_milan.cert
var DefaultRootCerts map[string]*AMDRootCerts

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
		glog.Errorf("could not parse ARK certificate: %v", err)
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

func askVerifiedBy(signee, signer *abi.AskCert, signeeName, signerName string) error {
	if !uuid.Equal(signee.CertifyingID[:], signer.KeyID[:]) {
		return fmt.Errorf("%s's certifying ID (%s) is not %s's key ID (%s) ",
			signeeName, signerName, signee.CertifyingID.String(), signer.KeyID.String())
	}
	// The signatures in the AskCert format cannot be verified. The signed contents are an x509
	// certificate with additional metadata that are not reconstructible from the sevcert file.
	return nil
}

func askCertPubKey(cert *abi.AskCert) (*rsa.PublicKey, error) {
	var result rsa.PublicKey
	result.N = abi.AmdBigInt(cert.Modulus)
	exponent := abi.AmdBigInt(cert.PubExp)
	if !exponent.IsInt64() {
		return nil, fmt.Errorf("AMD certificate public key exponent too large %s", exponent.String())
	}
	result.E = int(exponent.Int64())
	return &result, nil
}

func crossCheckSevX509(sev *abi.AskCert, x *x509.Certificate) error {
	// The cross-check is only meaningful if there's more than the X.509 certificates to trust.
	if sev == nil {
		return nil
	}
	// Perform a cross-check between the X.509 and AMD SEV format certificates.
	switch pub := x.PublicKey.(type) {
	case *rsa.PublicKey:
		certPub, err := askCertPubKey(sev)
		if err != nil {
			return err
		}
		if !pub.Equal(certPub) {
			return fmt.Errorf("cross-check failed: SEV cert public key (%v) not equal to X.509 public key (%v)", pub, certPub)
		}
	default:
		return fmt.Errorf("product public key not RSA: %v", x.PublicKey)
	}
	return nil
}

// Check the expected metadata as documented in AMD's KDS specification
// https://www.amd.com/system/files/TechDocs/57230.pdf
func validateAmdLocation(name pkix.Name, role string) error {
	checkSingletonList := func(l []string, name, names, value string) error {
		if len(l) != 1 {
			return fmt.Errorf("%s has %d %s, want 1", role, len(l), names)
		}
		if l[0] != value {
			return fmt.Errorf("%s %s '%s' not expected for AMD. Expected '%s'", role, name, l[0], value)
		}
		return nil
	}
	if err := checkSingletonList(name.Country, "country", "countries", "US"); err != nil {
		return err
	}
	if err := checkSingletonList(name.Locality, "locality", "localities", "Santa Clara"); err != nil {
		return err
	}
	if err := checkSingletonList(name.Province, "state", "states", "CA"); err != nil {
		return err
	}
	if err := checkSingletonList(name.Organization, "organization", "organizations", "Advanced Micro Devices"); err != nil {
		return err
	}
	if err := checkSingletonList(name.OrganizationalUnit, "organizational unit", "organizational uints", "Engineering"); err != nil {
		return err
	}
	return nil
}

func validateCRLlink(x *x509.Certificate, product, role string) error {
	url := fmt.Sprintf("https://kdsintf.amd.com/vcek/v1/%s/crl", product)
	if len(x.CRLDistributionPoints) != 1 {
		return fmt.Errorf("%s has %d CRL distribution points, want 1", role, len(x.CRLDistributionPoints))
	}
	if x.CRLDistributionPoints[0] != url {
		return fmt.Errorf("%s CRL distribution point is '%s', want '%s'", role, x.CRLDistributionPoints[0], url)
	}
	return nil
}

func (r *AMDRootCerts) validateRootX509(x *x509.Certificate, version int, role, cn string) error {
	// Additionally check that the X.509 cert's public key matches the SEV format cert.
	if x == nil {
		return fmt.Errorf("no X.509 certificate for %s", role)
	}
	if x.Version != version {
		return fmt.Errorf("%s certificate version: %d. Expected %d", role, x.Version, version)
	}
	if err := validateAmdLocation(x.Issuer, fmt.Sprintf("%s issuer", role)); err != nil {
		return err
	}
	if err := validateAmdLocation(x.Subject, fmt.Sprintf("%s subject", role)); err != nil {
		return err
	}
	// Only check product name if it's specified.
	if cn != "" && x.Subject.CommonName != cn {
		return fmt.Errorf("%s common-name is %s. Expected %s", role, x.Subject.CommonName, cn)
	}
	return validateCRLlink(x, r.Product, role)
}

// ValidateAskX509 checks expected metadata about the ASK X.509 certificate. It does not verify the
// cryptographic signatures.
func (r *AMDRootCerts) ValidateAskX509() error {
	if r == nil {
		r = DefaultRootCerts["Milan"]
	}
	var cn string
	if r.Product != "" {
		cn = fmt.Sprintf("SEV-%s", r.Product)
	}
	if err := r.validateRootX509(r.AskX509, askX509Version, "ASK", cn); err != nil {
		return err
	}
	if r.AskSev != nil {
		return crossCheckSevX509(r.AskSev, r.AskX509)
	}
	return nil
}

// ValidateArkX509 checks expected metadata about the ARK X.509 certificate. It does not verify the
// cryptographic signatures.
func (r *AMDRootCerts) ValidateArkX509() error {
	if r == nil {
		r = DefaultRootCerts["Milan"]
	}
	var cn string
	if r.Product != "" {
		cn = fmt.Sprintf("ARK-%s", r.Product)
	}
	if err := r.validateRootX509(r.ArkX509, arkX509Version, "ARK", cn); err != nil {
		return err
	}
	if r.ArkSev != nil {
		return crossCheckSevX509(r.ArkSev, r.ArkX509)
	}
	return nil
}

// Checks some steps of AMD SEV API Appendix B.3
func validateRootSev(subject, issuer *abi.AskCert, version, keyUsage uint32, subjectRole, issuerRole string) error {
	// Step 1 or 5
	if subject.Version != version {
		return fmt.Errorf("%s AMD cert is version %d, expected %d", subjectRole, subject.Version, version)
	}
	// Step 2 or 6
	if subject.KeyUsage != keyUsage {
		return fmt.Errorf("%s certificate KeyUsage is 0x%x, should be 0x%x", subjectRole, subject.KeyUsage, keyUsage)
	}
	return askVerifiedBy(subject, issuer, subjectRole, issuerRole)
}

// ValidateAskSev checks ASK SEV format certificate validity according to AMD SEV API Appendix B.3
// This covers steps 1, 2, and 5
func (r *AMDRootCerts) ValidateAskSev() error {
	if r == nil {
		r = DefaultRootCerts["Milan"]
	}
	return validateRootSev(r.AskSev, r.ArkSev, askVersion, askKeyUsage, "ASK", "ARK")
}

// ValidateArkSev checks ARK certificate validity according to AMD SEV API Appendix B.3
// This covers steps 5, 6, 9, and 11.
func (r *AMDRootCerts) ValidateArkSev() error {
	if r == nil {
		r = DefaultRootCerts["Milan"]
	}
	return validateRootSev(r.ArkSev, r.ArkSev, arkVersion, arkKeyUsage, "ARK", "ARK")
}

// ValidateX509 will validate the x509 certificates of the ASK and ARK.
func (r *AMDRootCerts) ValidateX509() error {
	if err := r.ValidateArkX509(); err != nil {
		return fmt.Errorf("ARK validation error: %v", err)
	}
	if err := r.ValidateAskX509(); err != nil {
		return fmt.Errorf("ASK validation error: %v", err)
	}
	return nil
}

// ValidateVcekCertSubject checks KDS-specified values of the subject metadata of the AMD certificate.
func ValidateVcekCertSubject(subject pkix.Name) error {
	if err := validateAmdLocation(subject, "VCEK subject"); err != nil {
		return err
	}
	if subject.CommonName != "SEV-VCEK" {
		return fmt.Errorf("VCEK certificate subject common name %s not expected. Expected SEV-VCEK", subject.CommonName)
	}
	return nil
}

// ValidateVcekCertIssuer checks KDS-specified values of the issuer metadata of the AMD certificate.
func (r *AMDRootCerts) ValidateVcekCertIssuer(issuer pkix.Name) error {
	if err := validateAmdLocation(issuer, "VCEK issuer"); err != nil {
		return err
	}
	cn := fmt.Sprintf("SEV-%s", r.Product)
	if issuer.CommonName != cn {
		return fmt.Errorf("VCEK certificate issuer common name %s not expected. Expected %s", issuer.CommonName, cn)
	}
	return nil
}

// ValidateVcekExtensions checks if the certificate extensions match
// wellformedness expectations.
func ValidateVcekExtensions(exts *kds.VcekExtensions) error {
	if _, ok := vcekProductMap[exts.ProductName]; !ok {
		return fmt.Errorf("unknown VCEK product name: %v", exts.ProductName)
	}
	return nil
}

// validateVcekCertificateProductNonspecific returns an error if the given certificate doesn't have
// the documented qualities of a VCEK certificate according to Key Distribution Service
// documentation:
// https://www.amd.com/system/files/TechDocs/57230.pdf
// This does not check the certificate revocation list since that requires internet access.
// If valid, then returns the VCEK-specific certificate extensions in the VcekExtensions type.
func validateVcekCertificateProductNonspecific(cert *x509.Certificate) (*kds.VcekExtensions, error) {
	if cert.Version != 3 {
		return nil, fmt.Errorf("VCEK certificate version is %v, expected 3", cert.Version)
	}
	// Signature algorithm: RSASSA-PSS
	// Signature hash algorithm sha384
	if cert.SignatureAlgorithm != x509.SHA384WithRSAPSS {
		return nil, fmt.Errorf("VCEK certificate signature algorithm is %v, expected SHA-384 with RSASSA-PSS", cert.SignatureAlgorithm)
	}
	// Subject Public Key Info ECDSA on curve P-384
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("VCEK certificate public key type is %v, expected ECDSA", cert.PublicKeyAlgorithm)
	}
	// Locally bind the public key any type to allow for occurrence typing in the switch statement.
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().Name != "P-384" {
			return nil, fmt.Errorf("VCEK certificate public key curve is %s, expected P-384", pub.Curve.Params().Name)
		}
	default:
		return nil, fmt.Errorf("VCEK certificate public key not ecdsa PublicKey type %v", pub)
	}

	if err := ValidateVcekCertSubject(cert.Subject); err != nil {
		return nil, err
	}
	exts, err := kds.VcekCertificateExtensions(cert)
	if err != nil {
		return nil, err
	}
	if err := ValidateVcekExtensions(exts); err != nil {
		return nil, err
	}
	return exts, nil
}

func (r *AMDRootCerts) validateVcekCertificateProductSpecifics(cert *x509.Certificate) error {
	if err := r.ValidateVcekCertIssuer(cert.Issuer); err != nil {
		return err
	}
	if err := cert.CheckSignatureFrom(r.AskX509); err != nil {
		return fmt.Errorf("error verifying VCEK certificate: %v (%v)", err, r.AskX509.IsCA)
	}
	// VCEK is not expected to have a CRL link.
	return nil
}

// VcekDER checks that the VCEK certificate matches expected fields
// from the KDS specification and also that its certificate chain matches
// hardcoded trusted root certificates from AMD.
func VcekDER(vcek []byte, ask []byte, ark []byte, options *Options) (*x509.Certificate, *AMDRootCerts, error) {
	vcekCert, err := x509.ParseCertificate(vcek)
	if err != nil {
		return nil, nil, fmt.Errorf("could not interpret VCEK DER bytes: %v", err)
	}
	exts, err := validateVcekCertificateProductNonspecific(vcekCert)
	if err != nil {
		return nil, nil, err
	}
	roots := options.TrustedRoots
	product := vcekProductMap[exts.ProductName]
	if roots == nil {
		root := &AMDRootCerts{
			Product: product,
			// Require that the root matches embedded root certs.
			AskSev: DefaultRootCerts[product].AskSev,
			ArkSev: DefaultRootCerts[product].ArkSev,
		}
		if err := root.FromDER(ask, ark); err != nil {
			return nil, nil, err
		}
		if err := root.ValidateX509(); err != nil {
			return nil, nil, err
		}
		roots = map[string][]*AMDRootCerts{
			product: {root},
		}
	}
	var lastErr error
	for _, productRoot := range roots[product] {
		if err := productRoot.validateVcekCertificateProductSpecifics(vcekCert); err != nil {
			lastErr = err
			continue
		}
		return vcekCert, productRoot, nil
	}
	return nil, nil, fmt.Errorf("VCEK could not be verified by any trusted roots. Last error: %v", lastErr)
}

// SnpReportSignature verifies the attestation report's signature based on the report's
// SignatureAlgo.
func SnpReportSignature(report []byte, vcek *x509.Certificate) error {
	if err := abi.ValidateReportFormat(report); err != nil {
		return fmt.Errorf("attestation report format error: %v", err)
	}
	der, err := abi.ReportToSignatureDER(report)
	if err != nil {
		return fmt.Errorf("could not interpret report signature: %v", err)
	}
	if abi.SignatureAlgo(report) == abi.SignEcdsaP384Sha384 {
		if err := vcek.CheckSignature(x509.ECDSAWithSHA384, abi.SignedComponent(report), der); err != nil {
			return fmt.Errorf("report signature verification error: %v", err)
		}
		return nil
	}

	return fmt.Errorf("unknown SignatureAlgo: %d", abi.SignatureAlgo(report))
}

// SnpProtoReportSignature verifies the protobuf representation of an attestation report's signature
// based on the report's SignatureAlgo.
func SnpProtoReportSignature(report *spb.Report, vcek *x509.Certificate) error {
	raw, err := abi.ReportToAbiBytes(report)
	if err != nil {
		return fmt.Errorf("could not interpret report: %v", err)
	}
	return SnpReportSignature(raw, vcek)
}

// Options represents verification options for an SEV-SNP attestation report.
type Options struct {
	// CheckRevocations set to true if the verifier should retrieve the CRL from the network and check
	// if the VCEK or ASK have been revoked according to the ARK.
	CheckRevocations bool
	// DisableCertFetching set to true if SnpAttestation should not connect to the AMD KDS to fill in
	// any missing certificates in an attestation's certificate chain. Uses Getter if false.
	DisableCertFetching bool
	// Getter takes a URL and returns the body of its contents. By default uses http.Get and returns
	// the body.
	Getter HTTPSGetter
	// TrustedRoots specifies the ARK and ASK certificates to trust when checking the VCEK. If nil,
	// then verification will fall back on embedded AMD-published root certificates.
	// Maps the product name to an array of allowed roots.
	TrustedRoots map[string][]*AMDRootCerts
}

// SnpAttestation verifies the protobuf representation of an attestation report's signature based
// on the report's SignatureAlgo, provided the certificate chain is valid.
func SnpAttestation(attestation *spb.Attestation, options *Options) error {
	// Make sure we have the whole certificate chain if we're allowed.
	if !options.DisableCertFetching {
		if err := fillInAttestation(attestation, options.Getter); err != nil {
			return err
		}
	}
	chain := attestation.GetCertificateChain()
	vcek, root, err := VcekDER(chain.GetVcekCert(), chain.GetAskCert(), chain.GetArkCert(), options)
	if err != nil {
		return err
	}
	if options != nil && options.CheckRevocations {
		getter := options.Getter
		if getter == nil {
			getter = &SimpleHTTPSGetter{}
		}
		if err := root.VcekNotRevoked(getter, vcek); err != nil {
			return err
		}
	}
	return SnpProtoReportSignature(attestation.GetReport(), vcek)
}

// HTTPSGetter represents the ability to fetch data from the internet from an HTTP URL.
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
		return nil, errors.New("failed to retrieve CRL")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	return body, nil
}

// AttestationRecreationErr represents a problem with fetching or interpreting associated
// certificates for a given attestation report. This is typically due to network unreliability.
type AttestationRecreationErr struct {
	error
}

// fillInAttestation uses AMD's KDS to populate any empty certificate field in the attestation's
// certificate chain.
func fillInAttestation(attestation *spb.Attestation, getter HTTPSGetter) error {
	// TODO(Issue #11): Determine the product a report was fetched from, or make this an option.
	product := "Milan"
	if getter == nil {
		getter = &SimpleHTTPSGetter{}
	}
	report := attestation.GetReport()
	chain := attestation.GetCertificateChain()
	if len(chain.GetAskCert()) == 0 || len(chain.GetArkCert()) == 0 {
		askark, err := getter.Get(kds.ProductCertChainURL(product))
		if err != nil {
			return AttestationRecreationErr{fmt.Errorf("could not download ASK and ARK certificates: %v", err)}
		}
		ask, ark, err := kds.ParseProductCertChain(askark)
		if err != nil {
			// Treat a bad parse as a network error since it's likely due to an incomplete transfer.
			return AttestationRecreationErr{fmt.Errorf("could not parse root cert_chain: %v", err)}
		}
		if len(chain.GetAskCert()) == 0 {
			chain.AskCert = ask
		}
		if len(chain.GetArkCert()) == 0 {
			chain.ArkCert = ark
		}
	}
	if len(chain.GetVcekCert()) == 0 {
		vcekURL := kds.VCEKCertURL(product, report.GetChipId(), kds.TCBVersion(report.GetCurrentTcb()))
		vcek, err := getter.Get(vcekURL)
		if err != nil {
			return AttestationRecreationErr{fmt.Errorf("could not download VCEK certificate: %v", err)}
		}
		chain.VcekCert = vcek
	}
	return nil
}

// GetAttestationFromReport uses AMD's Key Distribution Service (KDS) to download the certificate
// chain for the VCEK that supposedly signed the given report, and returns the Attestation
// representation of their combination. If getter is nil, uses Golang's http.Get.
func GetAttestationFromReport(report *spb.Report, getter HTTPSGetter) (*spb.Attestation, error) {
	result := &spb.Attestation{
		Report:           report,
		CertificateChain: &spb.CertificateChain{},
	}
	if err := fillInAttestation(result, getter); err != nil {
		return nil, err
	}
	return result, nil
}

// SnpReport verifies the protobuf representation of an attestation report's signature based
// on the report's SignatureAlgo and uses the AMD Key Distribution Service to download the
// report's corresponding VCEK certificate.
func SnpReport(report *spb.Report, options *Options) error {
	if options.DisableCertFetching {
		return errors.New("cannot verify attestation report without fetching certificates")
	}
	attestation, err := GetAttestationFromReport(report, options.Getter)
	if err != nil {
		return fmt.Errorf("could not recreate attestation from report: %v", err)
	}
	return SnpAttestation(attestation, options)
}

// RawSnpReport verifies the raw bytes representation of an attestation report's signature
// based on the report's SignatureAlgo and uses the AMD Key Distribution Service to download
// the report's corresponding VCEK certificate.
func RawSnpReport(rawReport []byte, options *Options) error {
	report, err := abi.ReportToProto(rawReport)
	if err != nil {
		return fmt.Errorf("could not interpret report bytes: %v", err)
	}
	return SnpReport(report, options)
}

// CRLUnavailableErr represents a problem with fetching the CRL from the network.
// This type is special to allow for easy "fail open" semantics for CRL unavailability. See
// Adam Langley's write-up on CRLs and network unreliability
// https://www.imperialviolet.org/2014/04/19/revchecking.html
type CRLUnavailableErr struct {
	error
}

// GetCrlAndCheckRoot downloads the given cert's CRL from one of the distribution points and
// verifies that the CRL is valid and doesn't revoke an intermediate key.
func (r *AMDRootCerts) GetCrlAndCheckRoot(getter HTTPSGetter) (*x509.RevocationList, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.CRL != nil && time.Now().Before(r.CRL.NextUpdate) {
		return r.CRL, nil
	}
	var errs error
	for _, url := range r.AskX509.CRLDistributionPoints {
		bytes, err := getter.Get(url)
		if err != nil {
			errs = multierr.Append(errs, err)
			continue
		}
		crl, err := x509.ParseRevocationList(bytes)
		if err != nil {
			errs = multierr.Append(errs, err)
			continue
		}
		r.CRL = crl
		if err := r.verifyCRL(); err != nil {
			return nil, err
		}
		return r.CRL, nil
	}
	return nil, CRLUnavailableErr{multierr.Append(errs, errors.New("could not fetch product CRL"))}
}

// verifyCRL checks that the VCEK CRL is signed by the ARK. Must be called after r.CRL is set.
func (r *AMDRootCerts) verifyCRL() error {
	if r.CRL == nil {
		return errors.New("internal error: CRL not set")
	}
	if r.ArkX509 == nil {
		return errors.New("missing ARK x509 certificate to check CRL validity")
	}
	if r.ArkX509 == nil {
		return errors.New("missing ASK x509 certificate to check intermediate key validity")
	}
	if err := r.CRL.CheckSignatureFrom(r.ArkX509); err != nil {
		return fmt.Errorf("CRL is not signed by ARK: %v", err)
	}
	for _, bad := range r.CRL.RevokedCertificates {
		if r.AskX509.SerialNumber.Cmp(bad.SerialNumber) == 0 {
			return fmt.Errorf("ASK was revoked at %v", bad.RevocationTime)
		}
		// From offline discussions with AMD, we don't expect them to ever explicitly revoke a VCEK
		// since TCB numbers serve the purpose of superceding previous certificates.
	}
	return nil
}

// VcekNotRevoked will consult the online CRL listed in the VCEK certificate for whether this cert
// has been revoked. Returns nil if not revoked, error on any problem.
func (r *AMDRootCerts) VcekNotRevoked(getter HTTPSGetter, cert *x509.Certificate) error {
	_, err := r.GetCrlAndCheckRoot(getter)
	return err
}
