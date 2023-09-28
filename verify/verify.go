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
	"fmt"
	"time"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	cpb "github.com/google/go-sev-guest/proto/check"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify/trust"
	"github.com/google/logger"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
)

const (
	askVersion      = 1
	askKeyUsage     = 0x13
	arkVersion      = 1
	arkKeyUsage     = 0x0
	askX509Version  = 3
	asvkX509Version = 3
	arkX509Version  = 3
)

var (
	// ErrMissingVlek is returned when attempting to verify a VLEK-signed report that doesn't also
	// have its VLEK certificate attached.
	ErrMissingVlek = errors.New("report signed with VLEK, but VLEK certificate is missing")
)

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
	return checkSingletonList(name.OrganizationalUnit, "organizational unit", "organizational uints", "Engineering")
}

func validateRootX509(product string, x *x509.Certificate, version int, role, cn string) error {
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
	return validateCRLlink(x, product, role)
}

// validateAskX509 checks expected metadata about the ASK X.509 certificate. It does not verify the
// cryptographic signatures.
func validateAskX509(r *trust.AMDRootCerts) error {
	if r == nil {
		r = trust.DefaultRootCerts["Milan"]
	}
	cn := intermediateKeyCommonName(r.Product, abi.VcekReportSigner)
	if err := validateRootX509(r.Product, r.ProductCerts.Ask, askX509Version, "ASK", cn); err != nil {
		return err
	}
	if r.AskSev != nil {
		return crossCheckSevX509(r.AskSev, r.ProductCerts.Ask)
	}
	return nil
}

func endorsementKeyCommonName(key abi.ReportSigner) string {
	return fmt.Sprintf("SEV-%v", key)
}

func intermediateKeyCommonName(product string, key abi.ReportSigner) string {
	if product != "" {
		switch key {
		case abi.VcekReportSigner:
			return fmt.Sprintf("SEV-%s", product)
		case abi.VlekReportSigner:
			return fmt.Sprintf("SEV-VLEK-%s", product)
		}
	}
	return ""
}

// validateAsvkX509 checks expected metadata about the ASVK X.509 certificate. It does not verify the
// cryptographic signatures.
func validateAsvkX509(r *trust.AMDRootCerts) error {
	if r == nil {
		r = trust.DefaultRootCerts["Milan"]
	}
	cn := intermediateKeyCommonName(r.Product, abi.VlekReportSigner)
	// There is no ASVK SEV ABI key released by AMD to cross-check.
	return validateRootX509(r.Product, r.ProductCerts.Asvk, asvkX509Version, "ASVK", cn)
}

// ValidateArkX509 checks expected metadata about the ARK X.509 certificate. It does not verify the
// cryptographic signatures.
func validateArkX509(r *trust.AMDRootCerts) error {
	if r == nil {
		r = trust.DefaultRootCerts["Milan"]
	}
	var cn string
	if r.Product != "" {
		cn = fmt.Sprintf("ARK-%s", r.Product)
	}
	if err := validateRootX509(r.Product, r.ProductCerts.Ark, arkX509Version, "ARK", cn); err != nil {
		return err
	}
	if r.ArkSev != nil {
		return crossCheckSevX509(r.ArkSev, r.ProductCerts.Ark)
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

// validateAskSev checks ASK SEV format certificate validity according to AMD SEV API Appendix B.3
// This covers steps 1, 2, and 5
func validateAskSev(r *trust.AMDRootCerts) error {
	if r == nil {
		r = trust.DefaultRootCerts["Milan"]
	}
	return validateRootSev(r.AskSev, r.ArkSev, askVersion, askKeyUsage, "ASK", "ARK")
}

// ValidateArkSev checks ARK certificate validity according to AMD SEV API Appendix B.3
// This covers steps 5, 6, 9, and 11.
func validateArkSev(r *trust.AMDRootCerts) error {
	if r == nil {
		r = trust.DefaultRootCerts["Milan"]
	}
	return validateRootSev(r.ArkSev, r.ArkSev, arkVersion, arkKeyUsage, "ARK", "ARK")
}

// validateX509 will validate the x509 certificates of the ASK, ASVK, and ARK.
func validateX509(r *trust.AMDRootCerts, key abi.ReportSigner) error {
	if err := validateArkX509(r); err != nil {
		return fmt.Errorf("ARK validation error: %v", err)
	}
	if r.ProductCerts.Ask == nil && key == abi.VcekReportSigner {
		return fmt.Errorf("trusted root must have ASK certificate for VCEK chain")
	}
	if r.ProductCerts.Asvk == nil && key == abi.VlekReportSigner {
		return fmt.Errorf("trusted root must have ASVK certificate for VLEK chain")
	}
	if r.ProductCerts.Ask != nil {
		if err := validateAskX509(r); err != nil {
			return fmt.Errorf("ASK validation error: %v", err)
		}
	}
	if r.ProductCerts.Asvk != nil {
		if err := validateAsvkX509(r); err != nil {
			return fmt.Errorf("ASVK validation error: %v", err)
		}
	}
	return nil
}

// validateKDSCertSubject checks KDS-specified values of the subject metadata of the AMD certificate.
func validateKDSCertSubject(subject pkix.Name, key abi.ReportSigner) error {
	if err := validateAmdLocation(subject, fmt.Sprintf("%v subject", key)); err != nil {
		return err
	}
	want := endorsementKeyCommonName(key)
	if subject.CommonName != want {
		return fmt.Errorf("%s certificate subject common name %v not expected. Expected %s", key, subject.CommonName, want)
	}
	return nil
}

// validateKDSCertIssuer checks KDS-specified values of the issuer metadata of the AMD certificate.
func validateKDSCertIssuer(r *trust.AMDRootCerts, issuer pkix.Name, key abi.ReportSigner) error {
	if err := validateAmdLocation(issuer, fmt.Sprintf("%v issuer", key)); err != nil {
		return err
	}
	cn := intermediateKeyCommonName(r.Product, key)
	if issuer.CommonName != cn {
		return fmt.Errorf("%s certificate issuer common name %v not expected. Expected %s", key, issuer.CommonName, cn)
	}
	return nil
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
func GetCrlAndCheckRoot(r *trust.AMDRootCerts, opts *Options) (*x509.RevocationList, error) {
	r.Mu.Lock()
	defer r.Mu.Unlock()
	getter := opts.Getter
	if getter == nil {
		getter = trust.DefaultHTTPSGetter()
	}
	if r.CRL != nil && opts.Now.Before(r.CRL.NextUpdate) {
		return r.CRL, nil
	}
	var errs error
	for _, url := range r.ProductCerts.Ask.CRLDistributionPoints {
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
		if err := verifyCRL(r); err != nil {
			return nil, err
		}
		return r.CRL, nil
	}
	return nil, CRLUnavailableErr{multierr.Append(errs, errors.New("could not fetch product CRL"))}
}

// verifyCRL checks that the VCEK CRL is signed by the ARK. Must be called after r.CRL is set and while
// r.Mu is held.
func verifyCRL(r *trust.AMDRootCerts) error {
	if r.CRL == nil {
		return errors.New("internal error: CRL not set")
	}
	if r.ProductCerts.Ark == nil {
		return errors.New("missing ARK x509 certificate to check CRL validity")
	}
	if r.ProductCerts.Ask == nil {
		return errors.New("missing ASK x509 certificate to check intermediate key validity")
	}
	if err := r.CRL.CheckSignatureFrom(r.ProductCerts.Ark); err != nil {
		return fmt.Errorf("CRL is not signed by ARK: %v", err)
	}
	for _, bad := range r.CRL.RevokedCertificates {
		if r.ProductCerts.Ask.SerialNumber.Cmp(bad.SerialNumber) == 0 {
			return fmt.Errorf("ASK was revoked at %v", bad.RevocationTime)
		}
		// From offline discussions with AMD, we don't expect them to ever explicitly revoke a VCEK
		// since TCB numbers serve the purpose of superceding previous certificates.
	}
	return nil
}

// VcekNotRevoked will consult the online CRL listed in the VCEK certificate for whether this cert
// has been revoked. Returns nil if not revoked, error on any problem.
func VcekNotRevoked(r *trust.AMDRootCerts, _ *x509.Certificate, options *Options) error {
	_, err := GetCrlAndCheckRoot(r, options)
	return err
}

// product is expected to be of form "Milan" or "Genoa".
// role is expected to be one of "ARK", "ASK", "ASVK".
func validateCRLlink(x *x509.Certificate, product, role string) error {
	url := kds.CrlLinkByRole(product, role)
	if len(x.CRLDistributionPoints) != 1 {
		return fmt.Errorf("%s has %d CRL distribution points, want 1", role, len(x.CRLDistributionPoints))
	}
	if x.CRLDistributionPoints[0] != url {
		return fmt.Errorf("%s CRL distribution point is '%s', want '%s'", role, x.CRLDistributionPoints[0], url)
	}
	return nil
}

// validateVcekExtensions checks if the certificate extensions match
// wellformedness expectations.
func validateExtensions(exts *kds.Extensions, key abi.ReportSigner) error {
	_, err := kds.ParseProductName(exts.ProductName, key)
	return err
}

// validateKDSCertificateProductNonspecific returns an error if the given certificate doesn't have
// the documented qualities of a V[CL]EK certificate according to Key Distribution Service
// documentation:
// https://www.amd.com/system/files/TechDocs/57230.pdf
// This does not check the certificate revocation list since that requires internet access.
// If valid, then returns the V[CL]EK-specific certificate extensions in the VcekExtensions type.
func validateKDSCertificateProductNonspecific(cert *x509.Certificate, key abi.ReportSigner) (*kds.Extensions, error) {
	if cert.Version != 3 {
		return nil, fmt.Errorf("%v certificate version is %v, expected 3", key, cert.Version)
	}
	// Signature algorithm: RSASSA-PSS
	// Signature hash algorithm sha384
	if cert.SignatureAlgorithm != x509.SHA384WithRSAPSS {
		return nil, fmt.Errorf("%v certificate signature algorithm is %v, expected SHA-384 with RSASSA-PSS", key, cert.SignatureAlgorithm)
	}
	// Subject Public Key Info ECDSA on curve P-384
	if cert.PublicKeyAlgorithm != x509.ECDSA {
		return nil, fmt.Errorf("%v certificate public key type is %v, expected ECDSA", key, cert.PublicKeyAlgorithm)
	}
	// Locally bind the public key any type to allow for occurrence typing in the switch statement.
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if pub.Curve.Params().Name != "P-384" {
			return nil, fmt.Errorf("%v certificate public key curve is %s, expected P-384", key, pub.Curve.Params().Name)
		}
	default:
		return nil, fmt.Errorf("%v certificate public key not ecdsa PublicKey type %v", key, pub)
	}

	if err := validateKDSCertSubject(cert.Subject, key); err != nil {
		return nil, err
	}
	exts, err := kds.CertificateExtensions(cert, key)
	if err != nil {
		return nil, err
	}
	if err := validateExtensions(exts, key); err != nil {
		return nil, err
	}
	return exts, nil
}

func validateKDSCertificateProductSpecifics(r *trust.AMDRootCerts, cert *x509.Certificate, key abi.ReportSigner, opts *Options) error {
	if err := validateKDSCertIssuer(r, cert.Issuer, key); err != nil {
		return err
	}
	// ica: Intermediate Certificate Authority.
	ica := r.ProductCerts.Ask
	if key == abi.VlekReportSigner {
		ica = r.ProductCerts.Asvk
	}
	if ica == nil {
		return fmt.Errorf("root of trust missing intermediate certificate authority certificate for key %v", key)
	}
	verifyOpts := r.X509Options(opts.Now, key)
	if verifyOpts == nil {
		return fmt.Errorf("internal error: could not get X509 options for %v (missing ARK cert or ICA cert)", key)
	}
	if _, err := cert.Verify(*verifyOpts); err != nil {
		return fmt.Errorf("error verifying %v certificate: %v (%v)", key, err, ica.IsCA)
	}
	// VCEK is not expected to have a CRL link.
	return nil
}

func checkProductName(got, want *spb.SevProduct, key abi.ReportSigner) error {
	// No constraint
	if want == nil {
		return nil
	}
	if got == nil {
		return fmt.Errorf("internal error: no product name")
	}
	if got.Name != want.Name {
		return fmt.Errorf("%v cert product name %v is not %v", key, got, want)
	}
	// The model stepping number is only part of the VLEK product name, not VLEK's.
	if key == abi.VcekReportSigner && got.Stepping != want.Stepping {
		return fmt.Errorf("%v cert product stepping number %02X is not %02X",
			key, got.Stepping, want.Stepping)
	}
	return nil
}

// decodeCerts checks that the V[CL]EK certificate matches expected fields
// from the KDS specification and also that its certificate chain matches
// hardcoded trusted root certificates from AMD.
func decodeCerts(chain *spb.CertificateChain, key abi.ReportSigner, options *Options) (*x509.Certificate, *trust.AMDRootCerts, error) {
	var ek []byte
	switch key {
	case abi.VcekReportSigner:
		ek = chain.GetVcekCert()
	case abi.VlekReportSigner:
		ek = chain.GetVlekCert()
	}
	endorsementKeyCert, err := trust.ParseCert(ek)
	if err != nil {
		return nil, nil, fmt.Errorf("could not interpret %v DER bytes: %v", key, err)
	}
	exts, err := validateKDSCertificateProductNonspecific(endorsementKeyCert, key)
	if err != nil {
		return nil, nil, err
	}
	roots := options.TrustedRoots

	product, err := kds.ParseProductName(exts.ProductName, key)
	if err != nil {
		return nil, nil, err
	}

	productName := kds.ProductString(product)
	// Ensure the extension product info matches expectations.
	if err := checkProductName(product, options.Product, key); err != nil {
		return nil, nil, err
	}
	if len(roots) == 0 {
		logger.Warning("Using embedded AMD certificates for SEV-SNP attestation root of trust")
		root := &trust.AMDRootCerts{
			Product: productName,
			// Require that the root matches embedded root certs.
			AskSev: trust.DefaultRootCerts[productName].AskSev,
			ArkSev: trust.DefaultRootCerts[productName].ArkSev,
		}
		if err := root.Decode(chain.GetAskCert(), chain.GetArkCert()); err != nil {
			return nil, nil, err
		}
		if err := validateX509(root, key); err != nil {
			return nil, nil, err
		}
		roots = map[string][]*trust.AMDRootCerts{
			productName: {root},
		}
	}
	var lastErr error
	for _, productRoot := range roots[productName] {
		if err := validateKDSCertificateProductSpecifics(productRoot, endorsementKeyCert, key, options); err != nil {
			lastErr = err
			continue
		}
		return endorsementKeyCert, productRoot, nil
	}
	return nil, nil, fmt.Errorf("%v could not be verified by any trusted roots. Last error: %v", key, lastErr)
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
	Getter trust.HTTPSGetter
	// Now is the time at which to verify the validity of certificates. If unset, uses time.Now().
	Now time.Time
	// TrustedRoots specifies the ARK and ASK certificates to trust when checking the VCEK. If nil,
	// then verification will fall back on embedded AMD-published root certificates.
	// Maps the product name to an array of allowed roots.
	TrustedRoots map[string][]*trust.AMDRootCerts
	// Product is a forced value for the attestation product name when verifying or retrieving
	// VCEK certificates. An attestation should carry the product of the reporting
	// machine.
	Product *spb.SevProduct
}

// DefaultOptions returns a useful default verification option setting
func DefaultOptions() *Options {
	return &Options{
		Getter: trust.DefaultHTTPSGetter(),
		Now:    time.Now(),
	}
}

func getTrustedRoots(rot *cpb.RootOfTrust) (map[string][]*trust.AMDRootCerts, error) {
	result := map[string][]*trust.AMDRootCerts{}
	for _, path := range rot.CabundlePaths {
		root := &trust.AMDRootCerts{Product: rot.Product}
		if err := root.FromKDSCert(path); err != nil {
			return nil, fmt.Errorf("could not parse CA bundle %q: %v", path, err)
		}
		result[rot.Product] = append(result[rot.Product], root)
	}
	for _, cabundle := range rot.Cabundles {
		root := &trust.AMDRootCerts{Product: rot.Product}
		if err := root.FromKDSCertBytes([]byte(cabundle)); err != nil {
			return nil, fmt.Errorf("could not parse CA bundle bytes: %v", err)
		}
		result[rot.Product] = append(result[rot.Product], root)
	}
	return result, nil
}

// RootOfTrustToOptions translates the RootOfTrust message into the Options type needed
// for driving an attestation verification.
func RootOfTrustToOptions(rot *cpb.RootOfTrust) (*Options, error) {
	trustedRoots, err := getTrustedRoots(rot)
	if err != nil {
		return nil, err
	}
	return &Options{
		CheckRevocations:    rot.CheckCrl,
		DisableCertFetching: rot.DisallowNetwork,
		TrustedRoots:        trustedRoots,
	}, nil
}

// SnpAttestation verifies the protobuf representation of an attestation report's signature based
// on the report's SignatureAlgo, provided the certificate chain is valid.
func SnpAttestation(attestation *spb.Attestation, options *Options) error {
	if options == nil {
		return fmt.Errorf("options cannot be nil")
	}
	if attestation == nil {
		return fmt.Errorf("attestation cannot be nil")
	}
	// Make sure we have the whole certificate chain, or at least the product
	// info.
	if err := fillInAttestation(attestation, options); err != nil {
		return err
	}
	// Pass along the expected product information for VcekDER. fillInAttestation will ensure
	// that this is a noop if options.Product began as non-nil.
	options.Product = attestation.Product

	report := attestation.GetReport()
	info, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return err
	}
	chain := attestation.GetCertificateChain()
	endorsementKeyCert, root, err := decodeCerts(chain, info.SigningKey, options)
	if err != nil {
		return err
	}
	if options != nil && options.CheckRevocations {
		if err := VcekNotRevoked(root, endorsementKeyCert, options); err != nil {
			return err
		}
	}
	return SnpProtoReportSignature(report, endorsementKeyCert)
}

// fillInAttestation uses AMD's KDS to populate any empty certificate field in the attestation's
// certificate chain.
func fillInAttestation(attestation *spb.Attestation, options *Options) error {
	var productOverridden bool
	if options.Product != nil {
		attestation.Product = options.Product
		productOverridden = true
	} else if attestation.Product == nil {
		attestation.Product = abi.DefaultSevProduct()
		productOverridden = true
	}
	if options.DisableCertFetching {
		return nil
	}
	product := kds.ProductString(options.Product)
	getter := options.Getter
	if getter == nil {
		getter = trust.DefaultHTTPSGetter()
	}
	report := attestation.GetReport()
	info, err := abi.ParseSignerInfo(report.GetSignerInfo())
	if err != nil {
		return err
	}
	chain := attestation.GetCertificateChain()
	if chain == nil {
		chain = &spb.CertificateChain{}
		attestation.CertificateChain = chain
	}
	if len(chain.GetAskCert()) == 0 || len(chain.GetArkCert()) == 0 {
		askark, err := trust.GetProductChain(product, info.SigningKey, getter)
		if err != nil {
			return err
		}

		if len(chain.GetAskCert()) == 0 {
			chain.AskCert = askark.Ask.Raw
		}
		if len(chain.GetArkCert()) == 0 {
			chain.ArkCert = askark.Ark.Raw
		}
	}
	switch info.SigningKey {
	case abi.VcekReportSigner:
		if len(chain.GetVcekCert()) == 0 {
			vcekURL := kds.VCEKCertURL(product, report.GetChipId(), kds.TCBVersion(report.GetReportedTcb()))
			vcek, err := getter.Get(vcekURL)
			if err != nil {
				return &trust.AttestationRecreationErr{
					Msg: fmt.Sprintf("could not download VCEK certificate: %v", err),
				}
			}
			chain.VcekCert = vcek
			if productOverridden {
				cert, err := x509.ParseCertificate(vcek)
				if err != nil {
					return err
				}
				exts, err := kds.VcekCertificateExtensions(cert)
				if err != nil {
					return err
				}
				attestation.Product, err = kds.ParseProductName(exts.ProductName, abi.VcekReportSigner)
				if err != nil {
					return err
				}
			}
		}
	case abi.VlekReportSigner:
		// We can't lazily ask KDS for the certificate as a user. The CSP must cache their provisioned
		// certificates and provide them in GET_EXT_REPORT.
		if len(chain.GetVlekCert()) == 0 {
			return ErrMissingVlek
		}
	}
	return nil
}

// GetAttestationFromReport uses AMD's Key Distribution Service (KDS) to download the certificate
// chain for the VCEK that supposedly signed the given report, and returns the Attestation
// representation of their combination. If getter is nil, uses Golang's http.Get.
func GetAttestationFromReport(report *spb.Report, options *Options) (*spb.Attestation, error) {
	result := &spb.Attestation{
		Report:           report,
		CertificateChain: &spb.CertificateChain{},
	}
	if err := fillInAttestation(result, options); err != nil {
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
	attestation, err := GetAttestationFromReport(report, options)
	if err != nil {
		return fmt.Errorf("could not recreate attestation from report: %w", err)
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
