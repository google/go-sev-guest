# SEV Guest

This project offers libraries for a simple wrapper around the `/dev/sev-guest`
device in Linux, as well as a library for attestation verification of
fundamental components of an attestation report.

This project is split into two complementary roles. The first role is producing
an attestation report, and the second is checking an attestation report.  The
`client` library produces reports, the `verify` library verifies reports'
signatures and key certificates, and the `validate` library checks non-signature
report fields against a user-provided policy.

## `client`

This library should be used within the confidential workload to collect an
attestation report along with requisite certificates.

Your main interactions with it will be to open the device, get an attestation
report with your provided 64 bytes of user data (typically a nonce or a hash of
a public key), and then close the device. For convenience, the attestation with
its associated certificates can be collected in a wire-transmittable protocol
buffer format.

### `func OpenDevice() (*LinuxDevice, error)`

This function creates a file descriptor to the `/dev/sev-guest` device and
returns an object that has methods encapsulating commands to the device. When
done, remember to `Close()` the device.

### `func GetExtendedReport(d Device, reportData [64]byte) (*pb.Attestation, error)`

This function takes an object implementing the `Device` interface (e.g., a
`LinuxDevice`) and returns the protocol buffer representation of the attestation
report and associated certificates. The report will be associated with VM
privilege level 0. You can provide a different privilege level as the third
argument to `GetExtendedReportAtVmpl`.

You can use `GetRawExtendedReport` or `GetRawExtendedReportAtVmpl` to get the
AMD SEV-SNP API formatted report and certificate table, or just `GetReport`,
`GetReportAtVmpl`, `GetRawReport`, or `GetRawReportAtVmpl` to avoid fetching the
certificate table.

### `func GetDerivedKeyAcknowledgingItsLimitations(d Device, request *SnpDerivedKeyReq) ([]byte, error)`

This function uses the `/dev/sev-guest` command for requesting a key derived
from data that is measured at VM launch time, with the additional ability to
continue to generate the same key as at earlier TCB and GuestSVN values.

This function's name is selected to discourage its use in a Cloud setting. See
[LIMITATIONS.md](LIMITATIONS.md).

### `func (d Device) Close() error`

Closes the device.

## `verify`

This library will check the signature and basic well-formedness properties of an
attestation report and certificate chain. The requirements for report
well-formedness comes from the AMD SEV-SNP API specification, and the
requirements for certificate well-formedness come from the AMD Key Distribution
Service (KDS) specification.

This library embeds AMD's root and SEV intermediate keys
([AMD source](https://download.amd.com/developer/eula/sev/ask_ark_milan.cert))
for the
[KDS product_name=Milan cert_chain](https://kdsintf.amd.com/vcek/v1/Milan/cert_chain)
in the AMD SEV certificate format to cross check against any certificate chain
that it's sent. The SEV certificate format is defined in an appendix of the AMD
SEV API specification.

### `func SnpAttestation(attestation *spb.Attestation, options *Options) error`

This function verifies that the attestation has a valid signature and
certificate chain, and optionally checks the certificate revocation list (CRL).
At time of writing, the CRL is empty. From discussions with AMD, we expect the
CRL to never contain a VCEK or ARK, and only in a very rare circumstance contain
the ASK (intermediate signing key). The default option is to not check the CRL.

Example expected invocation:

```
verify.SnpAttestation(myAttestation, verify.DefaultOptions())
```

#### `Options` type

This type contains three fields:

*   `CheckRevocations bool`: if true, then `SnpAttestation` will download the
    certificate revocation list (CRL) and check for revocations.
*   `Getter HTTPSGetter`: must be non-`nil` if `CheckRevocations` is true.
*   `TrustedRoots map[string][]*AMDRootCerts`: if `nil`, uses the library's embedded certificates.
     Maps a product name to all allowed root certifications for that product (e.g., Milan).

The `HTTPSGetter` interface consists of a single method `Get(url string)
([]byte, error)` that should return the body of the HTTPS response.


#### `AMDRootCerts` type

This type has 6 fields, the first 3 of which are mandatory:

*   `Product string`: the name of the product this bundle is for (e.g., `"Milan"`).
*   `AskX509 *x509.Certificate`: an X.509 representation of the AMD SEV Signer intermediate key (ASK)'s certificate.
*   `ArkX509 *x509.Certificate`: an X.509 representation of the AMD SEV Root key (ARK)'s certificate.
*   `AskSev *abi.AskCert`: if non-`nil`, will cross-check with
    `AskX509`. Represents the information present in the AMD SEV certificate
    format for the ASK.
*   `ArkSev *abi.AskCert`: if non-`nil`, will cross-check with
    `ArkX509`. Represents the information present in the AMD SEV certificate
    format for the ARK.
*   `CRL *x509.RevocationList`: the certificate revocation list signed by the ARK.
    Will be populated if `SnpAttestation` is called with `CheckRevocations: true`.

## `validate`

This library checks fields of an attestation report according to a policy
provided by the user.  The policy is represented with the `Options` type, which
specifies which fields to check, what their exact values should be, or whether
the field should be within a given bound.

### `func SnpAttestation(attestation *spb.Attestation, options *Options) error`

Not to be confused with `verify.SnpAttestation` for checking certificates and
signatures, the `validate.SnpAttestation` function is more open-ended about what
reports are acceptable. It's up to the user of the library to set the parameters
of acceptable values with the `options` argument.

#### The `Option` type

An instance of the `Option` type is a simple validation policy for non-signature
fields of an attestation report.

The fields that either can be skipped or must match the given value exactly are:

*   `ReportData` for the `REPORT_DATA` field
*   `HostData` for the `HOST_DATA` field
*   `ImageID` for the `IMAGE_ID` field
*   `FamilyID` for the `FAMILY_ID` field
*   `ReportID` for the `FEPORT_ID` field
*   `ReportIDMA` for the `REPORT_ID_MA` field
*   `Measurement` for the `MEASUREMENT` field

The fields that provide a minimum acceptable value are:

*   `MinimumBuild` for the minimum build number for the AMD secure processor
    firmware.
*   `RequireAuthorKey` for whether `AUTHOR_KEY_EN` can be 0 or 1 (false), or
    just 1 (true).
*   `RequireIDBlock` for whether IDBlock fields can be anything (false) or must
    validate (true) against the `Trusted` family of options.

The fields that provide a maximum acceptable value are:

*   `GuestPolicy`: each true field of `GuestPolicy` is permission for an
    attestation report's `POLICY` corresponding bit to be set.
*   `PermitProvisionalFirmware`: if false, the minimum TCB and API values are
    equal to the reported values. If true, the maximum TCB and API values are
    the reported values.
*   `PlatformInfo`: each true field of `PlatformInfo` is permission for the
    attestation report's `PLATFORM_INFO` corresponding bit to be set.

Finally, the fields for trusting IDBlock signers. Both ID keys and Author keys
have x.509 certificate and SEV-SNP hash format inputs for usability. The x.509
certificates will be converted to their corresponding SEV-SNP API format and
appended to the corresponding `KeyHashes` array. Only certificates for ECSDA
P-384 public keys are considered. All other certificates are quietly ignored.

*   `TrustedAuthorKeys`: x.509 certificates for author keys that are trusted to
    endorse an attestation report. If the report's author key is trusted, then
    the identity key it signed is implicitly trusted.
*   `TrustedAuthorKeyHashes`: An array of SHA-384 hashes of the SEV-SNP API
    format for an ECDSA public key. Has the same validation behavior as
    `TrustedAuthorKeys`.
*   `TrustedIDKeys`: x.509 certificates for identity keys that are trusted to
    endorse an attestation report. If the report's identity key is explicitly
    trusted, then its author key does not need to be trusted.
*   `TrustedIDKeyHashes`: An array of SHA-384 hashes of the SEV-SNP API format
    for an ECDSA public key. Has the same validation behavior as
    `TrustedIDKeys`.

## License

go-sev-guest is released under the Apache 2.0 license.

```
Copyright 2022 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

## Links

*   [AMD SEV API specification](https://www.amd.com/system/files/TechDocs/55766_SEV-KM_API_Specification.pdf)
*   [AMD SEV-SNP API specification](https://www.amd.com/system/files/TechDocs/56860.pdf)
*   [AMD KDS specification](https://www.amd.com/system/files/TechDocs/57230.pdf)

## Disclaimers

This is not an officially supported Google product.
