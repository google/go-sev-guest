# `check` CLI tool

This binary is a thin wrapper around the `verify` and `validate` libraries to
check attestation reports against expectations.

The tool's input is an AMD SEV-SNP attestation report and associated certificates.

The tool's output an error or "Success".

## Usage

```
./check [options...]
```

### `-in`

This flag provides the path to the attestation file to check. Stdin is "-".

### `-inform`

The format that input takes. One of

*   `bin`: for raw binary. This is the attestation report immediately followed
    by the certificate table if there is one.
*   `proto`: A binary serialized `sevsnp.Attestation` message.
*   `textproto`: The `sevsnp.Attestation` message in textproto format.

Default value is `bin`.

### `quiet`

If set, doesn't write to stdout. All results are communicated through exit code.

### `config`

A path to a serialized `check.Config` protocol buffer message that represents
values for each of the following flags. If any flags are additionally provided,
they are interpreted to override the respective message field.

If the path ends in `.textproto`, the message is deserialized with as the
human-readable `prototext` format.

### `guest_policy`

The most acceptable policy component-wise in its SEV-SNP API 64-bit number
format.  "Most acceptable" means the minimum API major.minor version, if debug
is allowed, if singlesocket is required, if migrateMA is allowed, if SMT is
allowed.

### `report_data`

The expected exact `REPORT_DATA` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `host_data`

The expected exact `HOST_DATA` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `family_id`

The expected exact `FAMILY_ID` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `image_id`

The expected exact `IMAGE_ID` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `report_id`

The expected exact `REPORT_ID` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `report_id_ma`

The expected exact `REPORT_ID_MA` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `measurement`

The expected exact `MEASUREMENT` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `chip_id`

The expected exact `CHIP_ID` value as a hex-encoded string. Unchecked if
empty. Default empty.

### `-vmpl`

The expected VMPL value.

### `minimum_tcb`

The component-wise minimum TCB allowed for both the current, committed, and
reported TCB values. Default `0`.

### `minimum_launch_tcb`

The component-wise minimum TCB allowed for the launch TCB value. Default `0`.

### `provisional`

If true, allows reported values to be greater than or equal to than committed
values. Default `false`

### `platform_info`

The maximum acceptable `PLATFORM_INFO` field bit-wise. If empty, left
unchecked. Default empty.

### `require_author_key`

If true, requires the attestation report to have `AUTHOR_KEY_EN` set to 1. Will
also check `AUTHOR_KEY_DIGEST` against trusted author arguments. Implies
`require_idblock` is true.

### `require_idblock`

If true, checks that the `ID_KEY_DIGEST` is trusted, either directly against
trusted id key arguments, or if the author key is present and the author key is
trusted.

### `min_build`

The minimum value allowed for both `CURRENT_BUILD` and `COMMITTED_BUILD`.

### `min_version`

A `major.minor` version string that specifies the lexicographically minimum
values allowed for `{CURRENT,COMMITTED}_{MAJOR,MINOR}`.

### `trusted_author_keys`

A colon-separated list of paths to x.509 certificate files for trusted author
keys. Combined with `trusted_author_key_hashes`.

### `trusted_author_key_hashes`
 
A comma-separated list of hex-encoded strings for SHA384 digests of trusted
author keys in SEV API format. Combined with `trusted_author_keys`.

### `trusted_id_keys`

A colon-separated list of paths to x.509 certificate files for trusted id
keys. Combined with `trusted_id_key_hashes`.

### `trusted_id_key_hashes`

A comma-separated list of hex-encoded strings for SHA384 digests of trusted id
keys in SEV API format. Combined with `trusted_id_keys`.

### `product`

The name of the AMD product that produced the attestation report. Default
`Milan`.

### `product_key_path`

A colon-separated list of paths to CA bundles for the product. The expected
format of each file is a ASK certificate followed by ARK certificate both in
PEM format.

### `check_crl`

Download the root key's certificate revocation list and check if the product
signing key (ASK) has been revoked. Default `false`.

### `network`

Fetch missing files (certificates or CRL) through the network. Default `true`.

## Examples

For these examples, we use the `attest` tool to give clarity on the expected
format of the input report. The `attest` tool is not required for `check` to
work.

```shell
$ echo -n "The best nonce" | ./attest > attestation.bin
$ hexnonce=$(echo -n "The best nonce" | xxd -p)
$ ./check -in attestation.bin -report_data=${hexnonce}
```

## Exit code meaning

*   0: Success
*   1: Failure due to tool misuse
*   2: Failure due to invalid signature
*   3: Failure due to certificate fetch failure
*   4: Failure due to certificate revocation list download failure
*   5: Failure due to policy
