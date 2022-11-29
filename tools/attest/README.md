# `attest` CLI tool

This binary is a thin wrapper around the `client` library to gather attestation
reports in either AMD API format or in this module's `sevsnp` protobuf formats.

The tool's input is the intended `REPORT_DATA` contents, which is 64 bytes of
user-provided data to include in the attestation report. This is typically a
nonce.

The tool's output is the report in any specified format to either standard out
or directly to a file.

## Example

```
$ go run . -inform base64 -in \
SGVsbG8gU0VWLVNOUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA== \
-out attestation.bin
```

Or equivalently through stdin and default binary input format:

```shell
$ echo \
“SGVsbG8gU0VWLVNOUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==” | \
base64 -d  | go run . -out attestation.bin
```

If the host does not provide cached certificates, passing --extended will return
empty certificates. It's still recommended to use --extended since the verification
logic won't change once the host provides cached certificates. The verification will
just not need to download them from the AMD Key Distribution Service (KDS).

## Usage

```
./attest [options...]
```

### `-extended`

The flag requests that the tool uses the extended guest request to get both the
attestation report and the host-provided certificates. If `-outform` is `bin`,
then the output is the attestation report immediately followed by the
certificate table.

### `-in`

This flag provides the `REPORT_DATA` content directly on the command line. The
contents will be interpreted by the value of the `-inform` flag. The `auto` inform
will default to expecting a hexadecimal string.

### `-infile`

A path to a file that contains `REPORT_DATA` contents. May be `-` for standard
in. If neither `-in` nor `-infile` are specified, then the default input is
standard in. The `auto` inform will default to expecting binary.

### `-inform`

The format that input takes. One of

*   `bin`: for raw binary. Must have the expected number of bytes.
*   `hex`: for a byte string encoded as a hexadecimal string. Fewer bytes than
    expected will be zero-filled.
*   `base64`: for a byte string in base64 encoding. Fewer bytes than expected
    will be zero-filled.
*   `auto`: has different meanings whether input is from a file or from a
    command line argument.
    +   If from an argument, then defaults to expecting a hexadecimal string.
        Will try base64 if hex decoding fails.
    +   If from a file, then defaults to expecting binary.

Default value is `auto`.

### `-outform`

The format that output takes. This can be `bin` for AMD's specified structures
in binary, `proto` for this module's protobuf message types serialized to bytes,
or `textproto` for this module's protobuf message types in human readable text
format.

Default value is `bin`.

### `-out`

Path to output file to write attestation report to.

Default is empty, interpreted as stdout.

### `-vmpl`

The VMPL at which the attestation report should be collected at. Must be between
0 and 3.

Default value is 0.

