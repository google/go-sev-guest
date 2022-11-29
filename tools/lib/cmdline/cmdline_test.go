package cmdline

import (
	"bytes"
	"strings"
	"testing"
)

func expect(err error, wantErr string) bool {
	if err == nil {
		return wantErr == ""
	}
	return wantErr != "" && strings.Contains(err.Error(), wantErr)
}

func TestParseBytes(t *testing.T) {
	tests := []struct {
		name     string
		byteSize int
		in       []byte
		inform   string
		intype   InputType
		want     []byte
		wantErr  string
	}{
		{
			name:     "binary as binary (intype stringy)",
			byteSize: 4,
			in:       []byte{0x30, 0x31, 0x32, 0x33},
			inform:   "bin",
			intype:   Stringy,
			want:     []byte{0x30, 0x31, 0x32, 0x33},
		},
		{
			name:     "binary as binary (intype filey)",
			byteSize: 4,
			in:       []byte{0x30, 0x31, 0x32, 0x33},
			inform:   "bin",
			intype:   Filey,
			want:     []byte{0x30, 0x31, 0x32, 0x33},
		},
		{
			name:     "binary as auto (intype filey)",
			byteSize: 4,
			in:       []byte{1, 2, 3, 4},
			inform:   "auto",
			intype:   Filey,
			want:     []byte{1, 2, 3, 4},
		},
		{
			name:     "binary as auto, not hex-encoded (intype stringy)",
			byteSize: 4,
			in:       []byte{1, 2, 3, 4},
			inform:   "auto",
			intype:   Stringy,
			wantErr:  "could not be decoded",
		},
		{
			name:     "hex as hex (intype stringy)",
			byteSize: 4,
			in:       []byte("0123"),
			inform:   "hex",
			intype:   Stringy,
			want:     []byte{0x01, 0x23, 0, 0},
		},
		{
			name:     "hex as hex (intype filey)",
			byteSize: 4,
			in:       []byte("0123"),
			inform:   "hex",
			intype:   Filey,
			want:     []byte{0x01, 0x23, 0, 0},
		},
		{
			name:     "base64 as base64 (intype stringy)",
			byteSize: 4,
			in:       []byte("MTIzNA=="), // echo -n "1234" | base64
			inform:   "base64",
			intype:   Stringy,
			want:     []byte{0x31, 0x32, 0x33, 0x34}, // ASCII codes
		},
		{
			name:     "base64 as base64 (intype filey)",
			byteSize: 4,
			in:       []byte("MTIzNA=="), // echo -n "1234" | base64
			inform:   "base64",
			intype:   Filey,
			want:     []byte{0x31, 0x32, 0x33, 0x34}, // ASCII codes
		},
		{
			name:     "base64 as auto does not work with non-hex",
			byteSize: 4,
			in:       []byte("MTIzNA=="), // echo -n "1234" | base64
			inform:   "auto",
			intype:   Filey,
			wantErr:  "binary input type had 8 bytes. Expect exactly 4 bytes",
		},
		{
			name:     "hexy base64 as base64",
			byteSize: 4,
			in:       []byte("1234"),
			inform:   "base64",
			intype:   Stringy,
			want:     []byte{0xd7, 0x6d, 0xf8, 0},
		},
		{
			name:     "hex auto (intype stringy)",
			byteSize: 4,
			in:       []byte("1234"),
			inform:   "auto",
			intype:   Stringy,
			want:     []byte{0x12, 0x34, 0, 0},
		},
		{
			name:     "hex auto (intype filey)",
			byteSize: 4,
			in:       []byte("1234"),
			inform:   "auto",
			intype:   Filey,
			want:     []byte{0x31, 0x32, 0x33, 0x34}, // ASCII codes
		},
		{
			name:     "non-exact binary",
			byteSize: 4,
			in:       []byte{2},
			inform:   "bin",
			intype:   Filey,
			wantErr:  "Expect exactly 4 bytes",
		},
		{
			name:     "chonky hexstring",
			byteSize: 4,
			in:       []byte("0102030405"),
			inform:   "hex",
			intype:   Filey,
			wantErr:  "test_input=0102030405 ([1 2 3 4 5]) is not representable in 4 bytes",
		},
		{
			name:     "\ufffd",
			byteSize: 4,
			// Example from https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
			in:      []byte{0xf0, 0x80, 0x80, 0x80},
			inform:  "hex",
			intype:  Stringy,
			wantErr: "could not decode test_input contents as a UTF-8 string",
		},
		{
			name:     "bad inform",
			byteSize: 4,
			in:       []byte{0},
			inform:   "wonk",
			intype:   Filey,
			wantErr:  "unknown -inform=wonk",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := bytes.NewReader(tc.in)
			got, err := ParseBytes("test_input", tc.byteSize, in, tc.inform, tc.intype)
			if !expect(err, tc.wantErr) {
				t.Errorf("ParseBytes(%s, %d, %q, %q, %v) errored unexpectedly. Got %v. Want %v",
					tc.name, tc.byteSize, tc.in, tc.inform, tc.intype, err, tc.wantErr)
			}
			if err == nil && !bytes.Equal(got, tc.want) {
				t.Errorf("ParseBytes(%s, %d, %q, %q, %v) = %v. Want %v",
					tc.name, tc.byteSize, tc.in, tc.inform, tc.intype, got, tc.want)
			}
		})
	}
}

func TestBytes(t *testing.T) {
	tests := []*struct {
		name     string
		in       string
		byteSize int
		want     []byte
	}{
		{
			name:     "test_input",
			byteSize: 4,
			in:       "1234",
			want:     []byte{0x12, 0x34, 0, 0},
		},
		{
			name:     "empty",
			byteSize: 4,
			in:       "",
			want:     []byte{},
		},
	}
	byteArray := make([]*[]byte, len(tests))
	for i, tc := range tests {
		byteArray[i] = Bytes(tc.name, tc.byteSize, &tc.in)
	}
	Parse("auto")
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if !bytes.Equal(*byteArray[i], tc.want) {
				t.Errorf("Bytes(%s, %d, &%q) = %v. Want %v", tc.name, tc.byteSize, tc.in, *byteArray[i], tc.want)
			}
		})
	}
}
