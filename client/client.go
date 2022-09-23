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

package client

import (
	"fmt"

	"github.com/google/go-sev-guest/abi"
	labi "github.com/google/go-sev-guest/client/linuxabi"
	pb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/pborman/uuid"
	"github.com/pkg/errors"
)

// Device encapsulates the possible commands to the AMD SEV guest device.
type Device interface {
	Open(path string) error
	Close() error
	Ioctl(command uintptr, argument interface{}) (uintptr, error)
}

type certTableEntry struct {
	GUID    uuid.UUID
	RawCert []byte
}

// certTable represents each (GUID, Blob) pair of certificates returned by an extended guest
// request.
type certTable struct {
	entries []certTableEntry
}

func message(d Device, command uintptr, req *labi.SnpUserGuestRequest) error {
	result, err := d.Ioctl(command, req)
	if err != nil {
		return err
	}
	if result != uintptr(labi.EsOk) {
		return labi.SevEsErr{Result: labi.EsResult(result)}
	}
	if req.FwErr != 0 {
		return abi.SevFirmwareErr{Status: abi.SevFirmwareStatus(req.FwErr)}
	}
	return nil
}

// GetRawReportAtVmpl requests for an attestation report at the given VMPL that incorporates the
// given user data.
func GetRawReportAtVmpl(d Device, userData [64]byte, vmpl int) ([]byte, error) {
	var snpReportRsp labi.SnpReportRespABI
	userGuestReq := labi.SnpUserGuestRequest{
		ReqData: &labi.SnpReportReqABI{
			UserData: userData,
			Vmpl:     uint32(vmpl),
		},
		RespData: &snpReportRsp,
	}
	if err := message(d, labi.IocSnpGetReport, &userGuestReq); err != nil {
		return nil, err
	}
	return snpReportRsp.Data[:abi.ReportSize], nil
}

// GetRawReport requests for an attestation report at VMPL0 that incorporates the given user data.
func GetRawReport(d Device, userData [64]byte) ([]byte, error) {
	return GetRawReportAtVmpl(d, userData, 0)
}

// GetReportAtVmpl gets an attestation report at the given VMPL into its protobuf representation.
func GetReportAtVmpl(d Device, userData [64]byte, vmpl int) (*pb.Report, error) {
	data, err := GetRawReportAtVmpl(d, userData, vmpl)
	if err != nil {
		return nil, err
	}
	return abi.ReportToProto(data)
}

// GetReport gets an attestation report at VMPL0 into its protobuf representation.
func GetReport(d Device, userData [64]byte) (*pb.Report, error) {
	return GetReportAtVmpl(d, userData, 0)
}

// getExtendedReportIn issues a GetExtendedReport command to the sev-guest driver with userData
// input and certs as a destination for certificate data. If certs is empty, this function returns
// the expected size of certs as its second result value. If certs is non-empty, this function
// returns the signed attestation report containing userData and the certificate chain for the
// report's endorsement key.
func getExtendedReportIn(d Device, userData [64]byte, vmpl int, certs []byte) ([]byte, uint32, error) {
	var snpReportRsp labi.SnpReportRespABI
	snpExtReportReq := labi.SnpExtendedReportReq{
		Data: labi.SnpReportReqABI{
			UserData: userData,
			Vmpl:     uint32(vmpl),
		},
		Certs:       certs,
		CertsLength: uint32(len(certs)),
	}
	userGuestReq := labi.SnpUserGuestRequest{
		ReqData:  &snpExtReportReq,
		RespData: &snpReportRsp,
	}
	// Query the length required for certs.
	if err := message(d, labi.IocSnpGetExtendedReport, &userGuestReq); err != nil {
		var fwErr abi.SevFirmwareErr
		if errors.As(err, &fwErr) && fwErr.Status == abi.GuestRequestInvalidLength {
			return nil, snpExtReportReq.CertsLength, nil
		}
		return nil, 0, err
	}
	return snpReportRsp.Data[:abi.ReportSize], snpExtReportReq.CertsLength, nil
}

// queryCertificateLength requests the required memory size in bytes to represent all certificates
// returned by an extended guest request.
func queryCertificateLength(d Device, vmpl int) (uint32, error) {
	_, length, err := getExtendedReportIn(d, [64]byte{}, vmpl, []byte{})
	if err != nil {
		return 0, err
	}
	return length, nil
}

// Unmarshal populates the certTable with the (GUID, Blob) pairs represented in the given bytes.
// The format of the bytes is specified by the SEV SNP API for extended guest requests.
func (c *certTable) Unmarshal(certs []byte) error {
	certTableHeader, err := abi.ParseSnpCertTableHeader(certs)
	if err != nil {
		return err
	}
	for i, entry := range certTableHeader {
		var next certTableEntry
		next.GUID = make([]byte, abi.GUIDSize)
		copy(next.GUID, entry.GUID)
		if entry.Offset+entry.Length > uint32(len(certs)) {
			return fmt.Errorf("cert table entry %d specifies a byte range outside the certificate data block (size %d): offset=%d, length%d", i, len(certs), entry.Offset, entry.Length)
		}
		next.RawCert = make([]byte, entry.Length)
		copy(next.RawCert, certs[entry.Offset:entry.Offset+entry.Length])
		c.entries = append(c.entries, next)
	}
	return nil
}

// getByGUIDString returns the raw bytes for a certificate that matches a key identified by the
// given GUID string.
func (c *certTable) getByGUIDString(guid string) ([]byte, error) {
	g := uuid.Parse(guid)
	if g == nil {
		return nil, fmt.Errorf("GUID string format is XXXXXXXX-XXXX-XXXX-XXXXXXXXXXXXXXXX, got %s", guid)
	}
	for _, entry := range c.entries {
		if uuid.Equal(entry.GUID, g) {
			return entry.RawCert, nil
		}
		fmt.Println(entry.GUID, "is not", g)
	}
	return nil, fmt.Errorf("cert not found for GUID %s", guid)
}

func (c *certTable) proto() (*pb.CertificateChain, error) {
	vcek, err := c.getByGUIDString(abi.VcekGUID)
	if err != nil {
		return nil, fmt.Errorf("VCEK not found: %v", err)
	}
	ask, err := c.getByGUIDString(abi.AskGUID)
	if err != nil {
		return nil, fmt.Errorf("ASK not found: %v", err)
	}
	ark, err := c.getByGUIDString(abi.ArkGUID)
	if err != nil {
		return nil, fmt.Errorf("ARK not found: %v", err)
	}
	return &pb.CertificateChain{
		VcekCert: vcek,
		AskCert:  ask,
		ArkCert:  ark,
	}, nil
}

// GetRawExtendedReportAtVmpl requests for an attestation report that incorporates the given user
// data at the given VMPL, and additional key certificate information.
func GetRawExtendedReportAtVmpl(d Device, userData [64]byte, vmpl int) ([]byte, []byte, error) {
	length, err := queryCertificateLength(d, vmpl)
	if err != nil {
		return nil, nil, fmt.Errorf("error querying certificate length: %v", err)
	}
	certs := make([]byte, length)
	report, _, err := getExtendedReportIn(d, userData, vmpl, certs)
	if err != nil {
		return nil, nil, err
	}
	return report, certs, nil
}

// GetRawExtendedReport requests for an attestation report that incorporates the given user data,
// and additional key certificate information.
func GetRawExtendedReport(d Device, userData [64]byte) ([]byte, []byte, error) {
	return GetRawExtendedReportAtVmpl(d, userData, 0)
}

// GetExtendedReportAtVmpl gets an extended attestation report at the given VMPL into a structured type.
func GetExtendedReportAtVmpl(d Device, userData [64]byte, vmpl int) (*pb.Attestation, error) {
	reportBytes, certBytes, err := GetRawExtendedReportAtVmpl(d, userData, vmpl)
	if err != nil {
		return nil, err
	}

	report, err := abi.ReportToProto(reportBytes)
	if err != nil {
		return nil, err
	}

	certs := new(certTable)
	if err := certs.Unmarshal(certBytes); err != nil {
		return nil, err
	}
	certChain, err := certs.proto()
	if err != nil {
		return nil, err
	}
	return &pb.Attestation{Report: report, CertificateChain: certChain}, nil
}

// GetExtendedReport gets an extended attestation report at VMPL0 into a structured type.
func GetExtendedReport(d Device, userData [64]byte) (*pb.Attestation, error) {
	return GetExtendedReportAtVmpl(d, userData, 0)
}

// GuestFieldSelect represents which guest-provided information will be mixed into a derived key.
type GuestFieldSelect struct {
	TCBVersion  bool
	GuestSVN    bool
	Measurement bool
	FamilyID    bool
	ImageID     bool
	GuestPolicy bool
}

// SnpDerivedKeyReq represents a request to the SEV guest device to derive a key from specified
// information.
type SnpDerivedKeyReq struct {
	// UseVCEK determines if the derived key will be based on VCEK or VMRK. This is opposite from the
	// ABI's ROOT_KEY_SELECT to avoid accidentally making an unsafe choice in a multitenant
	// environment.
	UseVCEK          bool
	GuestFieldSelect GuestFieldSelect
	// Vmpl to mix into the key. Must be greater than or equal to current Vmpl.
	Vmpl uint32
	// GuestSVN to mix into the key. Must be less than or equal to GuestSVN at launch.
	GuestSVN uint32
	// TCBVersion to mix into the key. Must be less than or equal to the CommittedTcb.
	TCBVersion uint64
}

// ABI returns the SNP ABI-specified uint64 bitmask of guest field selection.
func (g GuestFieldSelect) ABI() uint64 {
	var value uint64
	if g.TCBVersion {
		value |= uint64(1 << 5)
	}
	if g.GuestSVN {
		value |= uint64(1 << 4)
	}
	if g.Measurement {
		value |= uint64(1 << 3)
	}
	if g.FamilyID {
		value |= uint64(1 << 2)
	}
	if g.ImageID {
		value |= uint64(1 << 1)
	}
	if g.GuestPolicy {
		value |= uint64(1 << 0)
	}
	return value
}

// GetDerivedKeyAcknowledgingItsLimitations returns 32 bytes of key material that the AMD security
// processor derives from the given parameters. Security limitations of this command are described
// more in the project README.
func GetDerivedKeyAcknowledgingItsLimitations(d Device, request *SnpDerivedKeyReq) (*labi.SnpDerivedKeyRespABI, error) {
	response := &labi.SnpDerivedKeyRespABI{}
	rootKeySelect := uint32(1)
	if request.UseVCEK {
		rootKeySelect = 0
	}
	guestRequest := &labi.SnpUserGuestRequest{
		ReqData: &labi.SnpDerivedKeyReqABI{
			RootKeySelect:    rootKeySelect,
			GuestFieldSelect: request.GuestFieldSelect.ABI(),
			Vmpl:             request.Vmpl,
			GuestSVN:         request.GuestSVN,
			TCBVersion:       request.TCBVersion,
		},
		RespData: response,
	}
	if err := message(d, labi.IocSnpGetDerivedKey, guestRequest); err != nil {
		return nil, fmt.Errorf("error getting derived key: %v", err)
	}
	return response, nil
}
