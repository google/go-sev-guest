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

// Package linuxabi describes the /dev/sev-guest ioctl command ABI.
package linuxabi

import (
	"unsafe"

	"github.com/google/go-sev-guest/abi"
	"golang.org/x/sys/unix"
)

// EsResult is the status code type for Linux's GHCB communication results.
type EsResult int

// ioctl bits for x86-64
const (
	iocNrbits    = 8
	iocTypebits  = 8
	iocSizebits  = 14
	iocDirbits   = 2
	iocNrshift   = 0
	iocTypeshift = (iocNrshift + iocNrbits)
	iocSizeshift = (iocTypeshift + iocTypebits)
	iocDirshift  = (iocSizeshift + iocDirbits)
	iocWrite     = 1
	iocRead      = 2

	// Linux /dev/sev-guest ioctl interface
	iocTypeSnpGuestReq = 'S'
	iocSnpWithoutNr    = ((iocWrite | iocRead) << iocDirshift) |
		(iocTypeSnpGuestReq << iocTypeshift) |
		// unsafe.Sizeof(snpUserGuestRequest)
		(24 << iocSizeshift)

	// IocSnpGetReport is the ioctl command for getting an attestation report
	IocSnpGetReport = iocSnpWithoutNr | (0x0 << iocNrshift)

	// IocSnpGetReport is the ioctl command for getting an extended attestation report that includes
	// certificate information.
	IocSnpGetExtendedReport = iocSnpWithoutNr | (0x2 << iocNrshift)
)

const (
	// EsOk denotes success.
	EsOk EsResult = iota
	// EsUnsupported denotes that the requested operation is not supported.
	EsUnsupported
	// EsVmmError denotes that the virtual machine monitor was in an unexpected state.
	EsVmmError
	// EsDecodeFailed denotes that instruction decoding failed.
	EsDecodeFailed
	// EsException denotes that the GHCB communication caused an exception.
	EsException
	// EsRetry is the code for a retry instruction emulation
	EsRetry
)

// SevEsErr is an error that interprets SEV-ES guest-host communication results.
type SevEsErr struct {
	error
	Result EsResult
}

func (err SevEsErr) Error() string {
	if err.Result == EsUnsupported {
		return "requested operation not supported"
	}
	if err.Result == EsVmmError {
		return "unexpected state from the VMM"
	}
	if err.Result == EsDecodeFailed {
		return "instruction decoding failed"
	}
	if err.Result == EsException {
		return "instruction caused exception"
	}
	if err.Result == EsRetry {
		return "retry instruction emulation"
	}
	return "unknown error"
}

// SnpReportReq is Linux's sev-guest ioctl abi for sending a GET_REPORT request. See
// include/uapi/linux/sev-guest.h
type SnpReportReq struct {
	// UserData to be included in the report
	UserData [64]uint8

	// Vmpl is the SEV-SNP VMPL level to be included in the report.
	// The kernel must have access to the corresponding VMPCK.
	Vmpl uint32

	reserved [28]byte
}

// SnpReportResp is Linux's sev-guest ioctl abi for receiving a GET_REPORT response.
type SnpReportResp struct {
	// Data is the response data, see SEV-SNP spec for the format
	Data [abi.ReportSize]uint8
}

// SnpExtendedReportReqSafe is close to Linux's sev-guest ioctl abi for sending a GET_EXTENDED_REPORT request,
// but uses safer types for the Ioctl interface.
type SnpExtendedReportReqSafe struct {
	Data SnpReportReq

	// Where to copy the certificate blob.
	Certs []byte

	// length of the certificate blob
	CertsLength uint32
}

// SnpExtendedReportReq is Linux's sev-guest ioctl abi for sending a GET_EXTENDED_REPORT request.
type SnpExtendedReportReq struct {
	Data SnpReportReq

	// Where to copy the certificate blob.
	CertsAddress uint64

	// length of the certificate blob
	CertsLength uint32
}

// SnpUserGuestRequest is Linux's sev-guest ioctl abi for issuing a guest message.
type SnpUserGuestRequest struct {
	// Request and response structure address.
	ReqData  uint64
	RespData uint64
	// firmware error code on failure (see psp-sev.h in Linux kernel)
	FwErr uint64
}

// SnpUserGuestRequestSafe is Linux's sev-guest ioctl interface for issuing a guest message. The
// types here enhance runtime safety when using Ioctl as an interface.
type SnpUserGuestRequestSafe struct {
	// Request and response structure address.
	ReqData  interface{}
	RespData interface{}
	// firmware error code on failure (see psp-sev.h in Linux kernel)
	FwErr uint64
}

// Ioctl performs the ioctl Linux syscall with the sev-guest Linux ABI unsafe pointer
// manipulation contained all in this call.
func Ioctl(fd int, command uintptr, sreq *SnpUserGuestRequestSafe) (uintptr, error) {
	// Limit unsafe pointers to this scope by converting internal types to ABI types before a
	// raw ioctl call, and converting back.
	safeReqData := sreq.ReqData
	var reqData interface{}
	switch extReq := safeReqData.(type) {
	case *SnpExtendedReportReqSafe:
		var certsAddress uint64
		if len(extReq.Certs) > 0 {
			certsAddress = uint64(uintptr(unsafe.Pointer(&extReq.Certs[0])))
		}
		reqData = &SnpExtendedReportReq{
			Data:         extReq.Data,
			CertsAddress: certsAddress,
			CertsLength:  extReq.CertsLength,
		}
	}
	abi := SnpUserGuestRequest{
		ReqData:  uint64(uintptr(unsafe.Pointer(&reqData))),
		RespData: uint64(uintptr(unsafe.Pointer(&sreq.RespData))),
	}
	ptr := uintptr(unsafe.Pointer(&abi))
	result, _, errno := unix.RawSyscall(unix.SYS_IOCTL, uintptr(fd), command, ptr)
	if errno != 0 {
		return 0, errno
	}
	// Copy back the certsLength from the request copy if an extended report request.
	switch extReq := reqData.(type) {
	case *SnpExtendedReportReq:
		safeReqData.(*SnpExtendedReportReqSafe).CertsLength = extReq.CertsLength
	}
	sreq.FwErr = abi.FwErr
	return result, nil
}
