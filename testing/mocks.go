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

package testing

import (
	"encoding/hex"
	"fmt"
	"syscall"
	"testing"

	"github.com/google/go-sev-guest/abi"
	labi "github.com/google/go-sev-guest/client/linuxabi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// GetReportResponse represents a mocked response to a command request.
type GetReportResponse struct {
	Resp     labi.SnpReportRespABI
	EsResult labi.EsResult
	FwErr    abi.SevFirmwareStatus
}

// Device represents a sev-guest driver implementation with pre-programmed responses to commands.
type Device struct {
	isOpen        bool
	ReportDataRsp map[string]any
	Keys          map[string][]byte
	Certs         []byte
	Signer        *AmdSigner
	SevProduct    *spb.SevProduct
}

// Open changes the mock device's state to open.
func (d *Device) Open(_ string) error {
	if d.isOpen {
		return errors.New("device already open")
	}
	d.isOpen = true
	return nil
}

// Close changes the mock device's state to closed.
func (d *Device) Close() error {
	if !d.isOpen {
		return errors.New("device already closed")
	}
	d.isOpen = false
	return nil
}

func (d *Device) getReport(req *labi.SnpReportReqABI, rsp *labi.SnpReportRespABI, fwErr *uint64) (uintptr, error) {
	mockRspI, ok := d.ReportDataRsp[hex.EncodeToString(req.ReportData[:])]
	if !ok {
		return 0, fmt.Errorf("test error: no response for %v", req.ReportData)
	}
	mockRsp, ok := mockRspI.(*GetReportResponse)
	if !ok {
		return 0, fmt.Errorf("test error: incorrect response type %v", mockRspI)
	}
	esResult := uintptr(mockRsp.EsResult)
	if mockRsp.FwErr != 0 {
		*fwErr = uint64(mockRsp.FwErr)
		return esResult, syscall.Errno(unix.EIO)
	}
	report := mockRsp.Resp.Data[:abi.ReportSize]
	r, s, err := d.Signer.Sign(abi.SignedComponent(report))
	if err != nil {
		return 0, fmt.Errorf("test error: could not sign report: %v", err)
	}
	if err := abi.SetSignature(r, s, report); err != nil {
		return 0, fmt.Errorf("test error: could not set signature: %v", err)
	}
	copy(rsp.Data[:], report)
	return esResult, nil
}

func (d *Device) getExtReport(req *labi.SnpExtendedReportReq, rsp *labi.SnpReportRespABI, fwErr *uint64) (uintptr, error) {
	if req.CertsLength == 0 {
		*fwErr = uint64(abi.GuestRequestInvalidLength)
		req.CertsLength = uint32(len(d.Certs))
		return 0, syscall.Errno(unix.EIO)
	}
	ret, err := d.getReport(&req.Data, rsp, fwErr)
	if err != nil {
		return ret, err
	}
	if req.CertsLength < uint32(len(d.Certs)) {
		return 0, fmt.Errorf("test failure: cert buffer too small: %d < %d", req.CertsLength, len(d.Certs))
	}
	copy(req.Certs, d.Certs)
	return ret, nil
}

// DerivedKeyRequestToString translates a DerivedKeyReqABI into a map key string representation.
func DerivedKeyRequestToString(req *labi.SnpDerivedKeyReqABI) string {
	return fmt.Sprintf("%x %x %x %x %x", req.RootKeySelect, req.GuestFieldSelect, req.Vmpl, req.GuestSVN, req.TCBVersion)
}

func (d *Device) getDerivedKey(req *labi.SnpDerivedKeyReqABI, rsp *labi.SnpDerivedKeyRespABI, _ *uint64) (uintptr, error) {
	if len(d.Keys) == 0 {
		return 0, errors.New("test error: no keys")
	}
	key, ok := d.Keys[DerivedKeyRequestToString(req)]
	if !ok {
		return 0, fmt.Errorf("test error: unmapped key request %v", req)
	}
	copy(rsp.Data[:], key)
	return 0, nil
}

// Ioctl mocks commands with pre-specified responses for a finite number of requests.
func (d *Device) Ioctl(command uintptr, req any) (uintptr, error) {
	switch sreq := req.(type) {
	case *labi.SnpUserGuestRequest:
		switch command {
		case labi.IocSnpGetReport:
			return d.getReport(sreq.ReqData.(*labi.SnpReportReqABI), sreq.RespData.(*labi.SnpReportRespABI), &sreq.FwErr)
		case labi.IocSnpGetDerivedKey:
			return d.getDerivedKey(sreq.ReqData.(*labi.SnpDerivedKeyReqABI), sreq.RespData.(*labi.SnpDerivedKeyRespABI), &sreq.FwErr)
		case labi.IocSnpGetExtendedReport:
			return d.getExtReport(sreq.ReqData.(*labi.SnpExtendedReportReq), sreq.RespData.(*labi.SnpReportRespABI), &sreq.FwErr)
		default:
			return 0, fmt.Errorf("invalid command 0x%x", command)
		}
	}
	return 0, fmt.Errorf("unexpected request: %v", req)
}

// Product returns the mocked product info or the default.
func (d *Device) Product() *spb.SevProduct {
	if d.SevProduct == nil {
		return &spb.SevProduct{
			Name:          spb.SevProduct_SEV_PRODUCT_MILAN,
			ModelStepping: 0xB0,
		}
	}
	return d.SevProduct
}

// Getter represents a static server for request/respond url -> body contents.
type Getter struct {
	Responses map[string][]byte
}

// Get returns a registered response for a given URL.
func (g *Getter) Get(url string) ([]byte, error) {
	v, ok := g.Responses[url]
	if !ok {
		return nil, fmt.Errorf("404: %s", url)
	}
	return v, nil
}

// GetResponse controls how often (Occurances) a certain response should be
// provided.
type GetResponse struct {
	Occurances uint
	Body       []byte
	Error      error
}

// VariableResponseGetter is a mock for HTTPSGetter interface that sequentially
// returns the configured responses for the provided URL. Responses are returned
// as a queue, i.e., always serving from index 0.
type VariableResponseGetter struct {
	Responses map[string][]GetResponse
}

// Get the next configured response body and error. The configured response
// is also removed if it has been requested the configured number of times.
func (g *VariableResponseGetter) Get(url string) ([]byte, error) {
	resp, ok := g.Responses[url]
	if !ok || len(resp) == 0 {
		return nil, fmt.Errorf("404: %s", url)
	}
	body := resp[0].Body
	err := resp[0].Error
	resp[0].Occurances--
	if resp[0].Occurances == 0 {
		g.Responses[url] = resp[1:]
	}
	return body, err
}

// Done checks that all configured responses have been consumed, and errors
// otherwise.
func (g *VariableResponseGetter) Done(t testing.TB) {
	for key := range g.Responses {
		if len(g.Responses[key]) != 0 {
			t.Errorf("Prepared response for '%s' not retrieved.", key)
		}
	}
}
