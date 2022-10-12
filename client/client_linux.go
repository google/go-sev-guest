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

//go:build linux || freebsd || openbsd || netbsd

// Package client provides an interface to the AMD SEV-SNP guest device commands.
package client

import (
	"fmt"
	"syscall"
	"time"

	"github.com/google/go-sev-guest/abi"
	labi "github.com/google/go-sev-guest/client/linuxabi"
	"golang.org/x/sys/unix"
)

const ()

// The sev-guest device might not have been updated to interpret the busy value
// as -EAGAIN, so we will keep that check here until the patch is in major
// distros.
func legacyThrottle(errno syscall.Errno, sreq *labi.SnpUserGuestRequest) bool {
	return errno == unix.EIO && sreq.VmmErr == abi.GuestRequestVmmErrBusy
}

// LinuxDevice implements the Device interface with Linux ioctls.
type LinuxDevice struct {
	// TimeoutDuration is the maximum amount of time a guest request
	// should retry amidst contention and throttling. 0 means no limit.
	TimeoutDuration time.Duration
	fd              int
}

// Options provides flexible configuration to how this library will interact with the
// sev-guest device.
type Options struct {
	// TimeoutMs is the maximum amount of time in milliseconds a guest request
	// should retry amidst contention and throttling. 0 means no limit.
	Timeout time.Duration
	// DevicePath is the path to the sev-guest device. If empty, defaults to
	// "/dev/sev-guest"
	DevicePath string
}

// Timeout returns the configured timeout duration.
func (d *LinuxDevice) Timeout() time.Duration {
	return d.TimeoutDuration
}

// Open opens the SEV-SNP guest device from a given path
func (d *LinuxDevice) Open(path string) error {
	fd, err := unix.Open(path, unix.O_RDWR, 0)
	if err != nil {
		d.fd = -1
		return fmt.Errorf("could not open AMD SEV guest device at %s: %v", path, err)
	}
	d.fd = fd
	return nil
}

// OpenDevice opens the SEV-SNP guest device.
func OpenDevice(opts *Options) (*LinuxDevice, error) {
	var timeout time.Duration
	path := "/dev/sev-guest"
	if opts != nil {
		if opts.DevicePath != "" {
			path = opts.DevicePath
		}
		timeout = opts.Timeout
	}
	result := &LinuxDevice{TimeoutDuration: timeout}
	if err := result.Open(path); err != nil {
		return nil, err
	}
	return result, nil
}

// Close closes the SEV-SNP guest device.
func (d *LinuxDevice) Close() error {
	if d.fd == -1 { // Not open
		return nil
	}
	if err := unix.Close(d.fd); err != nil {
		return err
	}
	// Prevent double-close.
	d.fd = -1
	return nil
}

// Ioctl sends a command with its wrapped request and response values to the Linux device.
func (d *LinuxDevice) Ioctl(command uintptr, req any) (uintptr, error) {
	switch sreq := req.(type) {
	case *labi.SnpUserGuestRequest:
		abi := sreq.ABI()
		result, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(d.fd), command, uintptr(abi.Pointer()))
		abi.Finish(sreq)

		// TODO(Issue #5): remove the work around for the kernel bug that writes
		// uninitialized memory back on non-EIO.
		if errno != unix.EIO {
			sreq.FwErr = 0
			sreq.VmmErr = 0
		}
		if (errno == unix.EAGAIN) || legacyThrottle(errno, sreq) {
			return 0, &labi.RetryErr{}
		}
		if errno != 0 {
			return 0, errno
		}
		return result, nil
	}
	return 0, fmt.Errorf("unexpected request value: %v", req)
}
