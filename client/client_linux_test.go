// Copyright 2026 Google LLC
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

package client

import (
	"flag"
	"testing"
	"time"
)

// setFlag sets a flag until the test ends.
func setFlag(t *testing.T, name, value string) {
	t.Helper()
	old := flag.Lookup(name).Value.String()
	if err := flag.Set(name, value); err != nil {
		t.Fatalf("flag.Set(%q, %q) = %v", name, value, err)
	}
	t.Cleanup(func() {
		if err := flag.Set(name, old); err != nil {
			t.Errorf("flag.Set(%q, %q) = %v", name, old, err)
		}
	})
}

func TestOpenDeviceThrottlesFirstCommand(t *testing.T) {
	const throttle = 100 * time.Millisecond
	// /dev/null opens and fails the ioctl, which is enough to test the delay.
	setFlag(t, "sev_guest_device_path", "/dev/null")
	setFlag(t, "self_throttle_duration", throttle.String())
	start := time.Now()
	d, err := OpenDevice()
	if err != nil {
		t.Fatalf("OpenDevice() = %v", err)
	}
	defer d.Close()
	if _, err := GetRawReport(d, [64]byte{}); err == nil {
		t.Fatal("GetRawReport(/dev/null) = nil error, want an ioctl error")
	}
	if elapsed := time.Since(start); elapsed < throttle {
		t.Errorf("first command after OpenDevice took %v, want at least %v", elapsed, throttle)
	}
}
