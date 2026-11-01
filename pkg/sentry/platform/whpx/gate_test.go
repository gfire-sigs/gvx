// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package whpx

import (
	"errors"
	"testing"
)

func TestCheckHost(t *testing.T) {
	good := hostFeatures{hypervisorPresent: true, arm64Support: true, windowsBuild: 26100, windowsUBR: 3915}
	for _, c := range []struct {
		name    string
		arm64   bool
		f       hostFeatures
		wantErr bool
	}{
		{name: "amd64 with hypervisor", f: hostFeatures{hypervisorPresent: true, xsaveFeatures: xsaveFeatXsave}},
		{name: "amd64 without XsaveSupport", f: hostFeatures{hypervisorPresent: true, xsaveFeatures: xsaveFeatAvx}, wantErr: true},
		{name: "amd64 without hypervisor", f: hostFeatures{}, wantErr: true},
		{name: "arm64 at the minimum", arm64: true, f: good},
		{name: "arm64 above the minimum build with a low UBR", arm64: true, f: hostFeatures{hypervisorPresent: true, arm64Support: true, windowsBuild: 26200, windowsUBR: 100}},
		{name: "arm64 one revision short", arm64: true, f: hostFeatures{hypervisorPresent: true, arm64Support: true, windowsBuild: 26100, windowsUBR: 3914}, wantErr: true},
		{name: "arm64 old build with a high UBR", arm64: true, f: hostFeatures{hypervisorPresent: true, arm64Support: true, windowsBuild: 22631, windowsUBR: 9999}, wantErr: true},
		{name: "arm64 without Arm64Support", arm64: true, f: hostFeatures{hypervisorPresent: true, windowsBuild: 26100, windowsUBR: 3915}, wantErr: true},
		{name: "arm64 without hypervisor", arm64: true, f: hostFeatures{arm64Support: true, windowsBuild: 26100, windowsUBR: 3915}, wantErr: true},
		{name: "amd64 ignores the arm64 gate", f: hostFeatures{hypervisorPresent: true, windowsBuild: 19045, xsaveFeatures: xsaveFeatXsave}},
	} {
		err := checkHost(c.arm64, c.f)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: error %v, want error %v", c.name, err, c.wantErr)
		}
		if err != nil && !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: error %v does not wrap ErrUnsupported", c.name, err)
		}
	}
}

func TestNewFailsClosedWithoutWindows(t *testing.T) {
	if _, err := newBackend(); err == nil {
		t.Skip("running on a Windows host")
	}
	p, err := New()
	if err == nil || p != nil {
		t.Fatalf("New returned %v, %v on a host without WinHvPlatform.dll", p, err)
	}
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("error %v does not wrap ErrUnsupported", err)
	}
	if _, err := NewWithOptions(Options{ThreadInit: func() error { return nil }}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("NewWithOptions error is %v", err)
	}
}
