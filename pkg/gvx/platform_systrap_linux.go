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

//go:build linux

package gvx

import (
	"fmt"
	"os"
	"runtime"

	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/systrap"
)

// linuxSystrapName is the registration name of the upstream systrap platform.
const linuxSystrapName = "systrap"

// openSystrap starts the upstream gVisor systrap platform. Linux needs no
// hypervisor backend: the upstream platform runs the guest in stub processes
// that the host kernel isolates. New calls it before the host lockdown,
// because the platform forks its first stub process during construction.
func openSystrap() (platform.Platform, string, error) {
	p, err := systrap.New(platform.Options{})
	if err != nil {
		return nil, "", fmt.Errorf("gvx: %s backend: %w", linuxSystrapName, err)
	}
	return p, linuxSystrapName, nil
}

// probeStub reports the host facts of the upstream platform after it starts.
// The upstream platform exposes no stub process ID or handshake timing.
func probeStub() (StubInfo, error) {
	if _, _, err := openSystrap(); err != nil {
		return StubInfo{}, err
	}
	return StubInfo{Arch: runtime.GOARCH, HostPageSize: os.Getpagesize()}, nil
}
