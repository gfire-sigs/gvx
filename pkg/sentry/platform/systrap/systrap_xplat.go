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

//go:build darwin || windows

package systrap

import (
	"fmt"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// PlatformName is the registration name of the unified systrap backend.
const PlatformName = "systrap"

// ErrUnavailable reports that systrap cannot run on this host. Reason names
// the missing prerequisite.
type ErrUnavailable struct {
	// Host names the GOOS/GOARCH pair.
	Host string
	// Reason names the exact missing prerequisite.
	Reason string
}

// Error implements error.
func (e *ErrUnavailable) Error() string {
	return fmt.Sprintf("systrap is unavailable on %s: %s", e.Host, e.Reason)
}

// constructor adapts New to platform.Constructor.
type constructor struct{}

// New implements platform.Constructor.New.
func (constructor) New(platform.Options) (platform.Platform, error) {
	p, err := New()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// PrecompiledSeccompInfo implements platform.Constructor.PrecompiledSeccompInfo.
// macOS and Windows have no seccomp, so the info only names the platform.
func (constructor) PrecompiledSeccompInfo() []platform.SeccompInfo {
	return []platform.SeccompInfo{platform.StaticSeccompInfo{PlatformName: PlatformName}}
}

func init() {
	platform.Register(PlatformName, constructor{})
}

// ProbeInfo describes a stub that Probe started, handshook with and stopped.
type ProbeInfo struct {
	// Arch is the guest architecture that the stub runs, such as "arm64".
	Arch string
	// PageSize is the host VM page size that the stub reported.
	PageSize int
	// StubPID is the host process ID of the template stub.
	StubPID int
	// ProtocolVersion is the Sentry and stub handoff protocol version.
	ProtocolVersion uint32
	// RoundTrip is the mean time of one guest system call round trip,
	// from the guest svc through the Sentry back to the guest.
	RoundTrip time.Duration
	// UserMin and UserMax bound the guest address range. The platform derives
	// them from the layout of the stub task, so they differ between hosts.
	UserMin, UserMax uint64
}
