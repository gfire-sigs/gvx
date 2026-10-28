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

//go:build darwin

package systrap

import (
	"runtime"

	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// Platform is the darwin systrap backend. macOS uses Hypervisor.framework (hvf),
// so a Platform value never carries state.
type Platform struct {
	platform.Platform
}

// New always fails on darwin.
func New() (*Platform, error) {
	return nil, &ErrUnavailable{
		Host:   "darwin/" + runtime.GOARCH,
		Reason: "macOS uses Hypervisor.framework (hvf); the darwin systrap engine is disabled",
	}
}

// Probe always fails on darwin for the reason that New gives.
func Probe() (ProbeInfo, error) {
	_, err := New()
	return ProbeInfo{}, err
}
