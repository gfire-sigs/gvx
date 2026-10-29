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
	"testing"

	"z.gfire.dev/gvx/third_party/x_sys/unix"

	"z.gfire.dev/gvx/pkg/seccomp"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/runsc/boot/filter/config"
)

// TestHostFilesystemRulesAllowTheXattrCalls pins the calls that the native
// extended attribute store of hostfs makes after the lockdown. A host
// directory adds the rules of the host filesystem, and those rules carry the
// four descriptor forms of the xattr calls.
func TestHostFilesystemRulesAllowTheXattrCalls(t *testing.T) {
	plat := platform.StaticSeccompInfo{PlatformName: "test", Filters: seccomp.NewSyscallRules()}
	rules, _ := config.Rules(config.Options{Platform: plat, HostFilesystem: true})
	for name, sysno := range map[string]uintptr{
		"fgetxattr":    unix.SYS_FGETXATTR,
		"fsetxattr":    unix.SYS_FSETXATTR,
		"flistxattr":   unix.SYS_FLISTXATTR,
		"fremovexattr": unix.SYS_FREMOVEXATTR,
	} {
		if !rules.Has(sysno) {
			t.Errorf("the host filesystem rules lack %s, so hostfs xattr calls kill the process after the lockdown", name)
		}
	}
	without, _ := config.Rules(config.Options{Platform: plat})
	if without.Has(unix.SYS_FSETXATTR) {
		t.Errorf("the base rules allow fsetxattr without a host directory")
	}
}
