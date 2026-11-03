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
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"

	"z.gfire.dev/gvx/pkg/seccomp"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/runsc/boot/filter/config"
)

// statxArgReprs returns the Repr string of every matcher that the rules hold
// for one argument of statx.
func statxArgReprs(t *testing.T, rules seccomp.SyscallRules, arg int) []string {
	t.Helper()
	var reprs []string
	err := rules.ForSingleArgument(unix.SYS_STATX, arg, func(vm seccomp.ValueMatcher) error {
		var sb strings.Builder
		vm.Repr(&sb)
		reprs = append(reprs, sb.String())
		return nil
	})
	if err != nil {
		t.Fatalf("read the statx rules: %v", err)
	}
	return reprs
}

func reprOf(vm seccomp.ValueMatcher) string {
	var sb strings.Builder
	vm.Repr(&sb)
	return sb.String()
}

func containsRepr(reprs []string, vm seccomp.ValueMatcher) bool {
	want := reprOf(vm)
	for _, r := range reprs {
		if r == want {
			return true
		}
	}
	return false
}

// TestHostFilesystemRulesAllowTheStatxCalls pins the two forms of statx that
// hostfs makes after the lockdown. A path form names an entry inside a pinned
// directory and passes AT_SYMLINK_NOFOLLOW and AT_NO_AUTOMOUNT. A descriptor
// form passes an empty path and AT_EMPTY_PATH. The path form needs the rule of
// the host filesystem, and the descriptor form needs only the base rule.
func TestHostFilesystemRulesAllowTheStatxCalls(t *testing.T) {
	plat := platform.StaticSeccompInfo{PlatformName: "test", Filters: seccomp.NewSyscallRules()}
	with, _ := config.Rules(config.Options{Platform: plat, HostFilesystem: true})
	without, _ := config.Rules(config.Options{Platform: plat})
	if !with.Has(unix.SYS_STATX) {
		t.Fatal("the host filesystem rules lack statx, so hostfs stat calls kill the process after the lockdown")
	}
	if !without.Has(unix.SYS_STATX) {
		t.Fatal("the base rules lack statx, so descriptor stat calls of hostfs kill the process after the lockdown")
	}

	pathFlags := seccomp.EqualTo(unix.AT_SYMLINK_NOFOLLOW | unix.AT_NO_AUTOMOUNT)
	emptyPath := seccomp.MaskedEqual(unix.AT_EMPTY_PATH, unix.AT_EMPTY_PATH)

	flags := statxArgReprs(t, with, 2)
	if !containsRepr(flags, pathFlags) {
		t.Errorf("the host filesystem rules lack statx with flags AT_SYMLINK_NOFOLLOW|AT_NO_AUTOMOUNT; flag matchers: %v", flags)
	}
	if !containsRepr(flags, emptyPath) {
		t.Errorf("the host filesystem rules lack statx with AT_EMPTY_PATH; flag matchers: %v", flags)
	}
	for _, r := range statxArgReprs(t, with, 0) {
		if r != reprOf(seccomp.NonNegativeFD{}) {
			t.Errorf("statx accepts a descriptor matcher %q that is not a non-negative descriptor", r)
		}
	}

	baseFlags := statxArgReprs(t, without, 2)
	if !containsRepr(baseFlags, emptyPath) {
		t.Errorf("the base rules lack statx with AT_EMPTY_PATH; flag matchers: %v", baseFlags)
	}
	if containsRepr(baseFlags, pathFlags) {
		t.Errorf("the base rules allow the path form of statx without a host directory")
	}
}
