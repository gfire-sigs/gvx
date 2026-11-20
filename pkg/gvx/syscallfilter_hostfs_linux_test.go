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

	"z.gfire.dev/gvx/internal/xsys/unix"

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

func TestEmbedderRulesAllowOpenat2ForHostDirsOnly(t *testing.T) {
	withDirs := embedderRules(Config{}, true, false)
	if !withDirs.Has(unix.SYS_OPENAT2) {
		t.Error("embedderRules with hostDirs=true lacks openat2")
	}
	withoutDirs := embedderRules(Config{}, false, false)
	if withoutDirs.Has(unix.SYS_OPENAT2) {
		t.Error("embedderRules with hostDirs=false allows openat2")
	}
}

// TestEmbedderRulesAllowFlockOperationsForHostDirs verifies that hostDirs=true
// allows flock(LOCK_SH, LOCK_EX, LOCK_SH|LOCK_NB, LOCK_EX|LOCK_NB, LOCK_UN) on
// non-negative descriptors only, volumes-only allows LOCK_UN only, and neither
// allows flock at all when both hostDirs and volumes are false.
func TestEmbedderRulesAllowFlockOperationsForHostDirs(t *testing.T) {
	none := embedderRules(Config{}, false, false)
	if none.Has(unix.SYS_FLOCK) {
		t.Fatal("embedderRules(hostDirs=false, volumes=false) must not allow flock")
	}

	volOnly := embedderRules(Config{}, false, true)
	if !volOnly.Has(unix.SYS_FLOCK) {
		t.Fatal("embedderRules(hostDirs=false, volumes=true) lacks flock(LOCK_UN)")
	}
	volOps := flockArgReprs(t, volOnly, 1)
	if len(volOps) != 1 || !containsRepr(volOps, seccomp.EqualTo(unix.LOCK_UN)) {
		t.Fatalf("volumes-only flock op matchers = %v, want only LOCK_UN", volOps)
	}

	for _, both := range []bool{false, true} {
		rules := embedderRules(Config{}, true, both)
		if !rules.Has(unix.SYS_FLOCK) {
			t.Fatalf("embedderRules(hostDirs=true, volumes=%v) lacks flock", both)
		}
		for _, r := range flockArgReprs(t, rules, 0) {
			if r != reprOf(seccomp.NonNegativeFD{}) {
				t.Fatalf("flock fd matcher = %q, want NonNegativeFD", r)
			}
		}
		gotOps := flockArgReprs(t, rules, 1)
		for _, wantOp := range []uintptr{
			unix.LOCK_SH,
			unix.LOCK_EX,
			unix.LOCK_SH | unix.LOCK_NB,
			unix.LOCK_EX | unix.LOCK_NB,
			unix.LOCK_UN,
		} {
			if !containsRepr(gotOps, seccomp.EqualTo(wantOp)) {
				t.Errorf("embedderRules(hostDirs=true, volumes=%v) lacks flock op %#x; got %v", both, wantOp, gotOps)
			}
		}
	}
}

func flockArgReprs(t *testing.T, rules seccomp.SyscallRules, arg int) []string {
	t.Helper()
	var out []string
	if err := rules.ForSingleArgument(unix.SYS_FLOCK, arg, func(vm seccomp.ValueMatcher) error {
		out = append(out, reprOf(vm))
		return nil
	}); err != nil {
		t.Fatalf("ForSingleArgument(SYS_FLOCK, %d): %v", arg, err)
	}
	return out
}

func fallocateArgReprs(t *testing.T, rules seccomp.SyscallRules, arg int) []string {
	t.Helper()
	var out []string
	if err := rules.ForSingleArgument(unix.SYS_FALLOCATE, arg, func(vm seccomp.ValueMatcher) error {
		out = append(out, reprOf(vm))
		return nil
	}); err != nil {
		t.Fatalf("ForSingleArgument(SYS_FALLOCATE, %d): %v", arg, err)
	}
	return out
}

// TestEmbedderRulesAllowFallocateKeepSizeForHostDirsOnly verifies that
// embedderRules permits fallocate(FALLOC_FL_KEEP_SIZE) on non-negative
// descriptors only when hostDirs is true, and that merged with config.Rules it
// covers all three hostfs fallocate modes.
func TestEmbedderRulesAllowFallocateKeepSizeForHostDirsOnly(t *testing.T) {
	if embedderRules(Config{}, false, false).Has(unix.SYS_FALLOCATE) {
		t.Fatal("embedderRules(hostDirs=false, volumes=false) must not allow fallocate")
	}
	if embedderRules(Config{}, false, true).Has(unix.SYS_FALLOCATE) {
		t.Fatal("embedderRules(hostDirs=false, volumes=true) must not allow fallocate")
	}

	rules := embedderRules(Config{}, true, false)
	if !rules.Has(unix.SYS_FALLOCATE) {
		t.Fatal("embedderRules(hostDirs=true, volumes=false) lacks fallocate")
	}
	for _, r := range fallocateArgReprs(t, rules, 0) {
		if r != reprOf(seccomp.NonNegativeFD{}) {
			t.Fatalf("fallocate fd matcher = %q, want NonNegativeFD", r)
		}
	}
	modes := fallocateArgReprs(t, rules, 1)
	if len(modes) != 1 || !containsRepr(modes, seccomp.EqualTo(unix.FALLOC_FL_KEEP_SIZE)) {
		t.Fatalf("embedderRules fallocate mode matchers = %v, want only FALLOC_FL_KEEP_SIZE", modes)
	}

	plat := platform.StaticSeccompInfo{PlatformName: "test", Filters: seccomp.NewSyscallRules()}
	merged, _ := config.Rules(config.Options{Platform: plat, HostFilesystem: true})
	merged.Merge(rules)
	mergedModes := fallocateArgReprs(t, merged, 1)
	for _, wantMode := range []uintptr{
		0,
		unix.FALLOC_FL_KEEP_SIZE,
		unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE,
	} {
		if !containsRepr(mergedModes, seccomp.EqualTo(wantMode)) {
			t.Errorf("merged hostfs rules lack fallocate mode %#x; got %v", wantMode, mergedModes)
		}
	}
}
