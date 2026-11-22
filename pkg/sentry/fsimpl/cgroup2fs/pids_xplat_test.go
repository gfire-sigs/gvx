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

package cgroup2fs

import (
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

func TestRootPidsMaxNilKernelAndValidation(t *testing.T) {
	if err := SetRootPidsMax(nil, 10); !errors.Is(err, linuxerr.EINVAL) {
		t.Fatalf("SetRootPidsMax(nil, 10) = %v, want EINVAL", err)
	}
	if cur, lim := RootPidsLimit(nil); cur != 0 || lim != 0 {
		t.Fatalf("RootPidsLimit(nil) = (%d, %d), want (0, 0)", cur, lim)
	}

	fs := newTestFilesystem(t, MemoryEnforcerOptions{})
	root := fs.RootCgroup().(*cgroup)

	// Root cgroup must not expose a guest-writable pids.max file, keeping the
	// host-configured sandbox PID cap tamper-proof from inside the guest.
	ctx := context.WithValues(context.Background(), map[any]any{ktime.CtxRealtimeClock: fixedClock{}})
	if _, err := root.Lookup(ctx, "pids.max"); !errors.Is(err, linuxerr.ENOENT) {
		t.Fatalf("root.Lookup(pids.max) = %v, want ENOENT", err)
	}

	// Reject limits above pidMaxLimit without modifying the active setting.
	if err := setRootPidsMax(root, pidMaxLimit+1); !errors.Is(err, linuxerr.EINVAL) {
		t.Fatalf("setRootPidsMax(pidMaxLimit+1) = %v, want EINVAL", err)
	}
	if cur, lim := rootPidsLimit(root); cur != 0 || lim != 0 {
		t.Fatalf("initial rootPidsLimit = (%d, %d), want (0, 0)", cur, lim)
	}
}

func TestRootPidsMaxEnforcesLimitRollbackRaiseAndHierarchy(t *testing.T) {
	fs := newTestFilesystem(t, MemoryEnforcerOptions{})
	root := fs.RootCgroup().(*cgroup)
	ctx := context.WithValues(context.Background(), map[any]any{
		ktime.CtxRealtimeClock: fixedClock{},
		auth.CtxCredentials:    fs.rootCreds,
	})

	// Set root limit to 2 tasks.
	if err := setRootPidsMax(root, 2); err != nil {
		t.Fatalf("setRootPidsMax(2): %v", err)
	}
	if cur, lim := rootPidsLimit(root); cur != 0 || lim != 2 {
		t.Fatalf("rootPidsLimit after set(2) = (%d, %d), want (0, 2)", cur, lim)
	}

	t1, t2, t3 := &kernel.Task{}, &kernel.Task{}, &kernel.Task{}
	abort1, _, err := root.CanEnter(ctx, t1)
	if err != nil {
		t.Fatalf("CanEnter(t1): %v", err)
	}
	abort2, _, err := root.CanEnter(ctx, t2)
	if err != nil {
		t.Fatalf("CanEnter(t2): %v", err)
	}
	if cur, lim := rootPidsLimit(root); cur != 2 || lim != 2 {
		t.Fatalf("rootPidsLimit with 2 tasks = (%d, %d), want (2, 2)", cur, lim)
	}

	// 3rd task exceeds root pids.max and fails with EAGAIN without leaking count.
	if _, _, err := root.CanEnter(ctx, t3); !errors.Is(err, linuxerr.EAGAIN) {
		t.Fatalf("CanEnter(t3 at limit=2) = %v, want EAGAIN", err)
	}
	if cur, _ := rootPidsLimit(root); cur != 2 {
		t.Fatalf("committed count after rejected CanEnter = %d, want 2", cur)
	}

	// A child cgroup with +pids enabled still obeys the root cgroup's cap.
	root.fs.treeMu.Lock()
	root.setControllersLocked(ctx, []kernel.Cgroup2Ctrl{kernel.Cgroup2PIDs}, nil)
	root.fs.treeMu.Unlock()
	childInode, err := root.NewDir(ctx, "sub", vfs.MkdirOptions{Mode: 0o755})
	if err != nil {
		t.Fatalf("root.NewDir(sub): %v", err)
	}
	child := childInode.(*cgroup)
	if _, _, err := child.CanEnter(ctx, t3); !errors.Is(err, linuxerr.EAGAIN) {
		t.Fatalf("child.CanEnter(t3 while root full) = %v, want EAGAIN", err)
	}

	// Raising root pids.max to 3 immediately unblocks child entry.
	if err := setRootPidsMax(root, 3); err != nil {
		t.Fatalf("setRootPidsMax(3): %v", err)
	}
	abort3, _, err := child.CanEnter(ctx, t3)
	if err != nil {
		t.Fatalf("child.CanEnter(t3 after raising limit to 3): %v", err)
	}
	if cur, lim := rootPidsLimit(root); cur != 3 || lim != 3 {
		t.Fatalf("rootPidsLimit with child task = (%d, %d), want (3, 3)", cur, lim)
	}

	// Clearing limit with 0 or -1 removes enforcement and reports 0 (unlimited).
	if err := setRootPidsMax(root, 0); err != nil {
		t.Fatalf("setRootPidsMax(0): %v", err)
	}
	if cur, lim := rootPidsLimit(root); cur != 3 || lim != 0 {
		t.Fatalf("rootPidsLimit after set(0) = (%d, %d), want (3, 0)", cur, lim)
	}
	t4 := &kernel.Task{}
	abort4, _, err := root.CanEnter(ctx, t4)
	if err != nil {
		t.Fatalf("CanEnter(t4 unlimited): %v", err)
	}

	// Rollbacks return committed count cleanly back to 0.
	abort4()
	abort3()
	abort2()
	abort1()
	if cur, lim := rootPidsLimit(root); cur != 0 || lim != 0 {
		t.Fatalf("rootPidsLimit after rollbacks = (%d, %d), want (0, 0)", cur, lim)
	}
	if err := setRootPidsMax(root, -1); err != nil {
		t.Fatalf("setRootPidsMax(-1): %v", err)
	}
	if _, lim := rootPidsLimit(root); lim != 0 {
		t.Fatalf("rootPidsLimit after set(-1) = %d, want 0", lim)
	}
}
