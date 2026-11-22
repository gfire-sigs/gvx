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
	"fmt"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

// SetRootPidsMax sets the tamper-proof sandbox-wide PID limit on the root
// cgroup2 pids controller of k. Values <= 0 remove the limit (unlimited).
func SetRootPidsMax(k *kernel.Kernel, limit int64) error {
	if k == nil || k.Cgroup2FS() == nil {
		return linuxerr.EINVAL
	}
	root, ok := k.Cgroup2FS().RootCgroup().(*cgroup)
	if !ok || root == nil {
		return linuxerr.EINVAL
	}
	return setRootPidsMax(root, limit)
}

func setRootPidsMax(root *cgroup, limit int64) error {
	if root == nil {
		return linuxerr.EINVAL
	}
	if limit > pidMaxLimit {
		return fmt.Errorf("cgroup2fs: pids limit %d exceeds maximum %d: %w", limit, pidMaxLimit, linuxerr.EINVAL)
	}
	p := getPidsCtrl(root)
	if p == nil {
		return linuxerr.ENOENT
	}
	p.mu.Lock()
	if limit <= 0 {
		p.max = pidLimitUnlimited
	} else {
		p.max = limit
	}
	p.mu.Unlock()
	return nil
}

// RootPidsLimit returns the current committed task count and configured sandbox
// PID limit (0 when unlimited) on the root cgroup2 pids controller of k.
func RootPidsLimit(k *kernel.Kernel) (current, limit int64) {
	if k == nil || k.Cgroup2FS() == nil {
		return 0, 0
	}
	root, ok := k.Cgroup2FS().RootCgroup().(*cgroup)
	if !ok || root == nil {
		return 0, 0
	}
	return rootPidsLimit(root)
}

func rootPidsLimit(root *cgroup) (current, limit int64) {
	if root == nil {
		return 0, 0
	}
	p := getPidsCtrl(root)
	if p == nil {
		return 0, 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.max == pidLimitUnlimited {
		return p.committed, 0
	}
	return p.committed, p.max
}
