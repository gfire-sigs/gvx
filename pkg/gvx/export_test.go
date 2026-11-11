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

package gvx

import (
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

// PreparedMountForTest describes one prepared sandbox mount for black-box tests.
type PreparedMountForTest struct {
	Mount
	Workspace *hostfs.Workspace
	HostPath  string
	HostFile  bool
}

// NormalizeConfigForTest validates and normalizes cfg.
func NormalizeConfigForTest(cfg *Config) error {
	return cfg.normalize()
}

// SortMountPathsByDepthForTest orders guest mount paths by depth.
func SortMountPathsByDepthForTest(paths []string) []string {
	mounts := make([]sandboxMount, len(paths))
	for i, p := range paths {
		mounts[i] = sandboxMount{Mount: Mount{GuestPath: p}}
	}
	sortMountsByDepth(mounts)
	out := make([]string, len(mounts))
	for i, m := range mounts {
		out[i] = m.GuestPath
	}
	return out
}

// NewSandboxForMountTest creates an unbooted Sandbox with cfg for mount tests.
func NewSandboxForMountTest(cfg Config) *Sandbox {
	return &Sandbox{cfg: cfg}
}

// OpenMountsForTest prepares the mounts of sb without booting the Sentry kernel.
func OpenMountsForTest(sb *Sandbox) error {
	return sb.openMounts()
}

// CloseMountsForTest releases the prepared mounts of sb.
func CloseMountsForTest(sb *Sandbox) error {
	return sb.closeMounts()
}

// PreparedMountsForTest returns the prepared mounts of sb in mount order.
func PreparedMountsForTest(sb *Sandbox) []PreparedMountForTest {
	out := make([]PreparedMountForTest, len(sb.mounts))
	for i, m := range sb.mounts {
		out[i] = PreparedMountForTest{
			Mount:     m.Mount,
			Workspace: m.workspace,
			HostPath:  m.hostPath,
			HostFile:  m.hostFile,
		}
	}
	return out
}

// HostMountsForTest returns the host lockdown mount descriptors of sb.
func HostMountsForTest(sb *Sandbox) []hostlockdown.HostMount {
	return sb.hostMounts()
}

// UsesHostDirsForTest reports whether sb uses host directories or files.
func UsesHostDirsForTest(sb *Sandbox) bool {
	return sb.usesHostDirs()
}

// OpenWorkspaceCountForTest returns the number of open hostfs workspaces on sb.
func OpenWorkspaceCountForTest(sb *Sandbox) int {
	return len(sb.workspaces)
}

// OpenVolumeCountForTest returns the number of open ext4lite volumes on sb.
func OpenVolumeCountForTest(sb *Sandbox) int {
	return len(sb.volumes)
}

// VolumeRootForTest returns the directory that stores named volume images for cfg.
func VolumeRootForTest(cfg Config) (string, error) {
	return cfg.volumeRoot()
}

// HasHostDirsForTest reports whether cfg configures any host directory or file mount.
func HasHostDirsForTest(cfg Config) bool {
	return cfg.hasHostDirs()
}

// TmpfsMountDataForTest formats the tmpfs mount data string for sizeBytes.
func TmpfsMountDataForTest(sizeBytes int64) string {
	return tmpfsMountData(sizeBytes)
}
