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
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"z.gfire.dev/gvx/pkg/gvx/shm"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// SPIVersion increments when an exported Extension SPI contract changes.
const SPIVersion = 1

var (
	// ErrLockdownActive reports that host lockdown is already active in this
	// process and cannot grant new helper spawns or seccomp descriptors.
	ErrLockdownActive = errors.New("gvx: host lockdown already active in this process")

	// ErrCheckpointExtensionUnsupported reports that an active extension or
	// imported shared-memory region does not support checkpoint or restore.
	ErrCheckpointExtensionUnsupported = errors.New("gvx: active extension or imported shared memory does not support checkpointing")

	// ErrSandboxClosing reports that a Sandbox method ran after Close started.
	ErrSandboxClosing = errors.New("gvx: sandbox is closing")
)

// CheckpointPolicy describes whether a BoundExtension supports checkpointing.
// The zero value fails closed as CheckpointUnsupported.
type CheckpointPolicy int

const (
	// CheckpointUnsupported disables Checkpoint and CheckpointStream for the
	// sandbox while keeping other control-socket operations active.
	CheckpointUnsupported CheckpointPolicy = iota
	// CheckpointSupported allows checkpointing when no shared memory was imported.
	CheckpointSupported
)

// ExtensionLockdown declares minimal pre-lockdown OS grants required by a
// BoundExtension. Core translates these fields into OS confinement rules;
// extensions never supply raw BPF programs or Seatbelt profiles.
type ExtensionLockdown struct {
	// RecvMsgFDs lists pre-opened socketpair file descriptors on which the
	// extension receives ancillary descriptors via recvmsg(2) on Linux. Core
	// pins SYS_RECVMSG to each listed FD and never allows SYS_SENDMSG.
	RecvMsgFDs []int
}

// HelperSpec configures one pre-lockdown host worker process launched via
// PreLockdownEnv.SpawnHelper.
type HelperSpec struct {
	// Name labels the worker in logs and status output.
	Name string
	// Path is the host executable path to launch.
	Path string
	// Args lists command-line arguments passed after Path.
	Args []string
	// Env overrides the worker environment when non-nil.
	Env []string
	// Dir sets the worker working directory when non-empty.
	Dir string
	// ExtraFiles lists additional open files inherited by POSIX helpers
	// starting at descriptor 3.
	ExtraFiles []*os.File
	// Stdin, Stdout, and Stderr configure worker standard I/O streams.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

// Extension configures an optional host-backed capability for one Sandbox.
// Implementations must be immutable and safe to reuse across Sandboxes.
type Extension interface {
	Name() string
	Validate(env ValidationEnv) error
	OpenPreLockdown(ctx context.Context, env PreLockdownEnv) (BoundExtension, error)
}

// ValidationEnv supplies sandbox configuration to Extension.Validate before
// opening any host handles.
type ValidationEnv struct {
	GOOS          string
	GOARCH        string
	Platform      PlatformType
	NetworkMode   NetworkMode
	HasCheckpoint bool // True when CheckpointDir != ""; ignores ControlListener.
	IsRestore     bool
}

// PreLockdownEnv supplies per-sandbox host resources to Extension.OpenPreLockdown
// before hostlockdown.Apply runs.
type PreLockdownEnv struct {
	PlatformName     string // "hvf", "whpx", or "systrap"
	HostMappingAlign uint64 // 16384 on hvf and 16K Linux; 4096 on whpx, 4K Linux, winsystrap
	HostRAMBytes     uint64
	SharedMemory     *shm.Importer
	SpawnHelper      func(ctx context.Context, spec HelperSpec) (*HelperProcess, error)
	Logf             func(format string, args ...any)
}

// KernelEnv supplies per-kernel VFS and shared-memory access to
// BoundExtension.AttachKernel. It deliberately excludes *kernel.Kernel.
type KernelEnv struct {
	VFS          *vfs.VirtualFilesystem
	SharedMemory *shm.Importer
	Logf         func(format string, args ...any)
}

// BoundExtension owns the live pre-lockdown resources of one Extension bound
// to one Sandbox instance.
type BoundExtension interface {
	NeedsHelperSpawn() bool
	LockdownRequirements() ExtensionLockdown
	CheckpointPolicy() CheckpointPolicy
	SysfsTopologies() []sys.TopologyAddition
	AttachKernel(ctx context.Context, kenv *KernelEnv) error
	AbortPending()
	Close(guestUnmapped bool) error
	Inspect() (json.RawMessage, error)
	Stats() (json.RawMessage, error)
}
