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

// Package lockdownprobe defines the report of the lockdown probe command.
// The e2e suite decodes the report that the probe prints after it tries to
// escape the host lockdown.
package lockdownprobe

import "z.gfire.dev/gvx/pkg/hostlockdown"

// The WireGuard probe sends WireGuardPayload to WireGuardRemote inside the
// guest Netstack and expects WireGuardReply back from the test peer.
const (
	WireGuardRemote  = "198.51.100.1:9999"
	WireGuardPayload = "wg-after-lockdown"
	WireGuardReply   = "wg-peer-reply"
)

// Report is the JSON result that the probe writes to stdout.
type Report struct {
	// Platform is the backend that Sandbox.PlatformName reports.
	Platform string
	// Lockdown is the status that Sandbox.LockdownStatus reports.
	Lockdown hostlockdown.Status
	// LockedAPI is hostlockdown.IsLockedDown after gvx.New returned.
	LockedAPI bool

	// ReadOutsideErr, WriteOutsideErr, and SpawnErr hold the OS error text
	// of an escape attempt after gvx.New returned. An empty string means the
	// operation succeeded.
	ReadOutsideErr  string
	WriteOutsideErr string
	SpawnErr        string
	// OutsideReadBytes is the content that the outside read returned.
	OutsideReadBytes string

	// DirfdProbed reports that the probe pre-opened directory descriptors
	// before gvx.New and ran descriptor-relative probes after lockdown.
	DirfdProbed bool
	// RootDirfdReadErr and WorkspaceEscapeErr hold the OS error text from
	// opening -outside-file through "/" and "../" from -workspace.
	RootDirfdReadErr   string
	WorkspaceEscapeErr string
	// WorkspaceRWProbeErr holds any error from creating, writing, reading,
	// and unlinking a probe file inside the mounted -workspace directory.
	WorkspaceRWProbeErr string

	// DialAttempted reports that the probe dialed -dial-target after the
	// lockdown. DialErr is the OS error text, empty when the dial worked.
	DialAttempted bool
	DialErr       string

	// WireGuardErr describes the UDP exchange through the WireGuard tunnel
	// after the lockdown. It is empty when the probe sent a datagram and got
	// the reply. The mode -net=wg sets it.
	WireGuardErr string

	// GuestExitCode, GuestStdout, and GuestRunErr describe Sandbox.Run.
	GuestExitCode int
	GuestStdout   string
	GuestRunErr   string
	// NewErr is the gvx.New error text. The other fields stay empty then.
	NewErr string
}
