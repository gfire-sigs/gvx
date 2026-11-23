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

package control

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
)

// RPC method names dispatched in FrameRequest envelopes.
const (
	MethodPing             = "system.ping"
	MethodInspect          = "sandbox.inspect"
	MethodStats            = "sandbox.stats"
	MethodEvents           = "sandbox.events"
	MethodPause            = "lifecycle.pause"
	MethodUnpause          = "lifecycle.unpause"
	MethodStop             = "lifecycle.stop"
	MethodCheckpoint       = "lifecycle.checkpoint"
	MethodCheckpointStream = "lifecycle.checkpoint_stream"
	MethodExecStart        = "exec.start"
	MethodFSStat           = "fs.stat"
	MethodFSExport         = "fs.export"
	MethodFSImport         = "fs.import"
	MethodResourceUpdate   = "resource.update"
	MethodPortList         = "port.list"
	MethodPortAdd          = "port.add"
	MethodPortRemove       = "port.remove"
	MethodNetDial          = "net.dial"
	MethodNATPolicyGet     = "net.policy_get"
	MethodNATPolicySet     = "net.policy_set"
	MethodMountList        = "mount.list"
	MethodMountAdd         = "mount.add"
	MethodMountRemount     = "mount.remount"
	MethodMountRemove      = "mount.remove"
	MethodMountServe       = "mount.serve"
	MethodProcList         = "proc.list"
	MethodProcSignal       = "proc.signal"
	MethodKernelLog        = "kernel.log"
	MethodDebugLogLevel    = "debug.log_level"
)

// Capability identifiers advertised in HelloResponse.Capabilities.
const (
	CapPing                = "system.ping"
	CapInspect             = "sandbox.inspect"
	CapStats               = "sandbox.stats"
	CapEvents              = "sandbox.events"
	CapPause               = "lifecycle.pause"
	CapStop                = "lifecycle.stop"
	CapCheckpointLocal     = "checkpoint.local"
	CapCheckpointStream    = "checkpoint.stream"
	CapExec                = "exec"
	CapExecTTY             = "exec.tty"
	CapFSExport            = "fs.export"
	CapFSImport            = "fs.import"
	CapResourceMemory      = "resource.memory"
	CapResourceCPU         = "resource.cpu"
	CapResourcePids        = "resource.pids"
	CapResourceNetwork     = "resource.network"
	CapResourceTuning      = "resource.tuning"
	CapPortList            = "port.list"
	CapPortRemove          = "port.remove"
	CapPortDynamicLoopback = "port.dynamic_loopback"
	CapPortDynamicAny      = "port.dynamic_any"
	CapPortAnyBind         = "port.any_bind"
	CapNetDial             = "net.dial"
	CapNATPolicyRead       = "net.policy.read"
	CapNATPolicyWrite      = "net.policy.write"
	CapMountList           = "mount.list"
	CapMountTmpfs          = "mount.tmpfs"
	CapMountRemount        = "mount.remount"
	CapMountRemove         = "mount.remove"
	CapMountVolumeAttach   = "mount.volume_attach"
	CapMountBind           = "mount.bind"
	CapMountServe          = "mount.serve"
	CapProcList            = "proc.list"
	CapProcSignal          = "proc.signal"
	CapKernelLog           = "kernel.log"
	CapKernelLogClear      = "kernel.log_clear"
	CapDebug               = "debug"
)

var allKnownCapabilities = []string{
	CapPing,
	CapInspect,
	CapStats,
	CapEvents,
	CapPause,
	CapStop,
	CapCheckpointLocal,
	CapCheckpointStream,
	CapExec,
	CapExecTTY,
	CapFSExport,
	CapFSImport,
	CapResourceMemory,
	CapResourceCPU,
	CapResourcePids,
	CapResourceNetwork,
	CapResourceTuning,
	CapPortList,
	CapPortRemove,
	CapPortDynamicLoopback,
	CapPortDynamicAny,
	CapPortAnyBind,
	CapNetDial,
	CapNATPolicyRead,
	CapNATPolicyWrite,
	CapMountList,
	CapMountTmpfs,
	CapMountRemount,
	CapMountRemove,
	CapMountVolumeAttach,
	CapMountBind,
	CapMountServe,
	CapProcList,
	CapProcSignal,
	CapKernelLog,
	CapKernelLogClear,
	CapDebug,
}

// ValidateDisableList verifies that every entry in disabled names a known
// capability or capability group prefix.
func ValidateDisableList(disabled []string) error {
	for _, raw := range disabled {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" {
			continue
		}
		matched := false
		for _, capName := range allKnownCapabilities {
			if capName == d || strings.HasPrefix(capName, d+".") {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("unknown control capability or group %q in disable list", raw)
		}
	}
	return nil
}

// Policy selects the baseline set of control capabilities exposed by a sandbox.
type Policy string

const (
	// PolicyDefault enables all capabilities compatible with host lockdown.
	PolicyDefault Policy = "default"
	// PolicyReadOnly allows only observation and read-only export operations.
	PolicyReadOnly Policy = "readonly"
	// PolicyCheckpointOnly allows only ping, inspect, and checkpoint operations.
	PolicyCheckpointOnly Policy = "checkpoint-only"
)

// ParsePolicy validates a policy string. An empty string selects PolicyDefault.
func ParsePolicy(raw string) (Policy, error) {
	switch p := Policy(strings.ToLower(strings.TrimSpace(raw))); p {
	case "", PolicyDefault:
		return PolicyDefault, nil
	case PolicyReadOnly, PolicyCheckpointOnly:
		return p, nil
	default:
		return "", fmt.Errorf("unsupported control policy %q (want default, readonly, or checkpoint-only)", raw)
	}
}

var readOnlyCapabilities = map[string]bool{
	CapPing:          true,
	CapInspect:       true,
	CapStats:         true,
	CapEvents:        true,
	CapFSExport:      true,
	CapPortList:      true,
	CapNATPolicyRead: true,
	CapMountList:     true,
	CapProcList:      true,
	CapKernelLog:     true,
}

var checkpointOnlyCapabilities = map[string]bool{
	CapPing:             true,
	CapInspect:          true,
	CapCheckpointLocal:  true,
	CapCheckpointStream: true,
}

// methodRequiredCap maps each RPC method to its baseline policy capability.
var methodRequiredCap = map[string]string{
	MethodPing:             CapPing,
	MethodInspect:          CapInspect,
	MethodStats:            CapStats,
	MethodEvents:           CapEvents,
	MethodPause:            CapPause,
	MethodUnpause:          CapPause,
	MethodStop:             CapStop,
	MethodCheckpoint:       CapCheckpointLocal,
	MethodCheckpointStream: CapCheckpointStream,
	MethodExecStart:        CapExec,
	MethodFSStat:           CapFSExport,
	MethodFSExport:         CapFSExport,
	MethodFSImport:         CapFSImport,
	MethodResourceUpdate:   CapResourceMemory, // checked per-field as well
	MethodPortList:         CapPortList,
	MethodPortAdd:          CapPortDynamicLoopback,
	MethodPortRemove:       CapPortRemove,
	MethodNetDial:          CapNetDial,
	MethodNATPolicyGet:     CapNATPolicyRead,
	MethodNATPolicySet:     CapNATPolicyWrite,
	MethodMountList:        CapMountList,
	MethodMountAdd:         CapMountTmpfs, // checked per-kind as well
	MethodMountRemount:     CapMountRemount,
	MethodMountRemove:      CapMountRemove,
	MethodMountServe:       CapMountServe,
	MethodProcList:         CapProcList,
	MethodProcSignal:       CapProcSignal,
	MethodKernelLog:        CapKernelLog,
	MethodDebugLogLevel:    CapDebug,
}

// FilterCapabilities intersects runtime-available capabilities with policy and
// explicit disable entries (either exact capability names or group prefixes
// such as "exec", "fs", "port", "mount", "resource", "net.dial").
func FilterCapabilities(available []string, policy Policy, disabled []string) []string {
	if policy == "" {
		policy = PolicyDefault
	}
	out := make([]string, 0, len(available))
	for _, capName := range available {
		switch policy {
		case PolicyReadOnly:
			if !readOnlyCapabilities[capName] {
				continue
			}
		case PolicyCheckpointOnly:
			if !checkpointOnlyCapabilities[capName] {
				continue
			}
		}
		if capDisabled(capName, disabled) {
			continue
		}
		out = append(out, capName)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func capDisabled(capName string, disabled []string) bool {
	for _, raw := range disabled {
		d := strings.ToLower(strings.TrimSpace(raw))
		if d == "" {
			continue
		}
		if capName == d || strings.HasPrefix(capName, d+".") {
			return true
		}
	}
	return false
}

// MethodAllowed reports whether method is permitted under caps.
func MethodAllowed(method string, caps []string) bool {
	if method == MethodResourceUpdate {
		for _, c := range []string{CapResourceMemory, CapResourceCPU, CapResourcePids, CapResourceNetwork, CapResourceTuning} {
			if slices.Contains(caps, c) {
				return true
			}
		}
		return false
	}
	if method == MethodPortAdd {
		return slices.Contains(caps, CapPortDynamicLoopback) || slices.Contains(caps, CapPortDynamicAny) || slices.Contains(caps, CapPortAnyBind)
	}
	if method == MethodMountAdd {
		return slices.Contains(caps, CapMountTmpfs) || slices.Contains(caps, CapMountVolumeAttach) || slices.Contains(caps, CapMountBind)
	}
	req, ok := methodRequiredCap[method]
	if !ok {
		return false
	}
	return slices.Contains(caps, req)
}

// FeatureNetQoS advertises support for NAT bandwidth fields in resource updates.
const FeatureNetQoS = "net_qos"

// HelloRequest is sent by the client as the first v2 frame on StreamID 0.
type HelloRequest struct {
	Version  int      `json:"version"`
	Token    string   `json:"token,omitempty"`
	Client   string   `json:"client,omitempty"`
	Features []string `json:"features,omitempty"`
}

// HelloResponse is returned by the server on StreamID 0 after authentication.
type HelloResponse struct {
	OK            bool        `json:"ok"`
	Version       int         `json:"version"`
	SandboxID     string      `json:"sandbox_id,omitempty"`
	MaxFrameBytes int         `json:"max_frame_bytes,omitempty"`
	Capabilities  []string    `json:"capabilities,omitempty"`
	Features      []string    `json:"features,omitempty"`
	Error         *ProtoError `json:"error,omitempty"`
}

// RequestEnvelope is the JSON body of FrameRequest.
type RequestEnvelope struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// ResponseEnvelope is the JSON body of FrameResponse.
type ResponseEnvelope struct {
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *ProtoError     `json:"error,omitempty"`
}

// EventEnvelope is the JSON body of FrameEvent.
type EventEnvelope struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data,omitempty"`
}

// LegacyCheckpointRequest is the v1 JSON checkpoint payload preserved for
// backward compatibility with older clients.
type LegacyCheckpointRequest struct {
	Dir          string `json:"dir,omitempty"`
	LeaveRunning bool   `json:"leave_running,omitempty"`
	Token        string `json:"token,omitempty"`
}

// LegacyCheckpointResponse is the v1 JSON checkpoint reply.
type LegacyCheckpointResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// PingResponse is the result of MethodPing.
type PingResponse struct {
	Version      int      `json:"version"`
	SandboxID    string   `json:"sandbox_id"`
	State        string   `json:"state"`
	UptimeNanos  int64    `json:"uptime_ns"`
	Capabilities []string `json:"capabilities"`
}

// PauseRequest configures MethodPause.
type PauseRequest struct {
	QuiesceNet *bool `json:"quiesce_net,omitempty"`
}

// StopRequest configures MethodStop.
type StopRequest struct {
	Signal    string `json:"signal,omitempty"`
	TimeoutMS *int64 `json:"timeout_ms,omitempty"`
}

// StopResponse reports how the sandbox terminated.
type StopResponse struct {
	Signaled string `json:"signaled"`
	Killed   bool   `json:"killed,omitempty"`
}

// CheckpointRequest configures MethodCheckpoint.
type CheckpointRequest struct {
	Dir          string `json:"dir,omitempty"`
	LeaveRunning bool   `json:"leave_running,omitempty"`
	Force        bool   `json:"force,omitempty"`
}

// CheckpointStreamRequest configures MethodCheckpointStream.
type CheckpointStreamRequest struct {
	LeaveRunning bool `json:"leave_running,omitempty"`
	Force        bool `json:"force,omitempty"`
	Compress     bool `json:"compress,omitempty"`
}

// CheckpointStreamResponse returns metadata before the streamed tar archive.
type CheckpointStreamResponse struct {
	Files []string `json:"files"`
}

// ExecStartRequest configures MethodExecStart.
type ExecStartRequest struct {
	Argv       []string `json:"argv"`
	Env        []string `json:"env,omitempty"`
	WorkDir    string   `json:"workdir,omitempty"`
	User       string   `json:"user,omitempty"`
	Stdin      bool     `json:"stdin,omitempty"`
	TTY        bool     `json:"tty,omitempty"`
	Rows       uint16   `json:"rows,omitempty"`
	Cols       uint16   `json:"cols,omitempty"`
	Detach     bool     `json:"detach,omitempty"`
	Privileged *bool    `json:"privileged,omitempty"`
}

// ExecStartResponse reports the spawned guest PID.
type ExecStartResponse struct {
	PID int32 `json:"pid"`
}

// ExecResizeEvent updates the PTY window size of an active exec session.
type ExecResizeEvent struct {
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// ExecSignalEvent delivers a POSIX signal to an active exec session.
type ExecSignalEvent struct {
	Signal string `json:"signal"`
}

// ExecExitEvent reports the terminal status of an exec session.
type ExecExitEvent struct {
	ExitCode int   `json:"exit_code"`
	Signal   int32 `json:"signal,omitempty"`
}

// FSStatRequest inspects a guest path.
type FSStatRequest struct {
	Path       string `json:"path"`
	FollowLink bool   `json:"follow_link,omitempty"`
}

// FSStatResponse describes one guest filesystem entry.
type FSStatResponse struct {
	Path       string `json:"path"`
	Exists     bool   `json:"exists"`
	Type       string `json:"type,omitempty"` // "file", "dir", "symlink", "other"
	Size       int64  `json:"size"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	MtimeNanos int64  `json:"mtime_ns"`
	LinkTarget string `json:"link_target,omitempty"`
}

// FSExportRequest exports a guest file, directory, or overlay upper layer as tar.
type FSExportRequest struct {
	Path       string `json:"path"`
	FollowLink bool   `json:"follow_link,omitempty"`
	Compress   bool   `json:"compress,omitempty"`
	UpperOnly  bool   `json:"upper_only,omitempty"`
}

// FSExportResponse precedes the exported tar stream.
type FSExportResponse struct {
	Stat FSStatResponse `json:"stat"`
}

// FSImportRequest imports a tar stream into a guest destination directory.
type FSImportRequest struct {
	DestPath       string `json:"dest_path"`
	Archive        bool   `json:"archive,omitempty"`
	NoOverwriteDir bool   `json:"no_overwrite_dir,omitempty"`
	User           string `json:"user,omitempty"`
	Compress       bool   `json:"compress,omitempty"`
}

// FSImportResponse summarizes an import operation.
type FSImportResponse struct {
	FilesWritten int   `json:"files_written"`
	BytesWritten int64 `json:"bytes_written"`
}

// ResourceUpdateRequest updates live sandbox resource limits and mutable tunables.
type ResourceUpdateRequest struct {
	MemoryBytes   *int64 `json:"memory_bytes,omitempty"`
	ForceMemory   bool   `json:"force_memory,omitempty"`
	CPUMillis     *int64 `json:"cpu_millis,omitempty"`
	CPUQuotaUSec  *int64 `json:"cpu_quota_usec,omitempty"`
	CPUPeriodUSec *int64 `json:"cpu_period_usec,omitempty"`
	PidsLimit     *int64 `json:"pids_limit,omitempty"`
	IsolateLAN    *bool  `json:"isolate_lan,omitempty"`
	// Rates are guest-relative bits per second. Nil leaves a rate unchanged; zero clears it.
	NetTXBPS *uint64           `json:"net_tx_bps,omitempty"`
	NetRXBPS *uint64           `json:"net_rx_bps,omitempty"`
	Tuning   map[string]string `json:"tuning,omitempty"`
}

// ResourceSnapshot describes active sandbox resource limits.
type ResourceSnapshot struct {
	MemoryBytes   int64             `json:"memory_bytes"`
	CPUMillis     int64             `json:"cpu_millis"`
	CPUQuotaUSec  int64             `json:"cpu_quota_usec"`
	CPUPeriodUSec int64             `json:"cpu_period_usec"`
	GuestCPUs     int               `json:"guest_cpus"`
	PidsLimit     int64             `json:"pids_limit"`
	IsolateLAN    bool              `json:"isolate_lan"`
	NetTXBPS      uint64            `json:"net_tx_bps"` // Guest to host; zero is unlimited.
	NetRXBPS      uint64            `json:"net_rx_bps"` // Host to guest; zero is unlimited.
	Tuning        map[string]string `json:"tuning,omitempty"`
}

// PortRuleInfo describes one published host-to-guest port rule.
type PortRuleInfo struct {
	Proto      string `json:"proto"`
	HostIP     string `json:"host_ip,omitempty"`
	HostPort   uint16 `json:"host_port,omitempty"`
	HostSocket string `json:"host_socket,omitempty"`
	GuestIP    string `json:"guest_ip"`
	GuestPort  uint16 `json:"guest_port"`
	Source     string `json:"source"` // "static", "auto", "dynamic"
}

// PortListResponse lists all published port rules.
type PortListResponse struct {
	Ports []PortRuleInfo `json:"ports"`
}

// PortAddRequest publishes one or more host-to-guest rules dynamically.
type PortAddRequest struct {
	Specs   []string `json:"specs"`
	Replace bool     `json:"replace,omitempty"`
}

// PortAddResponse returns the newly bound port rules.
type PortAddResponse struct {
	Ports []PortRuleInfo `json:"ports"`
}

// PortRemoveRequest closes one or more published port rules.
type PortRemoveRequest struct {
	Specs      []string `json:"specs,omitempty"`
	AllDynamic bool     `json:"all_dynamic,omitempty"`
	Force      bool     `json:"force,omitempty"`
}

// PortRemoveResponse returns the removed port rules.
type PortRemoveResponse struct {
	Removed []PortRuleInfo `json:"removed"`
}

// NetDialRequest dials a guest TCP/UDP endpoint from the sandbox Netstack.
type NetDialRequest struct {
	Proto            string `json:"proto,omitempty"` // "tcp" (default)
	GuestIP          string `json:"guest_ip,omitempty"`
	GuestPort        uint16 `json:"guest_port"`
	LoopbackFallback bool   `json:"loopback_fallback,omitempty"`
}

// NetDialResponse confirms connection establishment to the guest endpoint.
type NetDialResponse struct {
	RemoteAddr string `json:"remote_addr"`
}

// NATPolicyState carries a NAT policy. A get result contains null if no policy
// is installed. A set request requires a policy object.
type NATPolicyState struct {
	Policy json.RawMessage `json:"policy"`
}

// MountInfo describes one guest mount entry.
type MountInfo struct {
	Target   string `json:"target"`
	Type     string `json:"type"`   // "tmpfs", "hostfs", "ext4lite", "overlay", "rpcfs", "erofs"
	Source   string `json:"source"` // volume name, host path, or label
	ReadOnly bool   `json:"read_only"`
	Mutable  bool   `json:"mutable"` // whether host backing allows remount rw
}

// MountListResponse lists active mounts.
type MountListResponse struct {
	Mounts []MountInfo `json:"mounts"`
}

// MountAddRequest mounts a new filesystem inside the guest.
type MountAddRequest struct {
	Type           string `json:"type"` // "tmpfs", "volume", "bind"
	Source         string `json:"source,omitempty"`
	Target         string `json:"target"`
	ReadOnly       bool   `json:"read_only,omitempty"`
	TmpfsSizeBytes int64  `json:"tmpfs_size_bytes,omitempty"`
}

// MountRemountRequest toggles read-only status on an existing mount.
type MountRemountRequest struct {
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only"`
}

// MountRemoveRequest unmounts one guest mount target.
type MountRemoveRequest struct {
	Target string `json:"target"`
	Detach bool   `json:"detach,omitempty"`
}

// MountServeRequest attaches a client-served proxy filesystem at Target.
type MountServeRequest struct {
	Target     string `json:"target"`
	ReadOnly   bool   `json:"read_only,omitempty"`
	Label      string `json:"label,omitempty"`
	SingleFile bool   `json:"single_file,omitempty"`
}

// MountServeResponse confirms attachment of the proxy mount.
type MountServeResponse struct {
	Target string `json:"target"`
}

// RPCFSRequest is one filesystem operation sent by the sandbox rpcfs driver to
// a connected `mount serve` client over FrameEvent / FrameData.
type RPCFSRequest struct {
	ID       uint64 `json:"id"`
	Op       string `json:"op"` // "stat", "readdir", "read", "write", "create", "mkdir", "unlink", "rmdir", "rename", "truncate", "chmod", "utimens", "readlink", "symlink", "watch", "unwatch"
	Path     string `json:"path"`
	NewPath  string `json:"new_path,omitempty"`
	Offset   int64  `json:"offset,omitempty"`
	Length   int64  `json:"length,omitempty"`
	Size     int64  `json:"size,omitempty"`
	Mode     uint32 `json:"mode,omitempty"`
	Flags    uint32 `json:"flags,omitempty"`
	Data     []byte `json:"data,omitempty"`
	Target   string `json:"target,omitempty"`
	AtimeNS  int64  `json:"atime_ns,omitempty"`
	MtimeNS  int64  `json:"mtime_ns,omitempty"`
	SetAtime bool   `json:"set_atime,omitempty"`
	SetMtime bool   `json:"set_mtime,omitempty"`
}

// RPCFSEntry describes one directory entry or stat result for rpcfs.
type RPCFSEntry struct {
	Name       string `json:"name,omitempty"`
	Ino        uint64 `json:"ino"`
	Mode       uint32 `json:"mode"`
	Size       int64  `json:"size"`
	Nlink      uint32 `json:"nlink"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	AtimeNS    int64  `json:"atime_ns"`
	MtimeNS    int64  `json:"mtime_ns"`
	CtimeNS    int64  `json:"ctime_ns"`
	LinkTarget string `json:"link_target,omitempty"`
}

// RPCFSResponse is the client reply to one RPCFSRequest.
type RPCFSResponse struct {
	ID         uint64       `json:"id"`
	Errno      int          `json:"errno,omitempty"`
	Error      string       `json:"error,omitempty"`
	Entry      *RPCFSEntry  `json:"entry,omitempty"`
	Entries    []RPCFSEntry `json:"entries,omitempty"`
	HasMore    bool         `json:"has_more,omitempty"`
	NextOffset int64        `json:"next_offset,omitempty"`
	Data       []byte       `json:"data,omitempty"`
	EOF        bool         `json:"eof,omitempty"`
	Written    int64        `json:"written,omitempty"`
}

// RPCFSNotifyEvent reports one host-side change on a watched rpcfs path to the
// sandbox over an "rpcfs.notify" stream event.
type RPCFSNotifyEvent struct {
	Path   string `json:"path"`
	Name   string `json:"name,omitempty"`
	Mask   uint32 `json:"mask"`
	Cookie uint32 `json:"cookie,omitempty"`
}

// Canonical Linux open(2) flags, mode_t file-type bits, inotify(7) event bits,
// and errno numbers transmitted in rpcfs wire payloads across heterogeneous
// host OSes.
const (
	LinuxOExcl  uint32 = 0o200
	LinuxSIFMT  uint32 = 0o170000
	LinuxSIFDIR uint32 = 0o040000
	LinuxSIFREG uint32 = 0o100000
	LinuxSIFLNK uint32 = 0o120000

	LinuxInModify     uint32 = 0x00000002
	LinuxInAttrib     uint32 = 0x00000004
	LinuxInMovedFrom  uint32 = 0x00000040
	LinuxInMovedTo    uint32 = 0x00000080
	LinuxInCreate     uint32 = 0x00000100
	LinuxInDelete     uint32 = 0x00000200
	LinuxInDeleteSelf uint32 = 0x00000400
	LinuxInIsDir      uint32 = 0x40000000

	LinuxEPERM        = 1
	LinuxENOENT       = 2
	LinuxEIO          = 5
	LinuxEACCES       = 13
	LinuxEBUSY        = 16
	LinuxEEXIST       = 17
	LinuxEXDEV        = 18
	LinuxENOTDIR      = 20
	LinuxEISDIR       = 21
	LinuxEINVAL       = 22
	LinuxENOSPC       = 28
	LinuxEROFS        = 30
	LinuxENAMETOOLONG = 36
	LinuxENOTEMPTY    = 39
	LinuxELOOP        = 40
	LinuxEOPNOTSUPP   = 95
)

// ProcessInfo describes one guest thread group.
type ProcessInfo struct {
	PID      int32    `json:"pid"`
	PPID     int32    `json:"ppid"`
	PGID     int32    `json:"pgid"`
	SID      int32    `json:"sid"`
	UID      uint32   `json:"uid"`
	GID      uint32   `json:"gid"`
	State    string   `json:"state"`
	Threads  int      `json:"threads"`
	CPUNanos int64    `json:"cpu_ns"`
	RSSBytes uint64   `json:"rss_bytes"`
	Comm     string   `json:"comm"`
	Cmdline  []string `json:"cmdline,omitempty"`
}

// ProcListResponse holds the guest process table snapshot.
type ProcListResponse struct {
	Processes []ProcessInfo `json:"processes"`
}

// ProcSignalRequest sends a POSIX signal to one guest PID or the container.
type ProcSignalRequest struct {
	Signal string `json:"signal"`
	PID    int32  `json:"pid,omitempty"`
	All    bool   `json:"all,omitempty"`
}

// StatsRequest configures MethodStats.
type StatsRequest struct {
	Stream     bool  `json:"stream,omitempty"`
	IntervalMS int64 `json:"interval_ms,omitempty"`
}

// CPUStatsSample holds CPU usage and bandwidth throttling counters.
type CPUStatsSample struct {
	UserNanos      int64  `json:"user_ns"`
	SystemNanos    int64  `json:"sys_ns"`
	Periods        uint64 `json:"periods,omitempty"`
	Throttled      uint64 `json:"throttled,omitempty"`
	ThrottledNanos int64  `json:"throttled_ns,omitempty"`
}

// MemoryStatsSample holds sandbox memory accounting.
type MemoryStatsSample struct {
	TotalBytes uint64 `json:"total_bytes"`
	AnonBytes  uint64 `json:"anon_bytes"`
	FileBytes  uint64 `json:"file_bytes"`
	TmpfsBytes uint64 `json:"tmpfs_bytes"`
	LimitBytes uint64 `json:"limit_bytes"`
}

// NetStatsSample holds per-interface network counters.
type NetStatsSample struct {
	Interface string `json:"interface"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
}

// BlockStatsSample holds per-disk block I/O counters.
type BlockStatsSample struct {
	Disk         string `json:"disk"`
	ReadOps      uint64 `json:"read_ops"`
	WriteOps     uint64 `json:"write_ops"`
	ReadSectors  uint64 `json:"read_sectors"`
	WriteSectors uint64 `json:"write_sectors"`
}

// StatsSample is one point-in-time resource measurement.
type StatsSample struct {
	Timestamp time.Time          `json:"timestamp"`
	CPU       CPUStatsSample     `json:"cpu"`
	Memory    MemoryStatsSample  `json:"memory"`
	Network   []NetStatsSample   `json:"network,omitempty"`
	BlockIO   []BlockStatsSample `json:"block_io,omitempty"`
	PIDs      int                `json:"pids"`
	PIDsLimit int64              `json:"pids_limit"`
}

// KernelLogRequest configures MethodKernelLog.
type KernelLogRequest struct {
	Follow   bool `json:"follow,omitempty"`
	Tail     int  `json:"tail,omitempty"`
	MaxLevel int  `json:"max_level,omitempty"` // 0 means all levels (1..8 shifted or -1)
	Clear    bool `json:"clear,omitempty"`
}

// KernelLogRecord is one entry from the guest kernel log ring.
type KernelLogRecord struct {
	Seq   uint64 `json:"seq"`
	Level int    `json:"level"`
	USec  int64  `json:"usec"`
	Text  string `json:"text"`
}

// KernelLogResponse returns buffered log records for non-streaming calls.
type KernelLogResponse struct {
	Records []KernelLogRecord `json:"records"`
}

// EventsRequest subscribes to sandbox lifecycle events.
type EventsRequest struct {
	Filters []string `json:"filters,omitempty"` // e.g. "type=port", "type=exec"
}

// SandboxEvent is one lifecycle notification emitted by the sandbox.
type SandboxEvent struct {
	Timestamp  time.Time         `json:"timestamp"`
	Type       string            `json:"type"`
	Action     string            `json:"action"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// DebugLogLevelRequest sets the active Sentry log level.
type DebugLogLevelRequest struct {
	Level string `json:"level"` // "warning", "info", "debug"
}

// InspectResponse describes a running sandbox.
type InspectResponse struct {
	ID                 string           `json:"id"`
	Name               string           `json:"name,omitempty"`
	State              string           `json:"state"`
	Platform           string           `json:"platform"`
	Architecture       string           `json:"architecture"`
	SyscallIsolation   string           `json:"syscall_isolation"`
	LockdownApplied    bool             `json:"lockdown_applied"`
	NetworkMode        string           `json:"network_mode"`
	Eth0IP             string           `json:"eth0_ip,omitempty"`
	Eth0MTU            uint32           `json:"eth0_mtu,omitempty"`
	Resources          ResourceSnapshot `json:"resources"`
	MemoryUsedBytes    uint64           `json:"memory_used_bytes"`
	Ports              []PortRuleInfo   `json:"ports,omitempty"`
	DynamicBindAddrs   []string         `json:"dynamic_bind_addrs,omitempty"`
	AutoPublishAddr    string           `json:"auto_publish_addr,omitempty"`
	Mounts             []MountInfo      `json:"mounts,omitempty"`
	ActiveExecSessions int              `json:"active_exec_sessions"`
	PIDCount           int              `json:"pid_count"`
	Capabilities       []string         `json:"capabilities"`
	StartedAt          time.Time        `json:"started_at"`
	UptimeNanos        int64            `json:"uptime_ns"`
}
