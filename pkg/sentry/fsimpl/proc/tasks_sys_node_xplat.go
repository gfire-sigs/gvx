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

package proc

import (
	"bytes"
	"fmt"
	"math"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode"
	"weak"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The sysctl files of the node agent (kubelet, containerd, runc, and k3s) store
// their values. A file belongs to one of three scopes. A node file has one
// value for the kernel. A network file has one value for each network
// namespace, and the namespace of the reader selects it. An IPC file has one
// value for each IPC namespace. A write checks the range of Linux and returns
// EINVAL for a value outside it. A few network files also set a knob of the
// network stack of the namespace.

// sysctlScope says which object owns the value of a sysctl file.
type sysctlScope int

const (
	scopeNode sysctlScope = iota
	scopeNet
	scopeIPC
)

// sysctlStore holds the text of sysctl values by key.
type sysctlStore interface {
	SysctlValue(key string) (string, bool)
	SetSysctlValue(key, value string)
}

// sysctlSpec describes one stored sysctl file.
type sysctlSpec struct {
	scope sysctlScope
	// name is the name of the file in its directory.
	name string
	// key identifies the value in its store.
	key string
	// def is the value before the first write, without a newline.
	def string
	// parse validates the text of a write and returns the text to store. cur is
	// the stored text, which a vector sysctl updates in part.
	parse func(text, cur string) (string, error)
	// apply sets a knob of the network stack from the stored values. It runs
	// after the store changed. A failure restores the old value.
	apply func(stack inet.Stack, st sysctlStore) error
}

// sysctlWriteMu serializes every write of a stored sysctl. A write reads the old
// text, validates the new text, and stores it. The writes are rare.
var sysctlWriteMu sync.Mutex

// valueStore is the sysctlStore of a scope that has no namespace object.
type valueStore struct {
	mu     sync.Mutex
	values map[string]string
}

// SysctlValue implements sysctlStore.SysctlValue.
func (s *valueStore) SysctlValue(key string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	return v, ok
}

// SetSysctlValue implements sysctlStore.SetSysctlValue.
func (s *valueStore) SetSysctlValue(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = make(map[string]string)
	}
	s.values[key] = value
}

// nodeStores maps a kernel to its node sysctl values. The map holds the kernels
// weakly, so a kernel that a test drops frees its values.
var nodeStores struct {
	mu     sync.Mutex
	stores map[weak.Pointer[kernel.Kernel]]*valueStore
}

// nodeStore returns the node sysctl values of the kernel.
func nodeStore(k *kernel.Kernel) *valueStore {
	key := weak.Make(k)
	nodeStores.mu.Lock()
	defer nodeStores.mu.Unlock()
	if s, ok := nodeStores.stores[key]; ok {
		return s
	}
	if nodeStores.stores == nil {
		nodeStores.stores = make(map[weak.Pointer[kernel.Kernel]]*valueStore)
	}
	s := new(valueStore)
	nodeStores.stores[key] = s
	runtime.AddCleanup(k, func(key weak.Pointer[kernel.Kernel]) {
		nodeStores.mu.Lock()
		defer nodeStores.mu.Unlock()
		delete(nodeStores.stores, key)
	}, key)
	return s
}

// ipcStore adapts the IPC namespace to sysctlStore. The namespace has the
// single value kernel.shm_rmid_forced.
type ipcStore struct {
	ns *kernel.IPCNamespace
}

const shmRmidForcedKey = "shm_rmid_forced"

// SysctlValue implements sysctlStore.SysctlValue.
func (s ipcStore) SysctlValue(key string) (string, bool) {
	if key != shmRmidForcedKey {
		return "", false
	}
	return strconv.Itoa(int(s.ns.ShmRmidForced())), true
}

// SetSysctlValue implements sysctlStore.SetSysctlValue.
func (s ipcStore) SetSysctlValue(key, value string) {
	if key != shmRmidForcedKey {
		return
	}
	v, _ := strconv.Atoi(value)
	s.ns.SetShmRmidForced(int32(v))
}

// sysctlNamespace returns the network namespace of the caller. A context
// without a task gets the root network namespace.
func sysctlNamespace(ctx context.Context) *inet.Namespace {
	if t := kernel.TaskFromContext(ctx); t != nil {
		return t.NetworkNamespace()
	}
	if k := kernel.KernelFromContext(ctx); k != nil {
		return k.RootNetworkNamespace()
	}
	return nil
}

// sysctlStack returns the network stack of the network namespace of the
// caller. It returns fallback when the context names no namespace with a stack.
func sysctlStack(ctx context.Context, fallback inet.Stack) inet.Stack {
	if ns := sysctlNamespace(ctx); ns != nil && ns.Stack() != nil {
		return ns.Stack()
	}
	return fallback
}

// withStore runs f with the store that holds the value of the spec for the
// caller. The network stack is nil for the other scopes. The store of a network
// sysctl is the network stack of the network namespace of the caller.
func (s *sysctlSpec) withStore(ctx context.Context, f func(st sysctlStore, stack inet.Stack) error) error {
	switch s.scope {
	case scopeNet:
		stack := sysctlStack(ctx, nil)
		st, ok := stack.(sysctlStore)
		if !ok {
			return linuxerr.ENOENT
		}
		return f(st, stack)
	case scopeIPC:
		ns := kernel.IPCNamespaceFromContext(ctx)
		if ns == nil {
			return linuxerr.ENOENT
		}
		defer ns.DecRef(ctx)
		return f(ipcStore{ns}, nil)
	default:
		k := kernel.KernelFromContext(ctx)
		if k == nil {
			return linuxerr.ENOENT
		}
		return f(nodeStore(k), nil)
	}
}

// sysctlFile implements vfs.WritableDynamicBytesSource for a stored sysctl.
type sysctlFile struct {
	kernfs.DynamicBytesFile

	spec *sysctlSpec
}

var _ vfs.WritableDynamicBytesSource = (*sysctlFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *sysctlFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	return f.spec.withStore(ctx, func(st sysctlStore, _ inet.Stack) error {
		v, ok := st.SysctlValue(f.spec.key)
		if !ok {
			v = f.spec.def
		}
		buf.WriteString(v)
		buf.WriteByte('\n')
		return nil
	})
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *sysctlFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	text, n, err := readSysctlText(ctx, src)
	if err != nil || n == 0 {
		return 0, err
	}
	sysctlWriteMu.Lock()
	defer sysctlWriteMu.Unlock()
	err = f.spec.withStore(ctx, func(st sysctlStore, stack inet.Stack) error {
		old, had := st.SysctlValue(f.spec.key)
		cur := old
		if !had {
			cur = f.spec.def
		}
		val, err := f.spec.parse(text, cur)
		if err != nil {
			return err
		}
		st.SetSysctlValue(f.spec.key, val)
		if f.spec.apply == nil || stack == nil {
			return nil
		}
		if err := f.spec.apply(stack, st); err != nil {
			st.SetSysctlValue(f.spec.key, cur)
			return err
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

// readSysctlText reads the text of a write. Like the other sysctl files, it
// reads at most one page.
func readSysctlText(ctx context.Context, src usermem.IOSequence) (string, int64, error) {
	if src.NumBytes() == 0 {
		return "", 0, nil
	}
	src = src.TakeFirst(int(hostarch.PageSize) - 1)
	buf := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, buf); err != nil {
		return "", 0, err
	}
	return string(buf), int64(len(buf)), nil
}

// intVecParser returns the parse function of a sysctl with count integers that
// each lie in [lo, hi]. A write may set the first integers only. Whitespace
// alone changes nothing. fix adjusts the vector after a write, or is nil.
func intVecParser(count int, lo, hi int64, fix func([]int64)) func(text, cur string) (string, error) {
	return func(text, cur string) (string, error) {
		fields := strings.Fields(text)
		if len(fields) > count {
			return "", linuxerr.EINVAL
		}
		vals := make([]int64, count)
		for i, f := range strings.Fields(cur) {
			vals[i], _ = strconv.ParseInt(f, 10, 64)
		}
		for i, f := range fields {
			v, err := strconv.ParseInt(f, 10, 64)
			if err != nil || v < lo || v > hi {
				return "", linuxerr.EINVAL
			}
			vals[i] = v
		}
		if fix != nil {
			fix(vals)
		}
		parts := make([]string, count)
		for i, v := range vals {
			parts[i] = strconv.FormatInt(v, 10)
		}
		return strings.Join(parts, "\t"), nil
	}
}

// parseReservedPorts validates and canonicalizes the text of
// ip_local_reserved_ports: ports and ranges "a-b" separated by commas. The
// result lists the sorted ranges, as Linux prints them.
func parseReservedPorts(text, _ string) (string, error) {
	var reserved [math.MaxUint16 + 1]bool
	parts := strings.FieldsFunc(text, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	for _, part := range parts {
		loText, hiText, isRange := strings.Cut(part, "-")
		lo, err := strconv.ParseUint(loText, 10, 16)
		if err != nil {
			return "", linuxerr.EINVAL
		}
		hi := lo
		if isRange {
			if hi, err = strconv.ParseUint(hiText, 10, 16); err != nil || hi < lo {
				return "", linuxerr.EINVAL
			}
		}
		for p := lo; p <= hi; p++ {
			reserved[p] = true
		}
	}
	var out []string
	for p := 0; p < len(reserved); p++ {
		if !reserved[p] {
			continue
		}
		end := p
		for end+1 < len(reserved) && reserved[end+1] {
			end++
		}
		if end == p {
			out = append(out, strconv.Itoa(p))
		} else {
			out = append(out, fmt.Sprintf("%d-%d", p, end))
		}
		p = end
	}
	return strings.Join(out, ","), nil
}

// fixPingGroupRange gives an empty range the form "1 0" that Linux stores.
func fixPingGroupRange(vals []int64) {
	if vals[1] < vals[0] {
		vals[0], vals[1] = 1, 0
	}
}

// Limits of Linux for the sysctls below. A time in seconds must fit in jiffies
// at 250 ticks per second.
const (
	maxSysctlSeconds = math.MaxInt32 / 250
	// maxGroupID is the largest group ID of ping_group_range (gid_t is 32 bits,
	// and Linux keeps 4294967295 for "no group").
	maxGroupID = math.MaxUint32 - 1
)

// nodeSysctlSpecs lists the stored sysctl files by the directory of
// /proc/sys that holds them.
var nodeSysctlSpecs = map[string][]*sysctlSpec{
	"vm": {
		{scope: scopeNode, name: "overcommit_memory", key: "vm/overcommit_memory", def: "0", parse: intVecParser(1, 0, 2, nil)},
		{scope: scopeNode, name: "panic_on_oom", key: "vm/panic_on_oom", def: "0", parse: intVecParser(1, 0, 2, nil)},
	},
	"kernel": {
		{scope: scopeNode, name: "panic", key: "kernel/panic", def: "0", parse: intVecParser(1, math.MinInt32, math.MaxInt32, nil)},
		{scope: scopeNode, name: "panic_on_oops", key: "kernel/panic_on_oops", def: "0", parse: intVecParser(1, math.MinInt32, math.MaxInt32, nil)},
		{scope: scopeIPC, name: "shm_rmid_forced", key: shmRmidForcedKey, def: "0", parse: intVecParser(1, 0, 1, nil)},
	},
	"kernel/keys": {
		{scope: scopeNode, name: "root_maxkeys", key: "kernel/keys/root_maxkeys", def: "1000000", parse: intVecParser(1, 1, math.MaxInt32, nil)},
		{scope: scopeNode, name: "root_maxbytes", key: "kernel/keys/root_maxbytes", def: "25000000", parse: intVecParser(1, 1, math.MaxInt32, nil)},
	},
	"net/ipv4": {
		{scope: scopeNet, name: "ip_unprivileged_port_start", key: netstack.UnprivilegedPortStartKey, def: strconv.Itoa(netstack.DefaultUnprivilegedPortStart), parse: intVecParser(1, 0, math.MaxUint16, nil)},
		{scope: scopeNet, name: "tcp_syncookies", key: "ipv4/tcp_syncookies", def: "1", parse: intVecParser(1, 0, 2, nil), apply: applySynCookies},
		{scope: scopeNet, name: "ping_group_range", key: "ipv4/ping_group_range", def: "1\t0", parse: intVecParser(2, 0, maxGroupID, fixPingGroupRange)},
		{scope: scopeNet, name: "ip_local_reserved_ports", key: "ipv4/ip_local_reserved_ports", def: "", parse: parseReservedPorts},
		{scope: scopeNet, name: "tcp_keepalive_time", key: keepaliveTimeKey, def: "7200", parse: intVecParser(1, 0, maxSysctlSeconds, nil), apply: applyKeepalive},
		{scope: scopeNet, name: "tcp_keepalive_intvl", key: keepaliveIntvlKey, def: "75", parse: intVecParser(1, 0, maxSysctlSeconds, nil), apply: applyKeepalive},
		{scope: scopeNet, name: "tcp_keepalive_probes", key: keepaliveProbesKey, def: "9", parse: intVecParser(1, 1, math.MaxInt32, nil), apply: applyKeepalive},
		{scope: scopeNet, name: "tcp_fin_timeout", key: "ipv4/tcp_fin_timeout", def: "60", parse: intVecParser(1, 0, maxSysctlSeconds, nil), apply: applyFinTimeout},
	},
	"net/netfilter": {
		{scope: scopeNet, name: "nf_conntrack_max", key: "netfilter/nf_conntrack_max", def: "262144", parse: intVecParser(1, math.MinInt32, math.MaxInt32, nil)},
		{scope: scopeNet, name: "nf_conntrack_tcp_timeout_established", key: "netfilter/nf_conntrack_tcp_timeout_established", def: "432000", parse: intVecParser(1, 0, maxSysctlSeconds, nil)},
		{scope: scopeNet, name: "nf_conntrack_tcp_timeout_close_wait", key: "netfilter/nf_conntrack_tcp_timeout_close_wait", def: "60", parse: intVecParser(1, 0, maxSysctlSeconds, nil)},
	},
}

const (
	keepaliveTimeKey   = "ipv4/tcp_keepalive_time"
	keepaliveIntvlKey  = "ipv4/tcp_keepalive_intvl"
	keepaliveProbesKey = "ipv4/tcp_keepalive_probes"
)

// storedInt returns the integer that the store holds for key, or def.
func storedInt(st sysctlStore, key string, def int) int {
	if text, ok := st.SysctlValue(key); ok {
		if v, err := strconv.Atoi(text); err == nil {
			return v
		}
	}
	return def
}

// applySynCookies sets the SYN cookie mode of the stack. The value 2 sends a
// cookie for every SYN. The stack sends cookies only when the accept queue is
// full for the values 0 and 1, so 0 does not turn cookies off.
func applySynCookies(stack inet.Stack, st sysctlStore) error {
	s, ok := stack.(interface{ SetTCPAlwaysUseSynCookies(bool) error })
	if !ok {
		return nil
	}
	return s.SetTCPAlwaysUseSynCookies(storedInt(st, "ipv4/tcp_syncookies", 1) == 2)
}

// stackSeconds converts a stored time in seconds to a duration that the stack
// accepts. Linux takes 0 and larger values, and the stack needs at least one
// second, so a smaller value counts as one second.
func stackSeconds(seconds int) time.Duration {
	return time.Duration(max(seconds, 1)) * time.Second
}

// maxStackKeepaliveProbes is the largest probe count that the stack gets. A
// larger stored value stays in the file and counts as this value.
const maxStackKeepaliveProbes = 127

// applyKeepalive sets the keepalive parameters that new TCP sockets start with.
// The stored values keep the range of Linux, and the stack gets them within
// the range that it accepts.
func applyKeepalive(stack inet.Stack, st sysctlStore) error {
	s, ok := stack.(interface {
		SetTCPKeepaliveDefaults(idle, interval time.Duration, probes int) error
	})
	if !ok {
		return nil
	}
	return s.SetTCPKeepaliveDefaults(
		stackSeconds(storedInt(st, keepaliveTimeKey, 7200)),
		stackSeconds(storedInt(st, keepaliveIntvlKey, 75)),
		min(max(storedInt(st, keepaliveProbesKey, 9), 1), maxStackKeepaliveProbes))
}

// applyFinTimeout sets the FIN-WAIT-2 timeout of the stack.
func applyFinTimeout(stack inet.Stack, st sysctlStore) error {
	s, ok := stack.(interface{ SetTCPFinTimeout(time.Duration) error })
	if !ok {
		return nil
	}
	return s.SetTCPFinTimeout(stackSeconds(storedInt(st, "ipv4/tcp_fin_timeout", 60)))
}

// addNodeSysctlFiles adds the stored sysctl files of the /proc/sys directory at
// path to files. conf/all/forwarding shares its value with ip_forward, and
// conf/default/forwarding has a value of its own.
func (fs *filesystem) addNodeSysctlFiles(ctx context.Context, root *auth.Credentials, k *kernel.Kernel, stack inet.Stack, path string, files map[string]kernfs.Inode) {
	for _, spec := range nodeSysctlSpecs[path] {
		files[spec.name] = fs.newInode(ctx, root, 0644, &sysctlFile{spec: spec})
	}
	switch path {
	case "kernel":
		for name, inode := range fs.kmsgSysctlFiles(ctx, root) {
			files[name] = inode
		}
	case "net/ipv4/conf/all":
		files["forwarding"] = fs.newInode(ctx, root, 0644, &nsForwarding{stack: stack, protocol: ipv4.ProtocolNumber})
	case "net/ipv4/conf/default":
		files["forwarding"] = fs.newInode(ctx, root, 0644, &nsForwarding{stack: stack, protocol: ipv4.ProtocolNumber, isDefault: true})
	}
}

// forwardingStack is a network stack that keeps the forwarding switches of its
// network namespace. See netstack.Stack.SetForwardingSwitch.
type forwardingStack interface {
	Forwarding(protocol tcpip.NetworkProtocolNumber, isDefault bool) bool
	SetForwardingSwitch(protocol tcpip.NetworkProtocolNumber, isDefault, enable bool) error
}

// nsForwarding implements vfs.WritableDynamicBytesSource for ip_forward and the
// forwarding files of the conf directories. It does what ipForwarding does, but
// the values belong to the network namespace of the caller. ip_forward and
// conf/all/forwarding are one switch. A write to it sets conf/default/forwarding
// and every link, as on Linux. A write to conf/default/forwarding changes only
// the links that the guest creates later.
type nsForwarding struct {
	kernfs.DynamicBytesFile

	// stack is the stack of the root network namespace. It serves a caller that
	// has no network namespace of its own.
	stack    inet.Stack
	protocol tcpip.NetworkProtocolNumber
	// isDefault selects conf/default/forwarding.
	isDefault bool
}

var _ vfs.WritableDynamicBytesSource = (*nsForwarding)(nil)

// switches returns the forwarding switches of the network namespace of the caller.
func (f *nsForwarding) switches(ctx context.Context) (forwardingStack, error) {
	s, ok := sysctlStack(ctx, f.stack).(forwardingStack)
	if !ok {
		return nil, linuxerr.ENOENT
	}
	return s, nil
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *nsForwarding) Generate(ctx context.Context, buf *bytes.Buffer) error {
	s, err := f.switches(ctx)
	if err != nil {
		return err
	}
	// Linux preserves the written integer; this file reports a boolean, so a
	// nonzero value such as "2" is read back as "1".
	fmt.Fprintf(buf, "%d\n", boolToInt32(s.Forwarding(f.protocol, f.isDefault)))
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *nsForwarding) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		// No need to handle partial writes thus far.
		return 0, linuxerr.EINVAL
	}
	buf := make([]int32, 1)
	n, err := ParseInt32Vec(ctx, src, buf)
	if err != nil || n == 0 {
		return 0, err
	}
	s, err := f.switches(ctx)
	if err != nil {
		return 0, err
	}
	sysctlWriteMu.Lock()
	defer sysctlWriteMu.Unlock()
	if err := s.SetForwardingSwitch(f.protocol, f.isDefault, buf[0] != 0); err != nil {
		return 0, err
	}
	return n, nil
}
