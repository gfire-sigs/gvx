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
	"strconv"
	"time"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/usermem"
)

// The files of /proc/sys/net/netfilter that set the connection tracker.
// Each timeout file belongs to one network namespace. The count and bucket
// files are read-only. nf_conntrack_max is one value for the whole kernel, and
// only the root network namespace may write it, as on Linux. See
// net/netfilter/nf_conntrack_standalone.c.

// conntrackTimeoutFiles lists the timeout files of /proc/sys/net/netfilter, in
// seconds, with the range of proc_dointvec_jiffies.
var conntrackTimeoutFiles = []struct {
	name    string
	timeout stack.ConntrackTimeout
}{
	{"nf_conntrack_generic_timeout", stack.ConntrackTimeoutGeneric},
	{"nf_conntrack_tcp_timeout_syn_sent", stack.ConntrackTimeoutTCPSynSent},
	{"nf_conntrack_tcp_timeout_syn_recv", stack.ConntrackTimeoutTCPSynRecv},
	{"nf_conntrack_tcp_timeout_established", stack.ConntrackTimeoutTCPEstablished},
	{"nf_conntrack_tcp_timeout_fin_wait", stack.ConntrackTimeoutTCPFinWait},
	{"nf_conntrack_tcp_timeout_close_wait", stack.ConntrackTimeoutTCPCloseWait},
	{"nf_conntrack_tcp_timeout_last_ack", stack.ConntrackTimeoutTCPLastAck},
	{"nf_conntrack_tcp_timeout_time_wait", stack.ConntrackTimeoutTCPTimeWait},
	{"nf_conntrack_tcp_timeout_close", stack.ConntrackTimeoutTCPClose},
	{"nf_conntrack_tcp_timeout_max_retrans", stack.ConntrackTimeoutTCPMaxRetrans},
	{"nf_conntrack_tcp_timeout_unacknowledged", stack.ConntrackTimeoutTCPUnacknowledged},
	{"nf_conntrack_udp_timeout", stack.ConntrackTimeoutUDP},
	{"nf_conntrack_udp_timeout_stream", stack.ConntrackTimeoutUDPStream},
	{"nf_conntrack_icmp_timeout", stack.ConntrackTimeoutICMP},
	{"nf_conntrack_icmpv6_timeout", stack.ConntrackTimeoutICMPv6},
}

// conntrackNetfilterSpecs returns the stored files of /proc/sys/net/netfilter.
// The stack applies each value after a write.
func conntrackNetfilterSpecs() []*sysctlSpec {
	var specs []*sysctlSpec
	for i, f := range conntrackTimeoutFiles {
		key := "netfilter/" + f.name
		def := int(stack.DefaultConntrackTimeout(f.timeout) / time.Second)
		specs = append(specs, registerSysctlSpec(&sysctlSpec{
			id:    sysctlConntrackTimeoutBase + sysctlID(i),
			scope: scopeNet,
			name:  f.name,
			key:   key,
			def:   strconv.Itoa(def),
			parse: intVecParser(1, 0, maxSysctlSeconds, nil),
			apply: func(s inet.Stack, st sysctlStore) error {
				cs, ok := s.(interface {
					SetConntrackTimeout(stack.ConntrackTimeout, time.Duration)
				})
				if !ok {
					return nil
				}
				cs.SetConntrackTimeout(f.timeout, time.Duration(storedInt(st, key, def))*time.Second)
				return nil
			},
		}))
	}
	// nf_conntrack_tcp_max_retrans is a u8 without a range in Linux.
	const maxRetransKey = "netfilter/nf_conntrack_tcp_max_retrans"
	specs = append(specs, registerSysctlSpec(&sysctlSpec{
		id:    sysctlConntrackTCPMaxRetrans,
		scope: scopeNet,
		name:  "nf_conntrack_tcp_max_retrans",
		key:   maxRetransKey,
		def:   "3",
		parse: intVecParser(1, 0, math.MaxUint8, nil),
		apply: func(s inet.Stack, st sysctlStore) error {
			cs, ok := s.(interface{ SetConntrackTCPMaxRetrans(uint8) })
			if !ok {
				return nil
			}
			cs.SetConntrackTCPMaxRetrans(uint8(storedInt(st, maxRetransKey, 3)))
			return nil
		},
	}))
	return specs
}

// conntrackNetfilterSysctls holds the stored files of /proc/sys/net/netfilter.
var conntrackNetfilterSysctls = conntrackNetfilterSpecs()

// conntrackStack is the network stack of a namespace that has a connection
// tracker. See netstack.Stack.
type conntrackStack interface {
	ConntrackMax() int32
	SetConntrackMax(int32)
	ConntrackCount() int
	ConntrackBuckets() int
}

// conntrackStackOf returns the connection tracker of the network namespace of
// the caller.
func conntrackStackOf(ctx context.Context, fallback inet.Stack) (conntrackStack, error) {
	s, ok := sysctlStack(ctx, fallback).(conntrackStack)
	if !ok {
		return nil, linuxerr.ENOENT
	}
	return s, nil
}

// conntrackMaxFile is nf_conntrack_max in /proc/sys/net/netfilter and in
// /proc/sys/net. Like Linux, the file holds one value for the kernel, shows it
// in every network namespace, and lets only the root network namespace write it.
// A write takes a signed 32-bit integer. The limit is the unsigned value of
// the integer, and 0 means no limit.
//
// +stateify savable
type conntrackMaxFile struct {
	kernfs.DynamicBytesFile

	// stack is the stack of the root network namespace. It serves a caller
	// that has no network namespace of its own.
	stack inet.Stack
}

var _ vfs.WritableDynamicBytesSource = (*conntrackMaxFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *conntrackMaxFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	s, err := conntrackStackOf(ctx, f.stack)
	if err != nil {
		return err
	}
	fmt.Fprintf(buf, "%d\n", s.ConntrackMax())
	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (f *conntrackMaxFile) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	if offset != 0 {
		return 0, linuxerr.EINVAL
	}
	text, n, err := readSysctlText(ctx, src)
	if err != nil || n == 0 {
		return 0, err
	}
	if k := kernel.KernelFromContext(ctx); k != nil {
		if ns := sysctlNamespace(ctx); ns != nil && ns != k.RootNetworkNamespace() {
			// Linux gives the file the mode 0444 in a network namespace
			// that is not the initial one.
			return 0, linuxerr.EACCES
		}
	}
	s, err := conntrackStackOf(ctx, f.stack)
	if err != nil {
		return 0, err
	}
	sysctlWriteMu.Lock()
	defer sysctlWriteMu.Unlock()
	// A write of white space only changes nothing, so the parser starts from the
	// current value.
	val, err := intVecParser(1, math.MinInt32, math.MaxInt32, nil)(text, strconv.Itoa(int(s.ConntrackMax())))
	if err != nil {
		return 0, err
	}
	v, _ := strconv.ParseInt(val, 10, 32)
	s.SetConntrackMax(int32(v))
	return n, nil
}

// conntrackCountFile is nf_conntrack_count or nf_conntrack_buckets. Both files
// are read-only.
//
// +stateify savable
type conntrackCountFile struct {
	kernfs.DynamicBytesFile

	stack   inet.Stack
	buckets bool
}

var _ vfs.DynamicBytesSource = (*conntrackCountFile)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (f *conntrackCountFile) Generate(ctx context.Context, buf *bytes.Buffer) error {
	s, err := conntrackStackOf(ctx, f.stack)
	if err != nil {
		return err
	}
	if f.buckets {
		fmt.Fprintf(buf, "%d\n", s.ConntrackBuckets())
	} else {
		fmt.Fprintf(buf, "%d\n", s.ConntrackCount())
	}
	return nil
}

// addConntrackFiles adds the connection tracker files that are not stored
// sysctls to the /proc/sys directory at path. stack is the stack of the root
// network namespace.
func (fs *filesystem) addConntrackFiles(ctx context.Context, root *auth.Credentials, stack inet.Stack, path string, files map[string]kernfs.Inode) {
	switch path {
	case "net":
		files["nf_conntrack_max"] = fs.newInode(ctx, root, 0644, &conntrackMaxFile{stack: stack})
	case "net/netfilter":
		files["nf_conntrack_max"] = fs.newInode(ctx, root, 0644, &conntrackMaxFile{stack: stack})
		files["nf_conntrack_count"] = fs.newInode(ctx, root, 0444, &conntrackCountFile{stack: stack})
		files["nf_conntrack_buckets"] = fs.newInode(ctx, root, 0444, &conntrackCountFile{stack: stack, buckets: true})
	}
}
