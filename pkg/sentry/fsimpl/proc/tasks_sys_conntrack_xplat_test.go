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
	"errors"
	"math"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/usermem"
)

func newConntrackTestStack(t *testing.T, id uint64) *netstack.Stack {
	t.Helper()
	return netstack.NewStack(stack.New(stack.Options{}), id)
}

// conntrackSpec returns the stored file with the name.
func conntrackSpec(t *testing.T, name string) *sysctlSpec {
	t.Helper()
	for _, spec := range conntrackNetfilterSysctls {
		if spec.name == name {
			return spec
		}
	}
	t.Fatalf("no sysctl file %q", name)
	return nil
}

// writeSysctl does what a write to the file does for a stack: it parses the
// text, stores the value, and applies it.
func writeSysctl(spec *sysctlSpec, s *netstack.Stack, text string) error {
	cur, ok := s.SysctlValue(spec.key)
	if !ok {
		cur = spec.def
	}
	val, err := spec.parse(text, cur)
	if err != nil {
		return err
	}
	s.SetSysctlValue(spec.key, val)
	return spec.apply(s, s)
}

func TestConntrackSysctlDefaultsAreLinuxDefaults(t *testing.T) {
	want := map[string]string{
		"nf_conntrack_generic_timeout":            "600",
		"nf_conntrack_tcp_timeout_syn_sent":       "120",
		"nf_conntrack_tcp_timeout_syn_recv":       "60",
		"nf_conntrack_tcp_timeout_established":    "432000",
		"nf_conntrack_tcp_timeout_fin_wait":       "120",
		"nf_conntrack_tcp_timeout_close_wait":     "60",
		"nf_conntrack_tcp_timeout_last_ack":       "30",
		"nf_conntrack_tcp_timeout_time_wait":      "120",
		"nf_conntrack_tcp_timeout_close":          "10",
		"nf_conntrack_tcp_timeout_max_retrans":    "300",
		"nf_conntrack_tcp_timeout_unacknowledged": "300",
		"nf_conntrack_tcp_max_retrans":            "3",
		"nf_conntrack_udp_timeout":                "30",
		"nf_conntrack_udp_timeout_stream":         "120",
		"nf_conntrack_icmp_timeout":               "30",
		"nf_conntrack_icmpv6_timeout":             "30",
	}
	if len(conntrackNetfilterSysctls) != len(want) {
		t.Errorf("%d stored conntrack files, want %d", len(conntrackNetfilterSysctls), len(want))
	}
	for name, def := range want {
		if got := conntrackSpec(t, name).def; got != def {
			t.Errorf("%s default = %q, want %q", name, got, def)
		}
	}
}

func TestConntrackTimeoutSysctlsApplyTheLinuxRange(t *testing.T) {
	for _, spec := range conntrackNetfilterSysctls {
		if spec.name == "nf_conntrack_tcp_max_retrans" {
			continue
		}
		for _, text := range []string{"0", "1\n", "5", " 432000 ", "8589934"} {
			if _, err := spec.parse(text, spec.def); err != nil {
				t.Errorf("%s rejects %q: %v", spec.name, text, err)
			}
		}
		for _, text := range []string{"-1", "8589935", "x", "1 2", "2147483648"} {
			if got, err := spec.parse(text, spec.def); !errors.Is(err, linuxerr.EINVAL) {
				t.Errorf("%s on %q = %q, %v, want EINVAL", spec.name, text, got, err)
			}
		}
	}
	if maxSysctlSeconds != 8589934 {
		t.Errorf("maxSysctlSeconds = %d, want 8589934 (INT_MAX / 250)", maxSysctlSeconds)
	}
}

func TestConntrackMaxRetransIsAnUnsignedByte(t *testing.T) {
	spec := conntrackSpec(t, "nf_conntrack_tcp_max_retrans")
	for text, want := range map[string]string{"0": "0", "255": "255", "7\n": "7"} {
		if got, err := spec.parse(text, "3"); err != nil || got != want {
			t.Errorf("parse(%q) = %q, %v, want %q", text, got, err, want)
		}
	}
	for _, text := range []string{"256", "-1", "x"} {
		if got, err := spec.parse(text, "3"); !errors.Is(err, linuxerr.EINVAL) {
			t.Errorf("parse(%q) = %q, %v, want EINVAL", text, got, err)
		}
	}
}

func TestConntrackTimeoutSysctlsBelongToTheNamespace(t *testing.T) {
	a, b := newConntrackTestStack(t, 1), newConntrackTestStack(t, 2)
	for _, tc := range []struct {
		file    string
		timeout stack.ConntrackTimeout
	}{
		{"nf_conntrack_tcp_timeout_established", stack.ConntrackTimeoutTCPEstablished},
		{"nf_conntrack_tcp_timeout_syn_sent", stack.ConntrackTimeoutTCPSynSent},
		{"nf_conntrack_tcp_timeout_syn_recv", stack.ConntrackTimeoutTCPSynRecv},
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
		{"nf_conntrack_generic_timeout", stack.ConntrackTimeoutGeneric},
	} {
		t.Run(tc.file, func(t *testing.T) {
			spec := conntrackSpec(t, tc.file)
			def := stack.DefaultConntrackTimeout(tc.timeout)
			if got := a.ConntrackTimeout(tc.timeout); got != def {
				t.Fatalf("timeout before a write = %v, want %v", got, def)
			}
			if err := writeSysctl(spec, a, "7"); err != nil {
				t.Fatal(err)
			}
			if got := a.ConntrackTimeout(tc.timeout); got != 7*time.Second {
				t.Errorf("timeout after the write = %v, want 7s", got)
			}
			if got := b.ConntrackTimeout(tc.timeout); got != def {
				t.Errorf("the other namespace has timeout %v, want %v", got, def)
			}
		})
	}
}

func TestConntrackMaxFileSharesOneKernelValue(t *testing.T) {
	root, child := newConntrackTestStack(t, 1), newConntrackTestStack(t, 2)
	root.InitConntrackLimit(nil)
	child.InitConntrackLimit(root)
	file := &conntrackMaxFile{stack: root}
	ctx := context.Background()

	read := func() string {
		var buf bytes.Buffer
		if err := file.Generate(ctx, &buf); err != nil {
			t.Fatal(err)
		}
		return buf.String()
	}
	if got := read(); got != "262144\n" {
		t.Fatalf("default nf_conntrack_max = %q, want 262144", got)
	}
	write := func(text string) error {
		_, err := file.Write(ctx, nil, usermem.BytesIOSequence([]byte(text)), 0)
		return err
	}
	if err := write("1000\n"); err != nil {
		t.Fatal(err)
	}
	if got, want := read(), "1000\n"; got != want {
		t.Errorf("nf_conntrack_max after a write = %q, want %q", got, want)
	}
	if got := child.ConntrackMax(); got != 1000 {
		t.Errorf("a child namespace sees %d, want the kernel value 1000", got)
	}
	// Linux stores an unsigned integer and prints it as a signed one.
	if err := write("-1"); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "-1\n" {
		t.Errorf("nf_conntrack_max after -1 = %q, want -1", got)
	}
	if got := root.Stack.ConntrackLimit().Max(); got != math.MaxUint32 {
		t.Errorf("limit after -1 = %d, want %d", got, uint32(math.MaxUint32))
	}
	for _, text := range []string{"2147483648", "x", "1 2"} {
		if err := write(text); !errors.Is(err, linuxerr.EINVAL) {
			t.Errorf("write %q = %v, want EINVAL", text, err)
		}
	}
	if err := write("0"); err != nil {
		t.Fatal(err)
	}
	if got := read(); got != "0\n" {
		t.Errorf("nf_conntrack_max after 0 = %q, want 0", got)
	}
}

func TestConntrackCountAndBucketsFilesAreReadOnlyValues(t *testing.T) {
	s := newConntrackTestStack(t, 1)
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		buckets bool
		want    string
	}{
		{"count", false, "0\n"},
		{"buckets", true, "16384\n"},
	} {
		var buf bytes.Buffer
		if err := (&conntrackCountFile{stack: s, buckets: tc.buckets}).Generate(ctx, &buf); err != nil {
			t.Fatal(err)
		}
		if buf.String() != tc.want {
			t.Errorf("nf_conntrack_%s = %q, want %q", tc.name, buf.String(), tc.want)
		}
	}
}
