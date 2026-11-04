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

//go:build darwin || windows || linux

package e2e

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// GVXIP-005 section 4.1 tests A1 to A7 check the kernel interfaces that a
// Kubernetes node agent reads and writes. The guest is the program nodeprobe,
// the only process of a sandbox without an image, so the tests need no
// registry. The tests set no flag and use no setting that is specific to
// Kubernetes.

// runNodeProbe runs nodeprobe with args in a sandbox. setup changes the
// configuration, or is nil.
func runNodeProbe(t *testing.T, b gateBackend, bin string, setup func(*gvx.Config), args ...string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var out, errOut bytes.Buffer
	cfg := gvx.Config{
		Platform:            b.plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		BinaryPath:          bin,
		Argv:                append([]string{"/bin/app"}, args...),
		Stdout:              &out,
		Stderr:              &errOut,
		DisableHostLockdown: true,
	}
	if setup != nil {
		setup(&cfg)
	}
	sb, err := gvx.New(ctx, cfg)
	skipWhenFixedAddressRefused(t, "New(nodeprobe)", err)
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	}()
	code, err := sb.Run(ctx)
	skipWhenFixedAddressRefused(t, "Run(nodeprobe)", err)
	if errOut.Len() > 0 {
		t.Logf("guest stderr:\n%s", errOut.String())
	}
	return code, out.String()
}

// requireNodeChecks fails the test unless the probe exited with 0, printed DONE,
// printed no FAIL line, and printed PASS for every named check.
func requireNodeChecks(t *testing.T, code int, out string, names ...string) {
	t.Helper()
	t.Logf("nodeprobe output:\n%s", out)
	if code != 0 || !strings.Contains(out, "DONE") || strings.Contains(out, "FAIL ") {
		t.Errorf("nodeprobe exited with %d", code)
	}
	for _, name := range names {
		if !strings.Contains(out, "PASS "+name+"\n") {
			t.Errorf("check %q did not pass", name)
		}
	}
}

// forEachNodeBackend runs the test body for each backend with the probe built
// for the host architecture.
func forEachNodeBackend(t *testing.T, body func(t *testing.T, b gateBackend, bin string)) {
	t.Helper()
	bin := acceptprog.BuildNodeProbe(t, runtime.GOARCH)
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			body(t, b, bin)
		})
	}
}

// TestE2ENodeKernelA1DevKmsg checks that /dev/kmsg opens, that SEEK_END returns
// 0, that a non-blocking read returns EAGAIN, and that a write returns its length.
func TestE2ENodeKernelA1DevKmsg(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "kmsg")
		requireNodeChecks(t, code, out,
			"kmsg-is-char-device-1-11", "kmsg-open-read-write", "kmsg-seek-end-returns-0",
			"kmsg-nonblocking-read-returns-eagain", "kmsg-poll-reports-no-record", "kmsg-write-returns-length")
	})
}

// TestE2ENodeKernelA2StoredSysctls checks that each stored sysctl returns the
// value that a write set, and that a value outside the Linux range fails with
// EINVAL.
func TestE2ENodeKernelA2StoredSysctls(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "sysctls")
		requireNodeChecks(t, code, out,
			"sysctl-store /proc/sys/vm/overcommit_memory", "sysctl-reject /proc/sys/vm/overcommit_memory",
			"overcommit-memory-accepts-0-1-2",
			"sysctl-store /proc/sys/vm/panic_on_oom", "sysctl-store /proc/sys/kernel/panic",
			"sysctl-store /proc/sys/kernel/panic_on_oops",
			"sysctl-store /proc/sys/kernel/keys/root_maxkeys", "sysctl-store /proc/sys/kernel/keys/root_maxbytes",
			"sysctl-store /proc/sys/kernel/shm_rmid_forced",
			"sysctl-store /proc/sys/net/netfilter/nf_conntrack_max",
			"sysctl-store /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established",
			"sysctl-store /proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait",
			"sysctl-store /sys/module/nf_conntrack/parameters/hashsize",
			"forwarding-files-act-as-ip-forward")
	})
}

// TestE2ENodeKernelA3UnprivilegedPortStart checks the bind rule of
// ip_unprivileged_port_start for TCP and UDP over IPv4 and IPv6, and that each
// network namespace has its own value.
func TestE2ENodeKernelA3UnprivilegedPortStart(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "portstart")
		requireNodeChecks(t, code, out,
			"port-start-default-1024", "nobody-bind-below-1024-fails-with-eacces", "nobody-bind-1024-succeeds",
			"start-0-lets-nobody-bind-port-80", "start-1024-again-refuses-nobody",
			"child-netns-write-keeps-parent-value", "child-netns-start-0-lets-nobody-bind",
			"parent-netns-still-refuses-nobody")
	})
}

// TestE2ENodeKernelA4SafeSysctls checks that each network sysctl that
// Kubernetes calls safe is writable in a network namespace and keeps its old
// value in the parent namespace.
func TestE2ENodeKernelA4SafeSysctls(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "netsysctls")
		var names []string
		for _, s := range []string{
			"ip_unprivileged_port_start", "ip_local_port_range", "tcp_syncookies", "ping_group_range",
			"ip_local_reserved_ports", "tcp_keepalive_time", "tcp_keepalive_intvl", "tcp_keepalive_probes",
			"tcp_fin_timeout",
		} {
			names = append(names, "child-netns-writes "+s)
		}
		names = append(names, "parent-values-before", "parent-values-after",
			"child-keepalive-reaches-new-sockets", "child-port-range-reaches-bind")
		requireNodeChecks(t, code, out, names...)
	})
}

// TestE2ENodeKernelA5Forwarding checks that three network namespaces A, R, and B
// pass ICMP echo from A to B only while R forwards, and that conf/all/forwarding,
// conf/default/forwarding, and ip_forward each switch forwarding.
func TestE2ENodeKernelA5Forwarding(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "forwarding")
		var names []string
		for _, f := range []string{"conf/all/forwarding", "conf/default/forwarding", "ip_forward"} {
			path := "/proc/sys/net/ipv4/" + f
			names = append(names, "forwarding-off-blocks-a-to-b via "+path, "forwarding-on-lets-a-reach-b via "+path)
		}
		names = append(names, "veth-pairs-link-the-namespaces", "a-reaches-r", "router-starts-with-forwarding-off")
		requireNodeChecks(t, code, out, names...)
	})
}

// TestE2ENodeKernelA6Capacity checks that a memory limit sets MemTotal and that
// a CPU quota sets the CPU count of the guest.
func TestE2ENodeKernelA6Capacity(t *testing.T) {
	if runtime.NumCPU() < 2 {
		t.Skip("the test needs a host with two CPUs")
	}
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		const mem = 2 << 30
		code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
			cfg.Resources = gvx.Resources{MemoryBytes: mem, CPUMillis: 2000}
		}, "capacity", strconv.Itoa(mem), "2")
		requireNodeChecks(t, code, out,
			"meminfo-total-follows-the-memory-limit", "sysinfo-total-follows-the-memory-limit",
			"sched-getaffinity-counts-the-cpus", "cpu-online-lists-the-cpus", "cpuinfo-lists-the-cpus")
	})
}

// TestE2ENodeKernelA7Statistics checks that the counters of eth0 and of the root
// disk grow with network traffic and file I/O.
func TestE2ENodeKernelA7Statistics(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen on the host: %v", err)
		}
		defer ln.Close()
		go serveStream(ln, 1<<20)
		port := ln.Addr().(*net.TCPAddr).Port
		code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
			cfg.NetworkMode = gvx.NetModeNAT
		}, "stats", net.JoinHostPort("10.0.2.2", strconv.Itoa(port)))
		requireNodeChecks(t, code, out,
			"link-directories-list-the-links", "link-attributes", "link-statistics-files-exist",
			"eth0-counters-grow", "sysfs-agrees-with-proc-net-dev", "diskstats-counters-grow")
	})
}

// serveStream accepts connections on ln. Each client sends one line, and the
// server answers with size bytes and closes the connection.
func serveStream(ln net.Listener, size int) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Minute))
			buf := make([]byte, 3)
			if _, err := io.ReadFull(conn, buf); err != nil {
				return
			}
			_, _ = conn.Write(bytes.Repeat([]byte{'s'}, size))
		}()
	}
}

// TestE2ENodeKernelA6MemTotalIsPerSandbox starts three sandboxes of one process
// at once, with the limits 1 GiB and 2 GiB and with no limit. Each guest must
// see its own MemTotal for the whole time that the others run.
func TestE2ENodeKernelA6MemTotalIsPerSandbox(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		const small, large = 1 << 30, 2 << 30
		limits := []struct {
			name  string
			limit int64
		}{{"1g", small}, {"2g", large}, {"none", 0}}
		got := make([]uint64, len(limits))
		t.Run("sandboxes", func(t *testing.T) {
			for i, l := range limits {
				t.Run(l.name, func(t *testing.T) {
					t.Parallel()
					code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
						cfg.Resources = gvx.Resources{MemoryBytes: l.limit}
					}, "memtotal")
					requireNodeChecks(t, code, out, "memtotal-stays-while-other-sandboxes-run")
					_, rest, ok := strings.Cut(out, "MEMTOTAL ")
					if !ok {
						return
					}
					first, _, _ := strings.Cut(rest, "\n")
					got[i], _ = strconv.ParseUint(first, 10, 64)
				})
			}
		})
		if t.Failed() || t.Skipped() {
			return
		}
		if got[0] != small || got[1] != large {
			t.Errorf("MemTotal with limits 1 GiB and 2 GiB = %d and %d, want %d and %d", got[0], got[1], uint64(small), uint64(large))
		}
		if got[2] <= large {
			t.Errorf("MemTotal without a limit = %d, want the RAM of the host, above 2 GiB", got[2])
		}
	})
}
