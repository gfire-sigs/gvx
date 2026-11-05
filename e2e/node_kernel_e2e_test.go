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
	"sync"
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

// TestE2ENodeKernelA1DevKmsg checks the kernel log of the guest: /dev/kmsg
// (the record format, the position of each open file, the sequence of errors
// EINVAL, EPIPE, and EAGAIN, blocking reads, poll, the three seek calls, the
// write prefix, the rate limit, and the mode printk_devkmsg), syslog(2), the
// sysctls of the log, and the access that kernel.dmesg_restrict controls.
func TestE2ENodeKernelA1DevKmsg(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "kmsg")
		requireNodeChecks(t, code, out,
			"kmsg-boot-messages-are-in-the-ring", "kmsg-first-record-has-sequence-0",
			"kmsg-is-char-device-1-11", "kmsg-open-read-write", "kmsg-seek-end-returns-0",
			"kmsg-seek-set-and-data-return-0", "kmsg-seek-with-offset-fails-with-espipe",
			"kmsg-seek-with-invalid-whence-fails-with-einval", "kmsg-nonblocking-read-returns-eagain",
			"kmsg-write-returns-length", "kmsg-write-of-more-than-1024-bytes-fails-with-einval", "kmsg-pread-fails-with-espipe",
			"kmsg-write-splits-lines-into-records-with-the-prefix", "kmsg-write-without-prefix-has-user-facility-and-level-4",
			"kmsg-read-into-a-small-buffer-fails-with-einval-and-skips-the-record", "kmsg-read-of-an-escaped-record-is-at-most-2048-bytes",
			"kmsg-each-open-file-has-its-own-position",
			"kmsg-blocking-read-waits-for-a-record", "kmsg-poll-reports-a-record-and-is-never-writable",
			"kmsg-ratelimit-allows-ten-writes-for-each-open-file", "kmsg-printk-devkmsg-off-refuses-opens-and-drops-writes-and-on-keeps-all",
			"kmsg-sysctls-show-and-set-the-values", "kmsg-overwrite-returns-epipe-once-then-continues",
			"kmsg-seek-data-follows-syslog-clear", "kmsg-dmesg-restrict-needs-cap-syslog-to-read",
			"syslog-size-buffer-is-the-ring-size", "syslog-read-all-returns-the-text-form",
			"syslog-read-all-returns-only-whole-records-that-fit", "syslog-read-all-with-a-null-buffer-fails-with-einval",
			"syslog-unknown-command-fails-with-einval", "syslog-read-clear-returns-the-log-and-clears-it",
			"syslog-clear-hides-the-records-from-read-all", "syslog-read-consumes-and-size-unread-counts",
			"syslog-read-blocks-until-a-record-arrives", "syslog-console-commands-set-console-loglevel")
	})
}

// TestE2ENodeKernelA1KernelLogSize checks that the tunable kernel.log_buf_len
// sets the ring size that syslog(2) reports, rounded up to a power of two.
func TestE2ENodeKernelA1KernelLogSize(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
			tuned, err := cfg.Tuning.Set("kernel.log_buf_len", "300KiB")
			if err != nil {
				t.Fatal(err)
			}
			cfg.Tuning = tuned
		}, "kmsg-size", "524288")
		requireNodeChecks(t, code, out, "syslog-size-buffer-follows-the-tunable")
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
// ip_unprivileged_port_start for TCP and UDP over IPv4 and IPv6. The root
// network namespace of the sandbox starts at 0, a namespace that the guest
// creates starts at 1024, and each namespace keeps its own value.
func TestE2ENodeKernelA3UnprivilegedPortStart(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "portstart")
		requireNodeChecks(t, code, out,
			"root-netns-starts-at-0", "root-netns-lets-nobody-bind-port-80",
			"start-1024-refuses-nobody-below-1024", "start-1024-lets-nobody-bind-1024",
			"start-0-lets-nobody-bind-port-80", "child-netns-starts-at-1024",
			"child-netns-refuses-nobody-below-1024", "child-netns-write-keeps-parent-value",
			"child-netns-value-leaves-parent-binds")
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
// pass ICMP echo from A to B only while R forwards. ip_forward and
// conf/all/forwarding switch the links that exist. conf/default/forwarding
// switches only the links that R creates later. A new network namespace gets
// the IPv4 switches of the root namespace.
func TestE2ENodeKernelA5Forwarding(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "forwarding")
		var names []string
		for _, f := range []string{"conf/all/forwarding", "ip_forward"} {
			path := "/proc/sys/net/ipv4/" + f
			names = append(names, "forwarding-off-blocks-a-to-b via "+path, "forwarding-on-lets-a-reach-b via "+path)
		}
		names = append(names, "veth-pairs-link-the-namespaces", "a-reaches-r", "router-starts-with-forwarding-off",
			"new-netns-inherits-ipv4-forwarding-of-the-root", "new-netns-starts-with-ipv6-forwarding-off",
			"new-netns-follows-the-root-when-forwarding-is-off",
			"default-forwarding-leaves-existing-links-off", "links-created-after-default-forwarding-forward")
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
		if b.plat == gvx.PlatformWHPX {
			// A second whpx sandbox that starts while another one runs fails in
			// WHvMapGpaRange (HRESULT 0xc0370008) on windows-latest, with or
			// without serialized creation. The other backends run the test.
			t.Skip("the whpx backend cannot hold two running sandboxes in one process")
		}
		const small, large = 1 << 30, 2 << 30
		limits := []struct {
			name    string
			limit   int64
			writeMB int
		}{{"1g", small, 4}, {"2g", large, 16}, {"none", 0, 0}}
		got := make([]uint64, len(limits))
		sectors := make([]uint64, len(limits))
		ran := make([]bool, len(limits))
		// Each guest prints MemTotal and then waits for the end of its input. The
		// host closes the inputs after every sandbox printed or ended, so the
		// three guests run at the same time. A subtest that skips ends without a
		// line and still releases the others.
		readers := make([]*io.PipeReader, len(limits))
		writers := make([]*io.PipeWriter, len(limits))
		ready := make([]chan struct{}, len(limits))
		var readyOnce [3]sync.Once
		for i := range limits {
			readers[i], writers[i] = io.Pipe()
			ready[i] = make(chan struct{})
		}
		release := func(i int) { readyOnce[i].Do(func() { close(ready[i]) }) }
		go func() {
			for i := range limits {
				select {
				case <-ready[i]:
				case <-time.After(2 * time.Minute):
				}
			}
			for _, w := range writers {
				w.Close()
			}
		}()
		t.Run("sandboxes", func(t *testing.T) {
			for i, l := range limits {
				t.Run(l.name, func(t *testing.T) {
					t.Parallel()
					defer release(i)
					code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
						cfg.Resources = gvx.Resources{MemoryBytes: l.limit}
						cfg.Stdin = readers[i]
						cfg.Stdout = io.MultiWriter(cfg.Stdout, lineWatcher{marker: "MEMTOTAL ", found: func() { release(i) }})
					}, "memtotal", strconv.Itoa(l.writeMB))
					requireNodeChecks(t, code, out, "memtotal-stays-while-other-sandboxes-run", "diskstats-count-only-this-sandbox")
					_, rest, ok := strings.Cut(out, "MEMTOTAL ")
					if !ok {
						return
					}
					first, _, _ := strings.Cut(rest, "\n")
					got[i], _ = strconv.ParseUint(first, 10, 64)
					_, rest, ok = strings.Cut(out, "SECTORS ")
					if !ok {
						return
					}
					written, _, _ := strings.Cut(rest, "\n")
					sectors[i], _ = strconv.ParseUint(written, 10, 64)
					ran[i] = true
				})
			}
		})
		if t.Failed() || !(ran[0] && ran[1] && ran[2]) {
			return
		}
		if got[0] != small || got[1] != large {
			t.Errorf("MemTotal with limits 1 GiB and 2 GiB = %d and %d, want %d and %d", got[0], got[1], uint64(small), uint64(large))
		}
		if got[2] <= large {
			t.Errorf("MemTotal without a limit = %d, want the RAM of the host, above 2 GiB", got[2])
		}
		// A sandbox counts its own writes: at least what it wrote, and less than
		// that plus 1 MiB, which the other sandboxes would add on top.
		for i, l := range limits {
			wrote := uint64(l.writeMB) << 20 / 512
			if sectors[i] < wrote || sectors[i] >= wrote+(1<<20)/512 {
				t.Errorf("sandbox %s: /proc/diskstats shows %d sectors written, want from %d to %d", l.name, sectors[i], wrote, wrote+(1<<20)/512)
			}
		}
	})
}

// lineWatcher is a writer that calls found when the text that it receives
// holds marker. It keeps no text.
type lineWatcher struct {
	marker string
	found  func()
}

func (w lineWatcher) Write(p []byte) (int, error) {
	if strings.Contains(string(p), w.marker) {
		w.found()
	}
	return len(p), nil
}
