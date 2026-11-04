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

//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// readValue returns the content of a sysctl file with its white space joined by
// single spaces. The kernel prints vectors with tabs, and the Sentry may print
// spaces, so the comparison ignores the difference.
func readValue(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.Join(strings.Fields(string(data)), " "), nil
}

// writeValue writes text to a sysctl file with one write call.
func writeValue(path, text string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(text); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// expectValue fails unless the file reads want.
func expectValue(path, want string) error {
	got, err := readValue(path)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s reads %q, want %q", path, got, want)
	}
	return nil
}

// writeAndExpect writes text to the file and expects the file to read want.
func writeAndExpect(path, text, want string) error {
	if err := writeValue(path, text); err != nil {
		return fmt.Errorf("write %q to %s: %w", text, path, err)
	}
	return expectValue(path, want)
}

// rejectValue writes text to the file, expects EINVAL, and expects the file to
// keep its value.
func rejectValue(path, text string) error {
	before, err := readValue(path)
	if err != nil {
		return err
	}
	if err := writeValue(path, text); !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("write %q to %s = %v, want EINVAL", text, path, err)
	}
	return expectValue(path, before)
}

// storedSysctl describes a file that stores the integer or text that a write
// sets.
type storedSysctl struct {
	path string
	// def is the value before the first write.
	def string
	// write is the text that the check writes. The file then reads want.
	write, want string
	// invalid lists texts that must fail with EINVAL.
	invalid []string
}

var storedSysctls = []storedSysctl{
	{path: "/proc/sys/vm/overcommit_memory", def: "0", write: "1", want: "1", invalid: []string{"3", "-1", "x"}},
	{path: "/proc/sys/vm/panic_on_oom", def: "0", write: "2", want: "2", invalid: []string{"3", "-1"}},
	{path: "/proc/sys/kernel/panic", def: "0", write: "10", want: "10", invalid: []string{"x", "99999999999"}},
	{path: "/proc/sys/kernel/panic_on_oops", def: "0", write: "1", want: "1", invalid: []string{"x"}},
	{path: "/proc/sys/kernel/keys/root_maxkeys", def: "1000000", write: "2000000", want: "2000000", invalid: []string{"0", "x"}},
	{path: "/proc/sys/kernel/keys/root_maxbytes", def: "25000000", write: "30000000", want: "30000000", invalid: []string{"0", "x"}},
	{path: "/proc/sys/kernel/shm_rmid_forced", def: "0", write: "1", want: "1", invalid: []string{"2", "-1"}},
	{path: "/proc/sys/net/netfilter/nf_conntrack_max", def: "262144", write: "131072", want: "131072", invalid: []string{"x"}},
	{path: "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established", def: "432000", write: "86400", want: "86400", invalid: []string{"x"}},
	{path: "/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_close_wait", def: "60", write: "3600", want: "3600", invalid: []string{"x"}},
	{path: "/sys/module/nf_conntrack/parameters/hashsize", def: "65536", write: "32768", want: "32768", invalid: []string{"0", "x"}},
}

func storedSysctlChecks() []check {
	var checks []check
	for _, s := range storedSysctls {
		checks = append(checks,
			check{"sysctl-default " + s.path, func() error { return expectValue(s.path, s.def) }},
			check{"sysctl-store " + s.path, func() error { return writeAndExpect(s.path, s.write+"\n", s.want) }},
			check{"sysctl-reject " + s.path, func() error {
				for _, text := range s.invalid {
					if err := rejectValue(s.path, text); err != nil {
						return err
					}
				}
				return nil
			}},
		)
	}
	checks = append(checks,
		check{"overcommit-memory-accepts-0-1-2", func() error {
			for _, v := range []string{"0", "1", "2"} {
				if err := writeAndExpect("/proc/sys/vm/overcommit_memory", v, v); err != nil {
					return err
				}
			}
			return nil
		}},
		check{"forwarding-files-act-as-ip-forward", forwardingFilesAgree},
	)
	return checks
}

// forwardingFilesAgree checks that conf/all/forwarding, conf/default/forwarding,
// and ip_forward show one value for the namespace.
func forwardingFilesAgree() error {
	files := []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv4/conf/all/forwarding",
		"/proc/sys/net/ipv4/conf/default/forwarding",
	}
	for _, writer := range files {
		for _, v := range []string{"1", "0"} {
			if err := writeValue(writer, v); err != nil {
				return fmt.Errorf("write %q to %s: %w", v, writer, err)
			}
			for _, reader := range files {
				if err := expectValue(reader, v); err != nil {
					return fmt.Errorf("after the write of %q to %s: %w", v, writer, err)
				}
			}
		}
	}
	return nil
}

// netSysctl describes a sysctl of a network namespace.
type netSysctl struct {
	name string
	// def is the value of a new namespace. The value unknownDefault means that the
	// check skips the default.
	def string
	// write is the text that the check writes. The file then reads want.
	write, want string
	// invalid lists texts that must fail with EINVAL.
	invalid []string
}

const (
	netIPv4        = "/proc/sys/net/ipv4/"
	unknownDefault = "?"
)

var netSysctls = []netSysctl{
	{name: "ip_unprivileged_port_start", def: "1024", write: "0", want: "0", invalid: []string{"65536", "-1", "x"}},
	{name: "ip_local_port_range", def: unknownDefault, write: "40000 40010", want: "40000 40010", invalid: []string{"x"}},
	{name: "tcp_syncookies", def: "1", write: "2", want: "2", invalid: []string{"3", "-1", "x"}},
	{name: "ping_group_range", def: "1 0", write: "100 200", want: "100 200", invalid: []string{"x"}},
	{name: "ip_local_reserved_ports", def: "", write: "8000-8010,80,81", want: "80-81,8000-8010", invalid: []string{"70000", "10-5", "x"}},
	{name: "tcp_keepalive_time", def: "7200", write: "1800", want: "1800", invalid: []string{"x"}},
	{name: "tcp_keepalive_intvl", def: "75", write: "30", want: "30", invalid: []string{"x"}},
	{name: "tcp_keepalive_probes", def: "9", write: "5", want: "5", invalid: []string{"x"}},
	{name: "tcp_fin_timeout", def: "60", write: "30", want: "30", invalid: []string{"x"}},
}
