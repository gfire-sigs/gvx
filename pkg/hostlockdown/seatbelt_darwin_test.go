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

//go:build darwin

package hostlockdown

import (
	"slices"
	"strings"
	"testing"
)

func profileLines(profile string) []string {
	return strings.Split(strings.TrimSuffix(profile, "\n"), "\n")
}

func TestSeatbeltProfileStartsFromDenyDefault(t *testing.T) {
	for _, opts := range []Options{
		{},
		{Mounts: []HostMount{{Path: "/ws"}}},
		{Mounts: []HostMount{{Path: "/ws"}}, AllowOutboundNet: true},
		{Mounts: []HostMount{{Path: "/ws"}}, OutboundUDPPorts: []uint16{51820}},
	} {
		lines := profileLines(BuildSeatbeltProfile(opts))
		if lines[0] != "(version 1)" || lines[1] != "(deny default)" {
			t.Errorf("opts %+v: profile starts with %q, want version then (deny default)", opts, lines[:2])
		}
		for _, line := range lines {
			if strings.Contains(line, "(allow default)") {
				t.Errorf("opts %+v: profile contains %q", opts, line)
			}
		}
	}
}

func TestSeatbeltProfileMinimalOptionsAllowOnlyChildSignals(t *testing.T) {
	got := profileLines(BuildSeatbeltProfile(Options{}))
	want := []string{"(version 1)", "(deny default)", "(allow signal (target children))", "(deny process-fork)", "(deny process-exec*)"}
	if !slices.Equal(got, want) {
		t.Fatalf("profile = %q, want %q", got, want)
	}
}

func TestSeatbeltProfileAllowsOnlyConfiguredResources(t *testing.T) {
	tests := []struct {
		name      string
		opts      Options
		wantAllow []string
	}{
		{
			name: "workspace",
			opts: Options{Mounts: []HostMount{{Path: "/ws"}}},
			wantAllow: []string{
				"(allow signal (target children))",
				`(allow file-read* file-write* (subpath (param "MOUNT_0")))`,
				`(allow file-read* file-write* (subpath (param "MOUNT_0_REAL")))`,
			},
		},
		{
			name: "read-only workspace",
			opts: Options{Mounts: []HostMount{{Path: "/ws", ReadOnly: true}}},
			wantAllow: []string{
				"(allow signal (target children))",
				`(allow file-read* (subpath (param "MOUNT_0")))`,
				`(allow file-read* (subpath (param "MOUNT_0_REAL")))`,
			},
		},
		{
			name: "two mounts with different access",
			opts: Options{Mounts: []HostMount{{Path: "/rw"}, {Path: "/ro", ReadOnly: true}}},
			wantAllow: []string{
				"(allow signal (target children))",
				`(allow file-read* file-write* (subpath (param "MOUNT_0")))`,
				`(allow file-read* file-write* (subpath (param "MOUNT_0_REAL")))`,
				`(allow file-read* (subpath (param "MOUNT_1")))`,
				`(allow file-read* (subpath (param "MOUNT_1_REAL")))`,
			},
		},
		{
			name: "nat",
			opts: Options{AllowOutboundNet: true},
			wantAllow: []string{
				"(allow signal (target children))",
				"(allow network-outbound)",
				"(allow network-inbound)",
			},
		},
		{
			name: "udp peer",
			opts: Options{OutboundUDPPorts: []uint16{51820, 51821}},
			wantAllow: []string{
				"(allow signal (target children))",
				`(allow network-outbound (remote udp "*:51820"))`,
				`(allow network-outbound (remote udp "*:51821"))`,
				`(allow network-inbound (local udp "*:*"))`,
			},
		},
		{
			name: "nat overrides udp peer list",
			opts: Options{AllowOutboundNet: true, OutboundUDPPorts: []uint16{51820}},
			wantAllow: []string{
				"(allow signal (target children))",
				"(allow network-outbound)",
				"(allow network-inbound)",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotAllow []string
			for _, line := range profileLines(BuildSeatbeltProfile(tt.opts)) {
				if strings.HasPrefix(line, "(allow ") {
					gotAllow = append(gotAllow, line)
				}
			}
			if !slices.Equal(gotAllow, tt.wantAllow) {
				t.Fatalf("allow rules = %q, want %q", gotAllow, tt.wantAllow)
			}
		})
	}
}

func TestSeatbeltProfileNeverAllowsBroadOperations(t *testing.T) {
	broad := []string{
		"(allow process", "(allow mach", "(allow sysctl", "(allow iokit", "(allow file*",
		"(allow file-write*)", "(allow file-read*)", "(allow network*", "(allow default",
		"(allow system", "(allow ipc", "(allow signal (target others", "(allow signal)", "(allow job-creation",
	}
	profile := BuildSeatbeltProfile(Options{Mounts: []HostMount{{Path: "/ws"}}, AllowOutboundNet: true, OutboundUDPPorts: []uint16{1}})
	for _, prefix := range broad {
		if strings.Contains(profile, prefix) {
			t.Errorf("profile contains broad rule %q:\n%s", prefix, profile)
		}
	}
	for _, line := range profileLines(profile) {
		if strings.HasPrefix(line, "(allow file-") && !strings.Contains(line, "(subpath (param ") {
			t.Errorf("file rule without a parameterized subpath: %q", line)
		}
	}
}

func TestSeatbeltProfileProcessDeniesComeLast(t *testing.T) {
	lines := profileLines(BuildSeatbeltProfile(Options{Mounts: []HostMount{{Path: "/ws"}}, AllowOutboundNet: true}))
	n := len(lines)
	if lines[n-2] != "(deny process-fork)" || lines[n-1] != "(deny process-exec*)" {
		t.Fatalf("profile ends with %q, want the process denies last", lines[n-2:])
	}
}

func TestSeatbeltProfileDeniesBindAfterInboundAllow(t *testing.T) {
	for _, opts := range []Options{
		{AllowOutboundNet: true},
		{OutboundUDPPorts: []uint16{51820}},
	} {
		lines := profileLines(BuildSeatbeltProfile(opts))
		inbound := slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "(allow network-inbound") })
		bind := slices.Index(lines, "(deny network-bind)")
		if inbound < 0 || bind < inbound {
			t.Errorf("opts %+v: (deny network-bind) at %d must follow the inbound allow at %d", opts, bind, inbound)
		}
	}
}

func TestSeatbeltProfileKeepsPathsOutOfPolicyText(t *testing.T) {
	profile := BuildSeatbeltProfile(Options{Mounts: []HostMount{
		{Path: `/tmp/evil") (allow default) ("`},
		{Path: `/var/other") (allow default) ("`, ReadOnly: true},
	}})
	for _, leaked := range []string{"evil", "other", "/tmp", "/var"} {
		if strings.Contains(profile, leaked) {
			t.Fatalf("mount path leaked %q into the policy text:\n%s", leaked, profile)
		}
	}
}
