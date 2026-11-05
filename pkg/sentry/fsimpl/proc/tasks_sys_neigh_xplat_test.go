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
	"errors"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func TestNeighDirectoriesAreInTheTree(t *testing.T) {
	for _, family := range []string{"ipv4", "ipv6"} {
		if got := sysSubdirs("net/" + family); !slices.Contains(got, "neigh") {
			t.Errorf("net/%s subdirectories = %v, want neigh", family, got)
		}
		if got := sysSubdirs("net/" + family + "/neigh"); !slices.Equal(got, []string{"default"}) {
			t.Errorf("net/%s/neigh subdirectories = %v, want default", family, got)
		}
		dir := "net/" + family + "/neigh/default"
		if !isNeighDir(dir) || !isNeighDir("net/"+family+"/neigh") {
			t.Errorf("isNeighDir rejects the directories of %s", family)
		}
		var names []string
		for _, spec := range nodeSysctlSpecs[dir] {
			names = append(names, spec.name)
			if spec.scope != scopeNet {
				t.Errorf("%s/%s has scope %d, want the network namespace scope", dir, spec.name, spec.scope)
			}
		}
		if want := []string{"gc_thresh1", "gc_thresh2", "gc_thresh3"}; !slices.Equal(names, want) {
			t.Errorf("%s files = %v, want %v", dir, names, want)
		}
	}
}

func TestGCThreshFilesStartAtTheLinuxDefaults(t *testing.T) {
	want := map[string]string{"gc_thresh1": "128", "gc_thresh2": "512", "gc_thresh3": "1024"}
	for _, dir := range []string{"net/ipv4/neigh/default", "net/ipv6/neigh/default"} {
		for _, spec := range nodeSysctlSpecs[dir] {
			if spec.def != want[spec.name] {
				t.Errorf("%s/%s default = %q, want %q", dir, spec.name, spec.def, want[spec.name])
			}
		}
	}
}

// TestGCThreshFilesAcceptTheRangeOfLinux checks proc_dointvec_minmax with
// SYSCTL_ZERO and SYSCTL_INT_MAX in neigh_sysctl_template.
func TestGCThreshFilesAcceptTheRangeOfLinux(t *testing.T) {
	spec := nodeSysctlSpecs["net/ipv4/neigh/default"][0]
	for text, want := range map[string]string{"0": "0", "1\n": "1", " 2147483647 ": "2147483647"} {
		if got, err := spec.parse(text, "128"); err != nil || got != want {
			t.Errorf("parse(%q) = %q, %v, want %q", text, got, err, want)
		}
	}
	for _, text := range []string{"-1", "2147483648", "x", "1 2", "1.5"} {
		if got, err := spec.parse(text, "128"); !errors.Is(err, linuxerr.EINVAL) {
			t.Errorf("parse(%q) = %q, %v, want EINVAL", text, got, err)
		}
	}
}

func newNetstack(t *testing.T) *netstack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol, ipv6.NewProtocol},
	})
	t.Cleanup(s.Close)
	return &netstack.Stack{Stack: s}
}

// store applies a write of the value to the file the way sysctlFile.Write does.
func store(t *testing.T, st *netstack.Stack, dir, name, text string) {
	t.Helper()
	for _, spec := range nodeSysctlSpecs[dir] {
		if spec.name != name {
			continue
		}
		cur, ok := st.SysctlValue(spec.key)
		if !ok {
			cur = spec.def
		}
		val, err := spec.parse(text, cur)
		if err != nil {
			t.Fatalf("parse(%q): %v", text, err)
		}
		st.SetSysctlValue(spec.key, val)
		if err := spec.apply(st, st); err != nil {
			t.Fatalf("apply: %v", err)
		}
		return
	}
	t.Fatalf("no file %s/%s", dir, name)
}

func TestGCThreshWritesReachTheNeighborTableOfTheNamespace(t *testing.T) {
	root, pod := newNetstack(t), newNetstack(t)
	store(t, root, "net/ipv4/neigh/default", "gc_thresh3", "4096")
	store(t, root, "net/ipv4/neigh/default", "gc_thresh1", "0")
	store(t, root, "net/ipv6/neigh/default", "gc_thresh2", "7")

	got4, _ := root.Stack.NeighborGCThresholds(ipv4.ProtocolNumber)
	if want := (stack.NeighborGCThresholds{Thresh1: 0, Thresh2: 512, Thresh3: 4096}); got4 != want {
		t.Errorf("IPv4 thresholds = %+v, want %+v", got4, want)
	}
	got6, _ := root.Stack.NeighborGCThresholds(ipv6.ProtocolNumber)
	if want := (stack.NeighborGCThresholds{Thresh1: 128, Thresh2: 7, Thresh3: 1024}); got6 != want {
		t.Errorf("IPv6 thresholds = %+v, want %+v", got6, want)
	}
	other, _ := pod.Stack.NeighborGCThresholds(ipv4.ProtocolNumber)
	if other != stack.DefaultNeighborGCThresholds() {
		t.Errorf("thresholds of the other namespace = %+v, want the defaults", other)
	}
}
