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

package gvx

import (
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/netbackend"
)

func TestHostsWithEntriesAppendsMissingNames(t *testing.T) {
	got := string(hostsWithEntries([]byte("127.0.0.1 localhost localhost.localdomain\n::1 localhost ip6-localhost # loopback"), "box"))
	for _, want := range []string{
		"127.0.0.1 localhost localhost.localdomain\n",
		"::1 localhost ip6-localhost # loopback\n",
		netbackend.DefaultGuestIPv4 + "\tbox\n",
		netbackend.HostGatewayIPv4 + "\thost.docker.internal\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("hosts file lacks %q:\n%s", want, got)
		}
	}
}

func TestHostsWithEntriesKeepsAFileThatAlreadyNamesThem(t *testing.T) {
	in := netbackend.DefaultGuestIPv4 + " BOX\n" + netbackend.HostGatewayIPv4 + " host.docker.internal\n"
	if got := string(hostsWithEntries([]byte(in), "box")); got != in {
		t.Errorf("hostsWithEntries changed a file that names the hostname (any case) and host.docker.internal:\n%s", got)
	}
}

func TestHostsWithEntriesIgnoresNamesInComments(t *testing.T) {
	got := string(hostsWithEntries([]byte("# box host.docker.internal\n127.0.0.1 localhost\n"), "box"))
	if !strings.Contains(got, netbackend.DefaultGuestIPv4+"\tbox\n") || !strings.Contains(got, "host.docker.internal\n") {
		t.Errorf("a name in a comment counted as an entry:\n%s", got)
	}
}

func TestHostsWithEntriesOnAnEmptyFile(t *testing.T) {
	got := string(hostsWithEntries(nil, "box"))
	want := netbackend.DefaultGuestIPv4 + "\tbox\n" + netbackend.HostGatewayIPv4 + "\thost.docker.internal\n"
	if got != want {
		t.Errorf("hostsWithEntries(nil) = %q, want %q", got, want)
	}
}
