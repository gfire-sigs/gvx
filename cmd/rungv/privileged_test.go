// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

import "testing"

func TestParseRunArgsPrivilegedDefaultAndOverrides(t *testing.T) {
	for _, tc := range []struct {
		name                           string
		args                           []string
		netRaw, packetWrite, allowSUID bool
	}{
		{"default is privileged", nil, true, true, true},
		{"privileged false turns all off", []string{"--privileged=false"}, false, false, false},
		{"explicit flag wins over privileged false", []string{"--privileged=false", "--allow-suid"}, false, false, true},
		{"explicit flag wins over the default", []string{"--allow-suid=false"}, true, true, false},
		{"no raw sockets means no packet writes", []string{"--net-raw=false"}, false, false, true},
		{"one dash form", []string{"-privileged=false", "-net-raw"}, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rc, _, done, stderr := parse(t, append(tc.args, "-image=x")...)
			if done {
				t.Fatalf("parseRunArgs ended the command: %s", stderr)
			}
			cfg := rc.cfg
			if cfg.NetRaw != tc.netRaw || cfg.AllowPacketSocketWrite != tc.packetWrite || cfg.AllowSUID != tc.allowSUID {
				t.Errorf("NetRaw=%v AllowPacketSocketWrite=%v AllowSUID=%v, want %v %v %v",
					cfg.NetRaw, cfg.AllowPacketSocketWrite, cfg.AllowSUID, tc.netRaw, tc.packetWrite, tc.allowSUID)
			}
		})
	}
}

func TestParseRunArgsPublishRangesAndSockets(t *testing.T) {
	rc, _, done, stderr := parse(t, "-p", "8000-8002:9000-9002", "-p", "unix:/tmp/d.sock:2375", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	pfs := rc.cfg.PortForwards
	if len(pfs) != 4 {
		t.Fatalf("PortForwards = %+v, want 4 entries", pfs)
	}
	if pfs[2].HostPort != 8002 || pfs[2].GuestPort != 9002 {
		t.Errorf("PortForwards[2] = %+v, want 8002 -> 9002", pfs[2])
	}
	if pfs[3].HostSocket != "/tmp/d.sock" || pfs[3].GuestPort != 2375 {
		t.Errorf("PortForwards[3] = %+v, want unix:/tmp/d.sock -> 2375", pfs[3])
	}
}
