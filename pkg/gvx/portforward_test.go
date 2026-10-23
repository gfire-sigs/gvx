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

import "testing"

func TestParsePortForwardDockerForms(t *testing.T) {
	for _, tc := range []struct {
		spec string
		want PortForward
	}{
		{"80", PortForward{HostPort: 0, GuestPort: 80, Protocol: "tcp", BindAddress: "127.0.0.1"}},
		{"53/udp", PortForward{HostPort: 0, GuestPort: 53, Protocol: "udp", BindAddress: "127.0.0.1"}},
		{"127.0.0.1:8080:80", PortForward{HostPort: 8080, GuestPort: 80, Protocol: "tcp", BindAddress: "127.0.0.1"}},
		{"0.0.0.0:8080:80/udp", PortForward{HostPort: 8080, GuestPort: 80, Protocol: "udp", BindAddress: "0.0.0.0"}},
		{"10.1.2.3::80", PortForward{HostPort: 0, GuestPort: 80, Protocol: "tcp", BindAddress: "10.1.2.3"}},
		{"[::1]:8080:80", PortForward{HostPort: 8080, GuestPort: 80, Protocol: "tcp", BindAddress: "::1"}},
		{"[::]::443/tcp", PortForward{HostPort: 0, GuestPort: 443, Protocol: "tcp", BindAddress: "::"}},
	} {
		got, err := ParsePortForward(tc.spec)
		if err != nil || got != tc.want {
			t.Errorf("ParsePortForward(%q) = (%+v, %v), want %+v", tc.spec, got, err, tc.want)
		}
	}
}

func TestParsePortForwardRejectsMalformedSpecifications(t *testing.T) {
	for _, spec := range []string{
		"8000-8010:80",        // port range
		"999.1.1.1:80:80",     // bad IPv4
		"::1:8080:80",         // IPv6 without brackets
		"[::1:8080:80",        // unclosed bracket
		"[127.0.0.1]:8080:80", // IPv4 in brackets
		"[::1]",               // no port
		"1.2.3.4:80:80:80",    // too many parts
		"80:",                 // empty guest port
		"127.0.0.1:8080:0",    // guest port zero
		"65536",               // guest port out of range
		"8080:80/",            // empty protocol
	} {
		if got, err := ParsePortForward(spec); err == nil {
			t.Errorf("ParsePortForward(%q) = %+v, want an error", spec, got)
		}
	}
}
