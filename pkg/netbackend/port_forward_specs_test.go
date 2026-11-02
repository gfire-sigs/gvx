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
package netbackend

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

func TestParsePortForwardSpecsRangesAndSockets(t *testing.T) {
	tcp := func(ip string, host, guest uint16) PortForwardRule {
		return PortForwardRule{Proto: "tcp", HostIP: ip, HostPort: host, GuestIP: DefaultGuestIPv4, GuestPort: guest}
	}
	for _, tc := range []struct {
		spec string
		want []PortForwardRule
	}{
		{"8080:80", []PortForwardRule{tcp("127.0.0.1", 8080, 80)}},
		{"8000-8002:9000-9002", []PortForwardRule{tcp("127.0.0.1", 8000, 9000), tcp("127.0.0.1", 8001, 9001), tcp("127.0.0.1", 8002, 9002)}},
		{"0.0.0.0:8000-8001:8000-8001", []PortForwardRule{tcp("0.0.0.0", 8000, 8000), tcp("0.0.0.0", 8001, 8001)}},
		{"8000-8001", []PortForwardRule{tcp("127.0.0.1", 0, 8000), tcp("127.0.0.1", 0, 8001)}},
		{"10.1.2.3::7000-7001", []PortForwardRule{tcp("10.1.2.3", 0, 7000), tcp("10.1.2.3", 0, 7001)}},
		{"[::1]:8000-8001:80-81", []PortForwardRule{tcp("::1", 8000, 80), tcp("::1", 8001, 81)}},
		{"5000-5001:5000-5001/udp", []PortForwardRule{
			{Proto: "udp", HostIP: "127.0.0.1", HostPort: 5000, GuestIP: DefaultGuestIPv4, GuestPort: 5000},
			{Proto: "udp", HostIP: "127.0.0.1", HostPort: 5001, GuestIP: DefaultGuestIPv4, GuestPort: 5001},
		}},
		{"unix:/run/user/docker.sock:2375", []PortForwardRule{{Proto: "tcp", GuestIP: DefaultGuestIPv4, GuestPort: 2375, HostSocket: "/run/user/docker.sock"}}},
		{"unix:~/.gvx/docker.sock:2375/tcp", []PortForwardRule{{Proto: "tcp", GuestIP: DefaultGuestIPv4, GuestPort: 2375, HostSocket: "~/.gvx/docker.sock"}}},
		{`unix:C:\Users\me\docker.sock:2375`, []PortForwardRule{{Proto: "tcp", GuestIP: DefaultGuestIPv4, GuestPort: 2375, HostSocket: `C:\Users\me\docker.sock`}}},
	} {
		got, err := ParsePortForwardSpecs(tc.spec, true, true)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("ParsePortForwardSpecs(%q) = (%+v, %v), want %+v", tc.spec, got, err, tc.want)
		}
	}
	for _, spec := range []string{
		"8000-8010:80",            // host range with one guest port
		"8000:9000-9001",          // guest range with one host port
		"8000-8002:9000-9001",     // ranges of different lengths
		"8002-8000:8002-8000",     // descending range
		"0-1:0-1",                 // port zero
		"1-2000",                  // longer than maxPortRange
		"unix:/tmp/x.sock",        // no guest port
		"unix:/tmp/x.sock:53/udp", // Unix sockets forward tcp only
		"unix::2375",              // empty path
	} {
		if got, err := ParsePortForwardSpecs(spec, true, true); err == nil {
			t.Errorf("ParsePortForwardSpecs(%q) = %+v, want an error", spec, got)
		}
	}
}

// shortTempDir returns a directory with a short path. A Unix socket path has
// a limit of about 104 bytes on macOS, and t.TempDir can pass it.
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "pf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestPortForwarderUnixSocketForwardsToGuestTCP(t *testing.T) {
	s := newForwardStack(t)
	sock := filepath.Join(shortTempDir(t), "d.sock")
	// A socket file that an earlier run left behind does not block the bind.
	stale, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	pf := NewPortForwarder()
	t.Cleanup(func() { _ = pf.Close() })
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", GuestPort: 2375, HostSocket: sock}}); err != nil {
		t.Fatalf("PreBind over a stale socket: %v", err)
	}
	// Windows keeps no permission bits on the socket file.
	if info, err := os.Stat(sock); err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Errorf("socket mode = %v, %v; want access for the owner only", info, err)
	}
	if got := pf.BoundRules(); len(got) != 1 || got[0].HostSocket != sock {
		t.Errorf("BoundRules() = %+v, want the socket rule", got)
	}
	guestLn, err := gonet.ListenTCP(s, guestFullAddr(2375), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcpEchoServer(t, guestLn)
	pf.Start(s)
	client, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	roundTripTCP(t, client, []byte("docker-api"))
}

func TestPortForwarderUnixSocketRefusesARegularFile(t *testing.T) {
	path := filepath.Join(shortTempDir(t), "notasocket")
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	pf := NewPortForwarder()
	defer pf.Close()
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", GuestPort: 2375, HostSocket: path}}); err == nil {
		t.Fatal("PreBind replaced a regular file with a socket")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Errorf("the regular file changed: %q, %v", data, err)
	}
}
