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
	"bufio"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

// serveThroughput answers the requests of "nodeprobe tput". "D n" sends n
// bytes, and "U n" reads n bytes and answers "OK".
func serveThroughput(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			r := bufio.NewReader(conn)
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			var kind string
			var size int64
			f := strings.Fields(line)
			if len(f) != 2 {
				return
			}
			kind = f[0]
			if size, err = strconv.ParseInt(f[1], 10, 64); err != nil {
				return
			}
			switch kind {
			case "D":
				buf := make([]byte, 64<<10)
				for sent := int64(0); sent < size; {
					n, err := conn.Write(buf[:min(int64(len(buf)), size-sent)])
					if err != nil {
						return
					}
					sent += int64(n)
				}
			case "U":
				if n, err := io.CopyN(io.Discard, r, size); err == nil && n == size {
					_, _ = conn.Write([]byte("OK\n"))
				}
			}
		}()
	}
}

// TestE2ENATThroughput measures the TCP throughput of a guest through the NAT
// link to a listener on the host, through the gateway 10.0.2.2. It is a
// measurement, not a gate: it logs the rates and fails only when a transfer
// fails. It runs when GVX_E2E_THROUGHPUT_MIB is set to the size of each
// transfer in MiB, for example 1024.
func TestE2ENATThroughput(t *testing.T) {
	mib := os.Getenv("GVX_E2E_THROUGHPUT_MIB")
	if mib == "" {
		t.Skip("set GVX_E2E_THROUGHPUT_MIB to measure the NAT throughput")
	}
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen on the host: %v", err)
		}
		defer ln.Close()
		go serveThroughput(ln)
		port := ln.Addr().(*net.TCPAddr).Port
		code, out := runNodeProbe(t, b, bin, func(cfg *gvx.Config) {
			cfg.NetworkMode = gvx.NetModeNAT
		}, "tput", net.JoinHostPort("10.0.2.2", strconv.Itoa(port)), mib)
		requireNodeChecks(t, code, out, "download", "upload")
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "TPUT ") {
				t.Logf("%s %s: %s", t.Name(), mib+" MiB", l)
			}
		}
	})
}
