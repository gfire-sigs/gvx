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

package oci

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
)

// newServerResolver returns a resolver that sends every query to servers. The
// Go resolver replaces the host resolver configuration, which a host such as
// Android does not have. The resolver is private to its caller, so it
// changes no process-wide state such as net.DefaultResolver.
//
// The Go resolver dials once for each query attempt and names its own guess
// of the server. The dial function ignores that name and takes the next
// configured server, so a failed attempt moves on to the next server.
func newServerResolver(servers []netip.AddrPort) *net.Resolver {
	servers = slices.Clone(servers)
	var next atomic.Uint64
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			var errs []error
			start := next.Add(1) - 1
			for i := range uint64(len(servers)) {
				server := servers[(start+i)%uint64(len(servers))]
				conn, err := dialer.DialContext(ctx, network, server.String())
				if err == nil {
					return conn, nil
				}
				errs = append(errs, err)
			}
			return nil, errors.Join(errs...)
		},
	}
}
