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

package hostlockdown

import (
	"context"
	"net"
)

// DialContext dials an outbound host network connection. On Windows after Apply
// with Options.AllowOutboundNet enabled, TCP and UDP dials execute on the
// Low-integrity socket broker so sandbox threads keep NULL_SID restriction.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialHostContext(ctx, network, address)
}

// AcceptListener accepts one inbound connection from a pre-bound listener. On
// Windows, AcceptEx allocates a new acceptor socket handle, so locked-down NAT
// sandboxes run the accept on the Low-integrity socket broker.
func AcceptListener(ln net.Listener) (net.Conn, error) {
	return acceptHostListener(ln)
}
