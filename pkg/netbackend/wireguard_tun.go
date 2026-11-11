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

package netbackend

import (
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/wgtun"
)

// wgTUNName is the interface name that channelTUN reports.
const wgTUNName = "gvx-wg0"

// errInvalidIPPacket reports a packet that is not a complete IPv4 or IPv6 packet.
var errInvalidIPPacket = wgtun.ErrInvalidIPPacket

type channelTUN = wgtun.Device

func newChannelTUN(ep *channel.Endpoint) *channelTUN {
	return wgtun.New(ep, wgTUNName)
}
