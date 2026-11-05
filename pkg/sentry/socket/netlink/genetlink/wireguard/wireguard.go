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

// Package wireguard provides the "wireguard" link kind and the WireGuard
// generic netlink family.
//
// "ip link add wg0 type wireguard" creates a link in the network stack of the
// caller. The device is the wireguard-go device. Its TUN side is the link
// itself, and its UDP side is a pair of UDP endpoints of the same network
// stack. The encrypted packets therefore leave through the routes of the
// guest, as the packets of the kernel module do. "wg" and "wg-quick"
// configure the link with the family "wireguard" of
// include/uapi/linux/wireguard.h.
package wireguard

import (
	"fmt"

	"golang.zx2c4.com/wireguard/device"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
)

const (
	// kind is the IFLA_INFO_KIND value of the link.
	kind = "wireguard"

	// familyName and familyVersion are WG_GENL_NAME and WG_GENL_VERSION.
	familyName    = "wireguard"
	familyVersion = 1

	// defaultMTU is the MTU of a new link, as in drivers/net/wireguard.
	defaultMTU = 1420
)

// Commands of wg_cmd.
const (
	cmdGetDevice = 0
	cmdSetDevice = 1
)

// Flags and attributes of the device, from include/uapi/linux/wireguard.h.
const (
	deviceFlagReplacePeers = 1 << 0

	deviceAttrIfindex    = 1
	deviceAttrIfname     = 2
	deviceAttrPrivateKey = 3
	deviceAttrPublicKey  = 4
	deviceAttrFlags      = 5
	deviceAttrListenPort = 6
	deviceAttrFwmark     = 7
	deviceAttrPeers      = 8
)

// Flags and attributes of a peer.
const (
	peerFlagRemoveMe         = 1 << 0
	peerFlagReplaceAllowedIP = 1 << 1
	peerFlagUpdateOnly       = 1 << 2

	peerAttrPublicKey    = 1
	peerAttrPresharedKey = 2
	peerAttrFlags        = 3
	peerAttrEndpoint     = 4
	peerAttrKeepalive    = 5
	peerAttrLastHshake   = 6
	peerAttrRxBytes      = 7
	peerAttrTxBytes      = 8
	peerAttrAllowedIPs   = 9
	peerAttrProtoVersion = 10
)

// Flags and attributes of an allowed IP address.
const (
	allowedIPFlagRemoveMe = 1 << 0

	allowedIPAttrFamily = 1
	allowedIPAttrIPAddr = 2
	allowedIPAttrCIDR   = 3
	allowedIPAttrFlags  = 4
)

// keyLen is NOISE_PUBLIC_KEY_LEN, the length of every WireGuard key.
const keyLen = 32

// family is the registered WireGuard family. Its ID is only known after the
// registration.
var family = &genetlink.Family{
	Name:    familyName,
	Version: familyVersion,
	MaxAttr: deviceAttrPeers,
	Ops: []genetlink.Op{
		{Cmd: cmdGetDevice, Flags: genetlink.OpNetAdmin, Dump: getDevice},
		{Cmd: cmdSetDevice, Flags: genetlink.OpNetAdmin, Do: setDevice},
	},
}

func init() {
	netstack.RegisterLinkKind(kind, netstack.LinkKind{
		NamePrefix:       "wg",
		New:              newLink,
		AdminState:       true,
		Flags:            linux.IFF_POINTOPOINT | linux.IFF_NOARP,
		OperStateUnknown: true,
		StackEnded:       stackEnded,
	})
	genetlink.RegisterFamily(family)
}

// newLogger returns the logger of one wireguard-go device. Both levels go to
// the Sentry log, which stays off unless the user sets GVX_DEBUG_LOG.
func newLogger(name string) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			// wireguard-go logs several lines for each peer. Skip the formatting
			// of a line that nobody reads.
			if log.IsLogging(log.Debug) {
				log.Debugf("wireguard %s: %s", name, fmt.Sprintf(format, args...))
			}
		},
		Errorf: func(format string, args ...any) { log.Warningf("wireguard %s: %s", name, fmt.Sprintf(format, args...)) },
	}
}
