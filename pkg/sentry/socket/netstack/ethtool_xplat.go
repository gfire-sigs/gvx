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

package netstack

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/abi/linux/errno"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// The ioctl SIOCETHTOOL follows net/ethtool/ioctl.c of Linux. Each link keeps
// the offload features that Linux keeps in struct net_device: the features that
// the guest can change (hw_features), the features that it asked for
// (wanted_features), and the features that are on (features). A change moves
// the wanted features and then applies the dependency rules of
// netdev_fix_features(), so "tx off" also switches scatter-gather and TSO off,
// and "tx on" brings them back. The datapath does not read the features.

// Command numbers of include/uapi/linux/ethtool.h.
const (
	ethtoolGSET        = 0x01
	ethtoolGDRVINFO    = 0x03
	ethtoolGMSGLVL     = 0x07
	ethtoolGLINK       = 0x0a
	ethtoolGCOALESCE   = 0x0e
	ethtoolGRINGPARAM  = 0x10
	ethtoolGPAUSEPARAM = 0x12
	ethtoolGRXCSUM     = 0x14
	ethtoolSRXCSUM     = 0x15
	ethtoolGTXCSUM     = 0x16
	ethtoolSTXCSUM     = 0x17
	ethtoolGSG         = 0x18
	ethtoolSSG         = 0x19
	ethtoolGSTRINGS    = 0x1b
	ethtoolGSTATS      = 0x1d
	ethtoolGTSO        = 0x1e
	ethtoolSTSO        = 0x1f
	ethtoolGPERMADDR   = 0x20
	ethtoolGUFO        = 0x21
	ethtoolGGSO        = 0x23
	ethtoolSGSO        = 0x24
	ethtoolGFLAGS      = 0x25
	ethtoolSFLAGS      = 0x26
	ethtoolGPFLAGS     = 0x27
	ethtoolGRXFH       = 0x29
	ethtoolGGRO        = 0x2b
	ethtoolSGRO        = 0x2c
	ethtoolGRXRINGS    = 0x2d
	ethtoolGRXCLSRLCNT = 0x2e
	ethtoolGRXCLSRULE  = 0x2f
	ethtoolGRXCLSRLALL = 0x30
	ethtoolGSSETINFO   = 0x37
	ethtoolGRXFHINDIR  = 0x38
	ethtoolGFEATURES   = 0x3a
	ethtoolSFEATURES   = 0x3b
	ethtoolGCHANNELS   = 0x3c
	ethtoolGETTSINFO   = 0x41
	ethtoolGEEE        = 0x44
	ethtoolGRSSH       = 0x46
	ethtoolGTUNABLE    = 0x48
	ethtoolGPHYSTATS   = 0x4a
	ethtoolGLINKSETS   = 0x4c
	ethtoolGFECPARAM   = 0x50
)

// String sets of include/uapi/linux/ethtool.h.
const ethSSFeatures = 4

// Flags that ETHTOOL_SFEATURES returns, and the legacy flags of ETHTOOL_GFLAGS.
const (
	ethtoolFUnsupported = 1 << 0
	ethtoolFWish        = 1 << 1

	ethFlagTxVlan = 1 << 7
	ethFlagRxVlan = 1 << 8
	ethFlagLRO    = 1 << 15
	ethFlagNtuple = 1 << 27
	ethFlagRxHash = 1 << 28
)

// Sizes of the structures of include/uapi/linux/ethtool.h.
const (
	ethGStringLen       = 32
	ethtoolDrvinfoSize  = 196
	ethtoolCmdSize      = 44
	ethtoolLinkSetSize  = 48
	ethtoolTSInfoSize   = 44
	ethtoolBlockSize    = 16
	ethtoolSetBlockSize = 8
	ethtoolSSetInfoSize = 16

	// linkModeMaskWords is __ETHTOOL_LINK_MODE_MASK_NU32.
	linkModeMaskWords = 4

	// featureWords is ETHTOOL_DEV_FEATURE_WORDS.
	featureWords = (featureCount + 31) / 32
)

// Values of the fields of ethtool_cmd and ethtool_link_settings.
const (
	speedUnknown  = 0xffffffff
	duplexFull    = 0x01
	duplexUnknown = 0xff
	portTP        = 0x00
	portOther     = 0xff
)

// Bit numbers of netdev_features_t, from include/linux/netdev_features.h.
const (
	bitSG = iota
	bitIPCsum
	_
	bitHWCsum
	bitIPv6Csum
	bitHighDMA
	bitFraglist
	bitVlanCtagTX
	bitVlanCtagRX
	bitVlanCtagFilter
	bitVlanChallenged
	bitGSO
	bitLLTX
	bitNetnsLocal
	bitGRO
	bitLRO
	bitTSO
	bitGSORobust
	bitTSOECN
	bitTSOMangleID
	bitTSO6
	bitFSO
	bitGSOGRE
	bitGSOGRECsum
	bitGSOIPXIP4
	bitGSOIPXIP6
	bitGSOUDPTunnel
	bitGSOUDPTunnelCsum
	bitGSOPartial
	bitGSOTunnelRemcsum
	bitGSOSCTP
	bitGSOESP
	bitGSOUDP
	bitGSOUDPL4
	bitGSOFraglist
	bitFCoECRC
	bitSCTPCRC
	bitFCoEMTU
	bitNtuple
	bitRXHash
	bitRXCsum
	bitNocacheCopy
	bitLoopback
	bitRXFCS
	bitRXAll
	bitVlanStagTX
	bitVlanStagRX
	bitVlanStagFilter
	bitL2FwdOffload
	bitHWTC
	bitHWESP
	bitHWESPTxCsum
	bitRXUDPTunnelPort
	bitHWTLSTX
	bitHWTLSRX
	bitGROHW
	bitHWTLSRecord
	bitGROFraglist
	bitHWMacsec
	bitGROUDPFwd
	bitHWHSRTagIns
	bitHWHSRTagRm
	bitHWHSRFwd
	bitHWHSRDup
	featureCount
)

// featureNames is netdev_features_strings of net/ethtool/common.c. The index
// is the bit number. A bit without a name has an empty string.
var featureNames = [featureCount]string{
	bitSG:               "tx-scatter-gather",
	bitIPCsum:           "tx-checksum-ipv4",
	bitHWCsum:           "tx-checksum-ip-generic",
	bitIPv6Csum:         "tx-checksum-ipv6",
	bitHighDMA:          "highdma",
	bitFraglist:         "tx-scatter-gather-fraglist",
	bitVlanCtagTX:       "tx-vlan-hw-insert",
	bitVlanCtagRX:       "rx-vlan-hw-parse",
	bitVlanCtagFilter:   "rx-vlan-filter",
	bitVlanChallenged:   "vlan-challenged",
	bitGSO:              "tx-generic-segmentation",
	bitLLTX:             "tx-lockless",
	bitNetnsLocal:       "netns-local",
	bitGRO:              "rx-gro",
	bitLRO:              "rx-lro",
	bitTSO:              "tx-tcp-segmentation",
	bitGSORobust:        "tx-gso-robust",
	bitTSOECN:           "tx-tcp-ecn-segmentation",
	bitTSOMangleID:      "tx-tcp-mangleid-segmentation",
	bitTSO6:             "tx-tcp6-segmentation",
	bitFSO:              "tx-fcoe-segmentation",
	bitGSOGRE:           "tx-gre-segmentation",
	bitGSOGRECsum:       "tx-gre-csum-segmentation",
	bitGSOIPXIP4:        "tx-ipxip4-segmentation",
	bitGSOIPXIP6:        "tx-ipxip6-segmentation",
	bitGSOUDPTunnel:     "tx-udp_tnl-segmentation",
	bitGSOUDPTunnelCsum: "tx-udp_tnl-csum-segmentation",
	bitGSOPartial:       "tx-gso-partial",
	bitGSOTunnelRemcsum: "tx-tunnel-remcsum-segmentation",
	bitGSOSCTP:          "tx-sctp-segmentation",
	bitGSOESP:           "tx-esp-segmentation",
	bitGSOUDPL4:         "tx-udp-segmentation",
	bitGSOFraglist:      "tx-gso-list",
	bitFCoECRC:          "tx-checksum-fcoe-crc",
	bitSCTPCRC:          "tx-checksum-sctp",
	bitFCoEMTU:          "fcoe-mtu",
	bitNtuple:           "rx-ntuple-filter",
	bitRXHash:           "rx-hashing",
	bitRXCsum:           "rx-checksum",
	bitNocacheCopy:      "tx-nocache-copy",
	bitLoopback:         "loopback",
	bitRXFCS:            "rx-fcs",
	bitRXAll:            "rx-all",
	bitVlanStagTX:       "tx-vlan-stag-hw-insert",
	bitVlanStagRX:       "rx-vlan-stag-hw-parse",
	bitVlanStagFilter:   "rx-vlan-stag-filter",
	bitL2FwdOffload:     "l2-fwd-offload",
	bitHWTC:             "hw-tc-offload",
	bitHWESP:            "esp-hw-offload",
	bitHWESPTxCsum:      "esp-tx-csum-hw-offload",
	bitRXUDPTunnelPort:  "rx-udp_tunnel-port-offload",
	bitHWTLSTX:          "tls-hw-tx-offload",
	bitHWTLSRX:          "tls-hw-rx-offload",
	bitGROHW:            "rx-gro-hw",
	bitHWTLSRecord:      "tls-hw-record",
	bitGROFraglist:      "rx-gro-list",
	bitHWMacsec:         "macsec-hw-offload",
	bitGROUDPFwd:        "rx-udp-gro-forwarding",
	bitHWHSRTagIns:      "hsr-tag-ins-offload",
	bitHWHSRTagRm:       "hsr-tag-rm-offload",
	bitHWHSRFwd:         "hsr-fwd-offload",
	bitHWHSRDup:         "hsr-dup-offload",
}

// feature returns the mask of the listed bit numbers.
func feature(bits ...int) uint64 {
	var m uint64
	for _, b := range bits {
		m |= 1 << b
	}
	return m
}

// Feature groups of include/linux/netdev_features.h.
var (
	csumMask      = feature(bitIPCsum, bitIPv6Csum, bitHWCsum)
	allTSO        = feature(bitTSO, bitTSO6, bitTSOECN, bitTSOMangleID)
	gsoSoftware   = allTSO | feature(bitGSOSCTP, bitGSOUDPL4, bitGSOFraglist)
	gsoEncapAll   = feature(bitGSOGRE, bitGSOGRECsum, bitGSOUDPTunnel, bitGSOUDPTunnelCsum, bitGSOIPXIP4, bitGSOIPXIP6)
	softFeatures  = feature(bitGSO, bitGRO)
	neverChange   = feature(bitVlanChallenged, bitLLTX, bitNetnsLocal)
	ethtoolBits   = (1<<featureCount - 1) &^ neverChange
	vlanHWAll     = feature(bitVlanCtagTX, bitVlanCtagRX, bitVlanStagTX, bitVlanStagRX)
	legacyTxCsum  = csumMask | feature(bitFCoECRC, bitSCTPCRC)
	legacyFlagMap = [...]struct {
		flag    uint32
		feature uint64
	}{
		{ethFlagTxVlan, feature(bitVlanCtagTX)},
		{ethFlagRxVlan, feature(bitVlanCtagRX)},
		{ethFlagLRO, feature(bitLRO)},
		{ethFlagNtuple, feature(bitNtuple)},
		{ethFlagRxHash, feature(bitRXHash)},
	}
)

// fixFeatures applies the dependencies of netdev_fix_features().
func fixFeatures(f uint64) uint64 {
	// Fix illegal checksum combinations.
	if f&feature(bitHWCsum) != 0 && f&feature(bitIPCsum, bitIPv6Csum) != 0 {
		f &^= feature(bitIPCsum, bitIPv6Csum)
	}
	// Scatter-gather needs a checksum feature.
	if f&feature(bitSG) != 0 && f&csumMask == 0 {
		f &^= feature(bitSG)
	}
	// TSO needs scatter-gather.
	if f&allTSO != 0 && f&feature(bitSG) == 0 {
		f &^= allTSO
	}
	// TSO ECN needs TSO.
	if f&allTSO == feature(bitTSOECN) {
		f &^= feature(bitTSOECN)
	}
	// Software GSO needs scatter-gather.
	if f&feature(bitGSO) != 0 && f&feature(bitSG) == 0 {
		f &^= feature(bitGSO)
	}
	// UDP segmentation needs both a checksum of IPv4 and one of IPv6.
	if f&feature(bitGSOUDPL4) != 0 && f&feature(bitHWCsum) == 0 &&
		f&feature(bitIPCsum, bitIPv6Csum) != feature(bitIPCsum, bitIPv6Csum) {
		f &^= feature(bitGSOUDPL4)
	}
	// Hardware GRO and TLS receive offload need the receive checksum.
	if f&feature(bitRXCsum) == 0 {
		f &^= feature(bitGROHW, bitHWTLSRX)
	}
	// LRO and hardware GRO cannot keep the FCS.
	if f&feature(bitRXFCS) != 0 {
		f &^= feature(bitLRO, bitGROHW)
	}
	return f
}

// ethtoolSettings is the answer of a link that has link settings.
type ethtoolSettings struct {
	speed  uint32
	duplex uint8
	port   uint8
}

// ethtoolProfile describes the ethtool view of one kind of link: the driver
// name that ETHTOOL_GDRVINFO returns, the link settings, and the features that
// the Linux driver of the kind sets up.
type ethtoolProfile struct {
	driver, version, busInfo string
	// features is dev->features and hw is dev->hw_features before
	// register_netdevice() adds the software features.
	features, hw uint64
	// settings is nil when the Linux driver has no get_link_ksettings.
	settings *ethtoolSettings
	// ownAddress is set when the permanent address equals the address of the
	// link. A virtual link has an all-zero permanent address.
	ownAddress bool
	// carrierAlways is set when the Linux driver reports a carrier whether or
	// not the link is up. The loopback link, vxlan, and wireguard do.
	carrierAlways bool
}

// ethtoolProfileOf returns the profile of a link. Each profile follows the
// Linux driver of the link kind.
func ethtoolProfileOf(kind string, loopback bool) ethtoolProfile {
	switch {
	case loopback:
		return ethtoolProfile{
			features: feature(bitSG, bitFraglist, bitHWCsum, bitRXCsum, bitSCTPCRC, bitHighDMA,
				bitLLTX, bitNetnsLocal, bitVlanChallenged, bitLoopback) | gsoSoftware,
			hw: gsoSoftware, carrierAlways: true,
		}
	case kind == "veth":
		veth := feature(bitSG, bitFraglist, bitHWCsum, bitRXCsum, bitSCTPCRC, bitHighDMA) | gsoSoftware | gsoEncapAll | vlanHWAll
		return ethtoolProfile{
			driver: "veth", version: "1",
			features: veth | feature(bitLLTX), hw: veth,
			settings: &ethtoolSettings{speed: 10000, duplex: duplexFull, port: portTP},
		}
	case kind == "bridge":
		common := feature(bitSG, bitFraglist, bitHighDMA, bitHWCsum)
		return ethtoolProfile{
			driver: "bridge", version: "2.3",
			features: common | feature(bitLLTX, bitNetnsLocal, bitVlanCtagTX, bitVlanStagTX) | gsoSoftware | gsoEncapAll,
			hw:       common | feature(bitVlanCtagTX, bitVlanStagTX),
			settings: &ethtoolSettings{speed: speedUnknown, duplex: duplexUnknown, port: portOther},
		}
	case kind == "vxlan":
		hw := feature(bitSG, bitHWCsum, bitRXCsum) | gsoSoftware
		return ethtoolProfile{driver: "vxlan", version: "0.1", features: hw | feature(bitLLTX), hw: hw, carrierAlways: true}
	case kind == "wireguard":
		hw := feature(bitHWCsum, bitRXCsum, bitSG, bitGSO, bitHighDMA) | gsoSoftware
		return ethtoolProfile{features: hw | feature(bitLLTX), hw: hw, carrierAlways: true}
	default:
		// The NIC of the sandbox and every other link behaves like virtio_net.
		hw := feature(bitSG, bitHWCsum, bitRXCsum, bitHighDMA) | gsoSoftware
		return ethtoolProfile{
			driver: "virtio_net", version: "1.0.0", busInfo: "virtio0",
			features: hw, hw: hw, ownAddress: true,
			settings: &ethtoolSettings{speed: speedUnknown, duplex: duplexUnknown, port: portOther},
		}
	}
}

// linkFeatures is the feature state of one link.
//
// +stateify savable
type linkFeatures struct {
	hw, wanted, active uint64
}

// newLinkFeatures returns the state that register_netdevice() builds from the
// profile.
func newLinkFeatures(p ethtoolProfile, loopback bool) *linkFeatures {
	hw := p.hw | softFeatures
	features := p.features | softFeatures
	l := &linkFeatures{wanted: features & hw}
	if !loopback {
		hw |= feature(bitNocacheCopy)
	}
	if hw&feature(bitTSO) != 0 {
		hw |= feature(bitTSOMangleID)
	}
	l.hw = hw
	l.active = fixFeatures(features)
	return l
}

// update is __netdev_update_features(): the features that the guest cannot
// change stay, and the wanted features join them before the dependency rules
// run.
func (l *linkFeatures) update() {
	l.active = fixFeatures(l.active&^l.hw | l.wanted)
}

// wantMask sets or clears the wanted features of mask that the guest can
// change. It reports false when none of them can change.
func (l *linkFeatures) wantMask(mask uint64, on bool) bool {
	mask &= l.hw
	if mask == 0 {
		return false
	}
	if on {
		l.wanted |= mask
	} else {
		l.wanted &^= mask
	}
	l.update()
	return true
}

// flags returns the legacy flags of ETHTOOL_GFLAGS.
func (l *linkFeatures) flags() uint32 {
	var v uint32
	for _, m := range legacyFlagMap {
		if l.active&m.feature != 0 {
			v |= m.flag
		}
	}
	return v
}

// ethtoolState keeps the feature state of the links of one network stack. The
// stack drops the state of a link when the link leaves the stack.
//
// +stateify savable
type ethtoolState struct {
	mu    sync.Mutex `state:"nosave"`
	links map[tcpip.NICID]*linkFeatures
}

// linkFeaturesLocked returns the state of a link and creates it on first use.
// It also drops the state of links that no longer exist, as the removal of the
// peer of a veth link does not pass the stack of the sockets.
//
// Preconditions: s.offloads.mu is held.
func (s *Stack) linkFeaturesLocked(id tcpip.NICID, info *stack.NICInfo) *linkFeatures {
	for other := range s.offloads.links {
		if _, ok := s.Stack.SingleNICInfo(other); !ok {
			delete(s.offloads.links, other)
		}
	}
	if l, ok := s.offloads.links[id]; ok {
		return l
	}
	if s.offloads.links == nil {
		s.offloads.links = make(map[tcpip.NICID]*linkFeatures)
	}
	l := newLinkFeatures(ethtoolProfileOf(info.Kind, info.Flags.Loopback), info.Flags.Loopback)
	s.offloads.links[id] = l
	return l
}

// dropLinkFeatures forgets the feature state of a link that left the stack.
func (s *Stack) dropLinkFeatures(id tcpip.NICID) {
	s.offloads.mu.Lock()
	defer s.offloads.mu.Unlock()
	delete(s.offloads.links, id)
}

// moveLinkFeatures hands the feature state of a link that moves to the stack
// dst to the new index of the link. The features belong to the device, so a
// move to another network namespace keeps them.
func (s *Stack) moveLinkFeatures(id tcpip.NICID, dst *Stack, newID tcpip.NICID) {
	s.offloads.mu.Lock()
	l, ok := s.offloads.links[id]
	delete(s.offloads.links, id)
	s.offloads.mu.Unlock()
	if !ok {
		return
	}
	dst.offloads.mu.Lock()
	defer dst.offloads.mu.Unlock()
	if dst.offloads.links == nil {
		dst.offloads.links = make(map[tcpip.NICID]*linkFeatures)
	}
	dst.offloads.links[newID] = l
}

// ethtoolUserBuffer is the memory that ifr_data of an SIOCETHTOOL request
// points to.
type ethtoolUserBuffer interface {
	// CopyIn reads len(dst) bytes at offset off.
	CopyIn(off int, dst []byte) error
	// CopyOut writes src at offset off.
	CopyOut(off int, src []byte) error
}

// taskBuffer is the memory of a task at an address.
type taskBuffer struct {
	t    *kernel.Task
	addr hostarch.Addr
}

// CopyIn implements ethtoolUserBuffer.CopyIn.
func (b taskBuffer) CopyIn(off int, dst []byte) error {
	_, err := b.t.CopyInBytes(b.addr+hostarch.Addr(off), dst)
	return err
}

// CopyOut implements ethtoolUserBuffer.CopyOut.
func (b taskBuffer) CopyOut(off int, src []byte) error {
	_, err := b.t.CopyOutBytes(b.addr+hostarch.Addr(off), src)
	return err
}

// errBufferTooSmall is ETOOSMALL (525), which Linux returns when the buffer of
// ETHTOOL_GPERMADDR is shorter than the address.
var errBufferTooSmall = errors.New(errno.Errno(525), "buffer too small")

// ethtoolIoctl implements SIOCETHTOOL for the task. The request names a link
// in ifr_name and holds the address of the ethtool structure in ifr_data.
func ethtoolIoctl(ctx context.Context, t *kernel.Task, ifrAddr hostarch.Addr) (uintptr, error) {
	var ifr linux.IFReq
	if _, err := ifr.CopyIn(t, ifrAddr); err != nil {
		return 0, err
	}
	stk, ok := inet.StackFromContext(ctx).(*Stack)
	if !ok {
		return 0, linuxerr.ENODEV
	}
	data := hostarch.Addr(hostarch.ByteOrder.Uint64(ifr.Data[:8]))
	admin := t.NetworkNamespace().HasCapability(ctx, linux.CAP_NET_ADMIN)
	ret, err := stk.ethtool(ifr.Name(), admin, taskBuffer{t: t, addr: data})
	return uintptr(ret), err
}

// ethtoolReadOnly lists the commands that a caller without CAP_NET_ADMIN may
// send, as dev_ethtool() lists them.
var ethtoolReadOnly = map[uint32]bool{
	ethtoolGSET: true, ethtoolGDRVINFO: true, ethtoolGMSGLVL: true, ethtoolGLINK: true,
	ethtoolGCOALESCE: true, ethtoolGRINGPARAM: true, ethtoolGPAUSEPARAM: true,
	ethtoolGRXCSUM: true, ethtoolGTXCSUM: true, ethtoolGSG: true, ethtoolGSSETINFO: true,
	ethtoolGSTRINGS: true, ethtoolGSTATS: true, ethtoolGPHYSTATS: true, ethtoolGTSO: true,
	ethtoolGPERMADDR: true, ethtoolGUFO: true, ethtoolGGSO: true, ethtoolGGRO: true,
	ethtoolGFLAGS: true, ethtoolGPFLAGS: true, ethtoolGRXFH: true, ethtoolGRXRINGS: true,
	ethtoolGRXCLSRLCNT: true, ethtoolGRXCLSRULE: true, ethtoolGRXCLSRLALL: true,
	ethtoolGRXFHINDIR: true, ethtoolGRSSH: true, ethtoolGFEATURES: true, ethtoolGCHANNELS: true,
	ethtoolGETTSINFO: true, ethtoolGEEE: true, ethtoolGTUNABLE: true, ethtoolGLINKSETS: true,
	ethtoolGFECPARAM: true,
}

// ethtool runs one SIOCETHTOOL command on the link with the given name. admin
// says whether the caller has CAP_NET_ADMIN. The result is the value that the
// ioctl returns.
func (s *Stack) ethtool(name string, admin bool, u ethtoolUserBuffer) (int, error) {
	var (
		id   tcpip.NICID
		info stack.NICInfo
		ok   bool
	)
	for nid, ni := range s.Stack.NICInfo() {
		if ni.Name == name {
			id, info, ok = nid, ni, true
			break
		}
	}
	if !ok {
		return 0, linuxerr.ENODEV
	}
	var cmdBuf [4]byte
	if err := u.CopyIn(0, cmdBuf[:]); err != nil {
		return 0, err
	}
	cmd := hostarch.ByteOrder.Uint32(cmdBuf[:])
	if !ethtoolReadOnly[cmd] && !admin {
		return 0, linuxerr.EPERM
	}

	s.offloads.mu.Lock()
	defer s.offloads.mu.Unlock()
	l := s.linkFeaturesLocked(id, &info)
	profile := ethtoolProfileOf(info.Kind, info.Flags.Loopback)

	switch cmd {
	case ethtoolGDRVINFO:
		return 0, ethtoolGetDrvinfo(u, profile)
	case ethtoolGLINK:
		return 0, ethtoolPutValue(u, cmd, boolToUint32(info.Flags.Running || profile.carrierAlways))
	case ethtoolGSET:
		return 0, ethtoolGetSettings(u, profile)
	case ethtoolGLINKSETS:
		return 0, ethtoolGetLinkSettings(u, profile)
	case ethtoolGFEATURES:
		return 0, ethtoolGetFeatures(u, l)
	case ethtoolSFEATURES:
		return ethtoolSetFeatures(u, l)
	case ethtoolGSSETINFO:
		return 0, ethtoolGetSSetInfo(u)
	case ethtoolGSTRINGS:
		return 0, ethtoolGetStrings(u)
	case ethtoolGFLAGS:
		return 0, ethtoolPutValue(u, cmd, l.flags())
	case ethtoolSFLAGS:
		return 0, ethtoolSetFlags(u, l)
	case ethtoolGPERMADDR:
		return 0, ethtoolGetPermAddr(u, &info, profile)
	case ethtoolGETTSINFO:
		return 0, ethtoolGetTSInfo(u)
	case ethtoolGTXCSUM, ethtoolGRXCSUM, ethtoolGSG, ethtoolGTSO, ethtoolGGSO, ethtoolGGRO:
		return 0, ethtoolPutValue(u, cmd, boolToUint32(l.active&legacyMask(cmd) != 0))
	case ethtoolSTXCSUM, ethtoolSRXCSUM, ethtoolSSG, ethtoolSTSO, ethtoolSGSO, ethtoolSGRO:
		return 0, ethtoolSetOne(u, l, cmd)
	}
	return 0, linuxerr.EOPNOTSUPP
}

func boolToUint32(b bool) uint32 {
	if b {
		return 1
	}
	return 0
}

// legacyMask is ethtool_get_feature_mask(): the features that a legacy get or
// set command stands for. A set command has the number of its get command plus
// one.
func legacyMask(cmd uint32) uint64 {
	switch cmd {
	case ethtoolGTXCSUM, ethtoolSTXCSUM:
		return legacyTxCsum
	case ethtoolGRXCSUM, ethtoolSRXCSUM:
		return feature(bitRXCsum)
	case ethtoolGSG, ethtoolSSG:
		return feature(bitSG)
	case ethtoolGTSO, ethtoolSTSO:
		return allTSO
	case ethtoolGGSO, ethtoolSGSO:
		return feature(bitGSO)
	case ethtoolGGRO, ethtoolSGRO:
		return feature(bitGRO)
	}
	return 0
}

// ethtoolPutValue writes struct ethtool_value.
func ethtoolPutValue(u ethtoolUserBuffer, cmd, data uint32) error {
	var b [8]byte
	hostarch.ByteOrder.PutUint32(b[0:], cmd)
	hostarch.ByteOrder.PutUint32(b[4:], data)
	return u.CopyOut(0, b[:])
}

// ethtoolSetOne is ethtool_set_one_feature().
func ethtoolSetOne(u ethtoolUserBuffer, l *linkFeatures, cmd uint32) error {
	var b [8]byte
	if err := u.CopyIn(0, b[:]); err != nil {
		return err
	}
	if !l.wantMask(legacyMask(cmd), hostarch.ByteOrder.Uint32(b[4:]) != 0) {
		return linuxerr.EOPNOTSUPP
	}
	return nil
}

// ethtoolGetDrvinfo writes struct ethtool_drvinfo.
func ethtoolGetDrvinfo(u ethtoolUserBuffer, p ethtoolProfile) error {
	b := make([]byte, ethtoolDrvinfoSize)
	hostarch.ByteOrder.PutUint32(b, ethtoolGDRVINFO)
	copy(b[4:36], p.driver)
	copy(b[36:68], p.version)
	copy(b[100:132], p.busInfo)
	return u.CopyOut(0, b)
}

// ethtoolGetSettings writes struct ethtool_cmd. A link without link settings
// answers EOPNOTSUPP, as a Linux driver without get_link_ksettings does.
func ethtoolGetSettings(u ethtoolUserBuffer, p ethtoolProfile) error {
	if p.settings == nil {
		return linuxerr.EOPNOTSUPP
	}
	b := make([]byte, ethtoolCmdSize)
	hostarch.ByteOrder.PutUint32(b[0:], ethtoolGSET)
	hostarch.ByteOrder.PutUint16(b[12:], uint16(p.settings.speed))
	b[14] = p.settings.duplex
	b[15] = p.settings.port
	hostarch.ByteOrder.PutUint16(b[32:], uint16(p.settings.speed>>16))
	return u.CopyOut(0, b)
}

// ethtoolGetLinkSettings writes struct ethtool_link_settings. A request with a
// wrong count of mask words gets the negative count that the driver needs, as
// the handshake of Linux says.
func ethtoolGetLinkSettings(u ethtoolUserBuffer, p ethtoolProfile) error {
	if p.settings == nil {
		return linuxerr.EOPNOTSUPP
	}
	var req [ethtoolLinkSetSize]byte
	if err := u.CopyIn(0, req[:]); err != nil {
		return err
	}
	b := make([]byte, ethtoolLinkSetSize+3*linkModeMaskWords*4)
	hostarch.ByteOrder.PutUint32(b[0:], ethtoolGLINKSETS)
	if int8(req[15]) != linkModeMaskWords {
		b[15] = byte(0x100 - linkModeMaskWords)
		return u.CopyOut(0, b[:ethtoolLinkSetSize])
	}
	hostarch.ByteOrder.PutUint32(b[4:], p.settings.speed)
	b[8] = p.settings.duplex
	b[9] = p.settings.port
	b[15] = linkModeMaskWords
	return u.CopyOut(0, b)
}

// ethtoolGetFeatures is ethtool_get_features().
func ethtoolGetFeatures(u ethtoolUserBuffer, l *linkFeatures) error {
	var hdr [8]byte
	if err := u.CopyIn(0, hdr[:]); err != nil {
		return err
	}
	blocks := min(hostarch.ByteOrder.Uint32(hdr[4:]), featureWords)
	hostarch.ByteOrder.PutUint32(hdr[0:], ethtoolGFEATURES)
	hostarch.ByteOrder.PutUint32(hdr[4:], featureWords)
	if err := u.CopyOut(0, hdr[:]); err != nil {
		return err
	}
	out := make([]byte, int(blocks)*ethtoolBlockSize)
	for i := range int(blocks) {
		shift := 32 * i
		hostarch.ByteOrder.PutUint32(out[i*ethtoolBlockSize+0:], uint32(l.hw>>shift))
		hostarch.ByteOrder.PutUint32(out[i*ethtoolBlockSize+4:], uint32(l.wanted>>shift))
		hostarch.ByteOrder.PutUint32(out[i*ethtoolBlockSize+8:], uint32(l.active>>shift))
		hostarch.ByteOrder.PutUint32(out[i*ethtoolBlockSize+12:], uint32(neverChange>>shift))
	}
	return u.CopyOut(len(hdr), out)
}

// ethtoolSetFeatures is ethtool_set_features(). The result carries the flags
// ETHTOOL_F_UNSUPPORTED and ETHTOOL_F_WISH.
func ethtoolSetFeatures(u ethtoolUserBuffer, l *linkFeatures) (int, error) {
	var hdr [8]byte
	if err := u.CopyIn(0, hdr[:]); err != nil {
		return 0, err
	}
	if hostarch.ByteOrder.Uint32(hdr[4:]) != featureWords {
		return 0, linuxerr.EINVAL
	}
	raw := make([]byte, featureWords*ethtoolSetBlockSize)
	if err := u.CopyIn(len(hdr), raw); err != nil {
		return 0, err
	}
	var valid, wanted uint64
	for i := range featureWords {
		valid |= uint64(hostarch.ByteOrder.Uint32(raw[i*ethtoolSetBlockSize:])) << (32 * i)
		wanted |= uint64(hostarch.ByteOrder.Uint32(raw[i*ethtoolSetBlockSize+4:])) << (32 * i)
	}
	if valid&^ethtoolBits != 0 {
		return 0, linuxerr.EINVAL
	}
	ret := 0
	if valid&^l.hw != 0 {
		valid &= l.hw
		ret |= ethtoolFUnsupported
	}
	l.wanted = l.wanted&^valid | wanted&valid
	l.update()
	if (l.wanted^l.active)&valid != 0 {
		ret |= ethtoolFWish
	}
	return ret, nil
}

// ethtoolSetFlags is __ethtool_set_flags().
func ethtoolSetFlags(u ethtoolUserBuffer, l *linkFeatures) error {
	var b [8]byte
	if err := u.CopyIn(0, b[:]); err != nil {
		return err
	}
	data := hostarch.ByteOrder.Uint32(b[4:])
	var all uint32
	var allFeatures, features uint64
	for _, m := range legacyFlagMap {
		all |= m.flag
		allFeatures |= m.feature
		if data&m.flag != 0 {
			features |= m.feature
		}
	}
	if data&^all != 0 {
		return linuxerr.EINVAL
	}
	changed := (features ^ l.active) & allFeatures
	if changed&^l.hw != 0 {
		if changed&l.hw != 0 {
			return linuxerr.EINVAL
		}
		return linuxerr.EOPNOTSUPP
	}
	l.wanted = l.wanted&^changed | features&changed
	l.update()
	return nil
}

// ethtoolGetSSetInfo is ethtool_get_sset_info(). The only string set that a
// link has is the feature names.
func ethtoolGetSSetInfo(u ethtoolUserBuffer) error {
	var hdr [ethtoolSSetInfoSize]byte
	if err := u.CopyIn(0, hdr[:]); err != nil {
		return err
	}
	mask := hostarch.ByteOrder.Uint64(hdr[8:])
	if mask == 0 {
		return nil
	}
	var counts []byte
	var have uint64
	if mask&(1<<ethSSFeatures) != 0 {
		have |= 1 << ethSSFeatures
		counts = hostarch.ByteOrder.AppendUint32(counts, featureCount)
	}
	hostarch.ByteOrder.PutUint32(hdr[0:], ethtoolGSSETINFO)
	hostarch.ByteOrder.PutUint32(hdr[4:], 0)
	hostarch.ByteOrder.PutUint64(hdr[8:], have)
	if err := u.CopyOut(0, hdr[:]); err != nil {
		return err
	}
	if len(counts) == 0 {
		return nil
	}
	return u.CopyOut(len(hdr), counts)
}

// ethtoolGetStrings is ethtool_get_strings().
func ethtoolGetStrings(u ethtoolUserBuffer) error {
	var hdr [12]byte
	if err := u.CopyIn(0, hdr[:]); err != nil {
		return err
	}
	if hostarch.ByteOrder.Uint32(hdr[4:]) != ethSSFeatures {
		return linuxerr.EOPNOTSUPP
	}
	hostarch.ByteOrder.PutUint32(hdr[8:], featureCount)
	if err := u.CopyOut(0, hdr[:]); err != nil {
		return err
	}
	out := make([]byte, featureCount*ethGStringLen)
	for i, n := range featureNames {
		copy(out[i*ethGStringLen:(i+1)*ethGStringLen], n)
	}
	return u.CopyOut(len(hdr), out)
}

// ethtoolGetPermAddr is ethtool_get_perm_addr().
func ethtoolGetPermAddr(u ethtoolUserBuffer, info *stack.NICInfo, p ethtoolProfile) error {
	var hdr [8]byte
	if err := u.CopyIn(0, hdr[:]); err != nil {
		return err
	}
	addrLen := len(info.LinkAddress)
	if int(hostarch.ByteOrder.Uint32(hdr[4:])) < addrLen {
		return errBufferTooSmall
	}
	hostarch.ByteOrder.PutUint32(hdr[0:], ethtoolGPERMADDR)
	hostarch.ByteOrder.PutUint32(hdr[4:], uint32(addrLen))
	if err := u.CopyOut(0, hdr[:]); err != nil {
		return err
	}
	if addrLen == 0 {
		return nil
	}
	perm := make([]byte, addrLen)
	if p.ownAddress {
		copy(perm, info.LinkAddress)
	}
	return u.CopyOut(len(hdr), perm)
}

// ethtoolGetTSInfo writes struct ethtool_ts_info for a link without a hardware
// clock: software timestamps and no PTP clock.
func ethtoolGetTSInfo(u ethtoolUserBuffer) error {
	const (
		rxSoftware = 1 << 3
		txSoftware = 1 << 1
		software   = 1 << 4
	)
	b := make([]byte, ethtoolTSInfoSize)
	hostarch.ByteOrder.PutUint32(b[0:], ethtoolGETTSINFO)
	hostarch.ByteOrder.PutUint32(b[4:], rxSoftware|txSoftware|software)
	hostarch.ByteOrder.PutUint32(b[8:], 0xffffffff)
	return u.CopyOut(0, b)
}
