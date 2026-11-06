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
	"errors"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/link/veth"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// memBuffer is the user memory of one request. A read or write outside the
// slice fails as a bad address does.
type memBuffer []byte

func (m memBuffer) CopyIn(off int, dst []byte) error {
	if off+len(dst) > len(m) {
		return linuxerr.EFAULT
	}
	copy(dst, m[off:])
	return nil
}

func (m memBuffer) CopyOut(off int, src []byte) error {
	if off+len(src) > len(m) {
		return linuxerr.EFAULT
	}
	copy(m[off:], src)
	return nil
}

// ethtoolStack returns a stack with one link of each named kind. The kind
// "lo" is the loopback link. The links are called after their kinds and have
// the indexes 1, 2, and so on.
func ethtoolStack(t *testing.T, kinds ...string) *Stack {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	t.Cleanup(func() { s.Close() })
	for i, kind := range kinds {
		opts := stack.NICOptions{Name: kind, Kind: kind, MinMTU: ethernetMinMTU, MaxMTU: ethernetMaxMTU}
		a, _ := veth.NewPair(defaultMTU, veth.DefaultBacklogSize)
		ep := newVethNICEndpoint(a)
		if kind == "lo" {
			opts.Kind = ""
			ep = loopback.New()
		}
		if err := s.CreateNICWithOptions(tcpip.NICID(i+1), ep, opts); err != nil {
			t.Fatalf("CreateNICWithOptions(%s): %v", kind, err)
		}
	}
	return NewStack(s, 1)
}

func le32(b []byte, off int) uint32 { return hostarch.ByteOrder.Uint32(b[off:]) }

// getFeatures sends ETHTOOL_GFEATURES and returns the four masks of the link.
func getFeatures(t *testing.T, s *Stack, link string) (available, requested, active, neverChanged uint64) {
	t.Helper()
	buf := make(memBuffer, 8+featureWords*ethtoolBlockSize)
	hostarch.ByteOrder.PutUint32(buf[0:], ethtoolGFEATURES)
	hostarch.ByteOrder.PutUint32(buf[4:], featureWords)
	if _, err := s.ethtool(link, false, buf); err != nil {
		t.Fatalf("ETHTOOL_GFEATURES on %s: %v", link, err)
	}
	if got := le32(buf, 4); got != featureWords {
		t.Fatalf("ETHTOOL_GFEATURES size = %d, want %d", got, featureWords)
	}
	for i := range featureWords {
		blk := buf[8+i*ethtoolBlockSize:]
		available |= uint64(le32(blk, 0)) << (32 * i)
		requested |= uint64(le32(blk, 4)) << (32 * i)
		active |= uint64(le32(blk, 8)) << (32 * i)
		neverChanged |= uint64(le32(blk, 12)) << (32 * i)
	}
	return
}

// setFeatures sends ETHTOOL_SFEATURES for the features in mask.
func setFeatures(s *Stack, link string, admin bool, mask uint64, on bool) (int, error) {
	buf := make(memBuffer, 8+featureWords*ethtoolSetBlockSize)
	hostarch.ByteOrder.PutUint32(buf[0:], ethtoolSFEATURES)
	hostarch.ByteOrder.PutUint32(buf[4:], featureWords)
	for i := range featureWords {
		blk := buf[8+i*ethtoolSetBlockSize:]
		hostarch.ByteOrder.PutUint32(blk[0:], uint32(mask>>(32*i)))
		if on {
			hostarch.ByteOrder.PutUint32(blk[4:], uint32(mask>>(32*i)))
		}
	}
	return s.ethtool(link, admin, buf)
}

// legacyValue sends a legacy get command and returns the value.
func legacyValue(t *testing.T, s *Stack, link string, cmd uint32) uint32 {
	t.Helper()
	buf := make(memBuffer, 8)
	hostarch.ByteOrder.PutUint32(buf, cmd)
	if _, err := s.ethtool(link, false, buf); err != nil {
		t.Fatalf("command %#x on %s: %v", cmd, link, err)
	}
	return le32(buf, 4)
}

// legacySet sends a legacy set command.
func legacySet(s *Stack, link string, cmd, value uint32) error {
	buf := make(memBuffer, 8)
	hostarch.ByteOrder.PutUint32(buf[0:], cmd)
	hostarch.ByteOrder.PutUint32(buf[4:], value)
	_, err := s.ethtool(link, true, buf)
	return err
}

func requireErr(t *testing.T, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestFeatureNamesFollowLinuxBitOrder(t *testing.T) {
	if featureCount != 64 || featureWords != 2 {
		t.Fatalf("featureCount = %d, featureWords = %d, want 64 and 2", featureCount, featureWords)
	}
	for bit, want := range map[int]string{
		0: "tx-scatter-gather", 1: "tx-checksum-ipv4", 3: "tx-checksum-ip-generic", 4: "tx-checksum-ipv6",
		11: "tx-generic-segmentation", 14: "rx-gro", 16: "tx-tcp-segmentation", 20: "tx-tcp6-segmentation",
		36: "tx-checksum-sctp", 40: "rx-checksum", 41: "tx-nocache-copy",
	} {
		if featureNames[bit] != want {
			t.Errorf("feature bit %d is %q, want %q", bit, featureNames[bit], want)
		}
	}
}

func TestStringsAndCountsDescribeTheFeatureBits(t *testing.T) {
	s := ethtoolStack(t, "veth")

	info := make(memBuffer, ethtoolSSetInfoSize+4*3)
	hostarch.ByteOrder.PutUint32(info[0:], ethtoolGSSETINFO)
	// Ask for ETH_SS_STATS (1), ETH_SS_FEATURES (4), and ETH_SS_TUNABLES (6).
	hostarch.ByteOrder.PutUint64(info[8:], 1<<1|1<<ethSSFeatures|1<<6)
	if _, err := s.ethtool("veth", false, info); err != nil {
		t.Fatalf("ETHTOOL_GSSET_INFO: %v", err)
	}
	if got := hostarch.ByteOrder.Uint64(info[8:]); got != 1<<ethSSFeatures {
		t.Errorf("sset_mask = %#x, want only ETH_SS_FEATURES", got)
	}
	if got := le32(info, 16); got != featureCount {
		t.Errorf("count of ETH_SS_FEATURES = %d, want %d", got, featureCount)
	}

	strs := make(memBuffer, 12+featureCount*ethGStringLen)
	hostarch.ByteOrder.PutUint32(strs[0:], ethtoolGSTRINGS)
	hostarch.ByteOrder.PutUint32(strs[4:], ethSSFeatures)
	if _, err := s.ethtool("veth", false, strs); err != nil {
		t.Fatalf("ETHTOOL_GSTRINGS: %v", err)
	}
	if got := le32(strs, 8); got != featureCount {
		t.Errorf("GSTRINGS len = %d, want %d", got, featureCount)
	}
	name := func(bit int) string {
		raw := strs[12+bit*ethGStringLen : 12+(bit+1)*ethGStringLen]
		return strings.TrimRight(string(raw), "\x00")
	}
	if name(bitHWCsum) != "tx-checksum-ip-generic" || name(bitRXCsum) != "rx-checksum" || name(2) != "" {
		t.Errorf("strings at bits 3, 40, and 2 = %q, %q, %q", name(bitHWCsum), name(bitRXCsum), name(2))
	}

	strs = make(memBuffer, 12)
	hostarch.ByteOrder.PutUint32(strs[0:], ethtoolGSTRINGS)
	hostarch.ByteOrder.PutUint32(strs[4:], 1) // ETH_SS_STATS
	_, err := s.ethtool("veth", false, strs)
	requireErr(t, "GSTRINGS of ETH_SS_STATS", err, linuxerr.EOPNOTSUPP)
}

func TestVethStartsWithTheLinuxVethFeatures(t *testing.T) {
	s := ethtoolStack(t, "veth")
	avail, req, active, never := getFeatures(t, s, "veth")
	on := func(name string, mask uint64) {
		if active&mask != mask {
			t.Errorf("%s is off on a new veth link, want on", name)
		}
	}
	on("tx-checksum-ip-generic", feature(bitHWCsum))
	on("rx-checksum", feature(bitRXCsum))
	on("tx-scatter-gather", feature(bitSG))
	on("tx-tcp-segmentation", feature(bitTSO, bitTSO6))
	on("tx-generic-segmentation", feature(bitGSO))
	on("rx-gro", feature(bitGRO))
	on("tx-udp_tnl-segmentation", feature(bitGSOUDPTunnel))
	if active&feature(bitNocacheCopy, bitLRO, bitIPCsum) != 0 {
		t.Errorf("nocache-copy, lro, or tx-checksum-ipv4 is on: active=%#x", active)
	}
	if avail&feature(bitHWCsum, bitSG, bitTSO, bitTSOMangleID, bitNocacheCopy, bitGRO) != feature(bitHWCsum, bitSG, bitTSO, bitTSOMangleID, bitNocacheCopy, bitGRO) {
		t.Errorf("available = %#x lacks a toggle that a veth link has", avail)
	}
	if avail&feature(bitLRO, bitIPCsum, bitVlanChallenged) != 0 {
		t.Errorf("available = %#x holds a fixed feature", avail)
	}
	if req&active != active&avail {
		t.Errorf("requested = %#x and active = %#x differ for the toggles", req, active)
	}
	if never != neverChange {
		t.Errorf("never_changed = %#x, want %#x", never, neverChange)
	}
}

func TestSetFeaturesThenGetReturnsTheNewValue(t *testing.T) {
	s := ethtoolStack(t, "vxlan")
	ret, err := setFeatures(s, "vxlan", true, feature(bitHWCsum), false)
	if err != nil || ret != 0 {
		t.Fatalf("SFEATURES tx-checksum-ip-generic off = (%d, %v), want (0, nil)", ret, err)
	}
	_, req, active, _ := getFeatures(t, s, "vxlan")
	if active&feature(bitHWCsum) != 0 || req&feature(bitHWCsum) != 0 {
		t.Errorf("tx-checksum-ip-generic: requested=%#x active=%#x, want off in both", req, active)
	}
	// Linux drops scatter-gather, TSO, and GSO when the link has no checksum
	// feature, and keeps the request of the guest.
	if active&feature(bitSG, bitTSO, bitTSO6, bitGSO) != 0 {
		t.Errorf("active = %#x keeps scatter-gather, TSO, or GSO without a checksum feature", active)
	}
	if req&feature(bitSG, bitTSO, bitGSO) != feature(bitSG, bitTSO, bitGSO) {
		t.Errorf("requested = %#x lost the request for scatter-gather, TSO, or GSO", req)
	}

	if _, err := setFeatures(s, "vxlan", true, feature(bitHWCsum), true); err != nil {
		t.Fatalf("SFEATURES tx-checksum-ip-generic on: %v", err)
	}
	_, _, active, _ = getFeatures(t, s, "vxlan")
	if active&feature(bitHWCsum, bitSG, bitTSO, bitGSO) != feature(bitHWCsum, bitSG, bitTSO, bitGSO) {
		t.Errorf("active = %#x does not bring scatter-gather and TSO back", active)
	}

	if _, err := setFeatures(s, "vxlan", true, feature(bitRXCsum), false); err != nil {
		t.Fatalf("SFEATURES rx-checksum off: %v", err)
	}
	_, _, active, _ = getFeatures(t, s, "vxlan")
	if active&feature(bitRXCsum) != 0 || active&feature(bitHWCsum) == 0 {
		t.Errorf("active = %#x after rx-checksum off, want only rx-checksum off", active)
	}
}

func TestSetFeaturesRefusesWhatLinuxRefuses(t *testing.T) {
	s := ethtoolStack(t, "veth")

	_, err := setFeatures(s, "veth", true, feature(bitVlanChallenged), true)
	requireErr(t, "SFEATURES of a never-changed bit", err, linuxerr.EINVAL)

	before := func() uint64 { _, _, a, _ := getFeatures(t, s, "veth"); return a }
	active := before()
	ret, err := setFeatures(s, "veth", true, feature(bitLRO), true)
	if err != nil || ret != ethtoolFUnsupported {
		t.Errorf("SFEATURES rx-lro on veth = (%d, %v), want (ETHTOOL_F_UNSUPPORTED, nil)", ret, err)
	}
	if got := before(); got != active {
		t.Errorf("active changed from %#x to %#x after a refused request", active, got)
	}

	buf := make(memBuffer, 8+featureWords*ethtoolSetBlockSize)
	hostarch.ByteOrder.PutUint32(buf[0:], ethtoolSFEATURES)
	hostarch.ByteOrder.PutUint32(buf[4:], 1) // one block, not two
	_, err = s.ethtool("veth", true, buf)
	requireErr(t, "SFEATURES with one block", err, linuxerr.EINVAL)

	_, err = s.ethtool("veth", true, buf[:6])
	requireErr(t, "SFEATURES with a truncated header", err, linuxerr.EFAULT)

	// A link that cannot change a feature ignores the request for the others.
	lo := ethtoolStack(t, "lo")
	ret, err = setFeatures(lo, "lo", true, feature(bitHWCsum), false)
	if err != nil || ret != ethtoolFUnsupported {
		t.Errorf("SFEATURES tx-checksum-ip-generic on lo = (%d, %v), want (ETHTOOL_F_UNSUPPORTED, nil)", ret, err)
	}
	if _, _, a, _ := getFeatures(t, lo, "lo"); a&feature(bitHWCsum) == 0 {
		t.Error("tx-checksum-ip-generic of lo went off")
	}
}

func TestLegacyFeatureCommands(t *testing.T) {
	s := ethtoolStack(t, "veth", "lo")
	for _, tc := range []struct {
		name     string
		get, set uint32
	}{
		{"tx checksum", ethtoolGTXCSUM, ethtoolSTXCSUM},
		{"rx checksum", ethtoolGRXCSUM, ethtoolSRXCSUM},
		{"scatter-gather", ethtoolGSG, ethtoolSSG},
		{"TSO", ethtoolGTSO, ethtoolSTSO},
		{"GSO", ethtoolGGSO, ethtoolSGSO},
		{"GRO", ethtoolGGRO, ethtoolSGRO},
	} {
		if legacyValue(t, s, "veth", tc.get) != 1 {
			t.Errorf("%s is off on a new veth link", tc.name)
		}
		if err := legacySet(s, "veth", tc.set, 0); err != nil {
			t.Errorf("set %s off: %v", tc.name, err)
		}
		if legacyValue(t, s, "veth", tc.get) != 0 {
			t.Errorf("%s is on after it was set off", tc.name)
		}
		if err := legacySet(s, "veth", tc.set, 5); err != nil {
			t.Errorf("set %s on: %v", tc.name, err)
		}
		if legacyValue(t, s, "veth", tc.get) != 1 {
			t.Errorf("%s is off after it was set on", tc.name)
		}
	}

	// Switching the transmit checksum off also switches scatter-gather off.
	if err := legacySet(s, "veth", ethtoolSTXCSUM, 0); err != nil {
		t.Fatal(err)
	}
	if legacyValue(t, s, "veth", ethtoolGSG) != 0 || legacyValue(t, s, "veth", ethtoolGTSO) != 0 {
		t.Error("scatter-gather or TSO stays on without a transmit checksum")
	}

	// The loopback link cannot change its checksum, but it can change TSO.
	requireErr(t, "set tx checksum on lo", legacySet(s, "lo", ethtoolSTXCSUM, 0), linuxerr.EOPNOTSUPP)
	requireErr(t, "set rx checksum on lo", legacySet(s, "lo", ethtoolSRXCSUM, 0), linuxerr.EOPNOTSUPP)
	if err := legacySet(s, "lo", ethtoolSTSO, 0); err != nil {
		t.Errorf("set TSO off on lo: %v", err)
	}
	if legacyValue(t, s, "lo", ethtoolGTXCSUM) != 1 || legacyValue(t, s, "lo", ethtoolGTSO) != 0 {
		t.Error("lo keeps its checksum and loses TSO, but the commands say otherwise")
	}
}

func TestFlagsFollowTheFeatures(t *testing.T) {
	s := ethtoolStack(t, "veth")
	const rxtx = ethFlagTxVlan | ethFlagRxVlan
	if got := legacyValue(t, s, "veth", ethtoolGFLAGS); got != rxtx {
		t.Errorf("GFLAGS = %#x, want %#x", got, uint32(rxtx))
	}
	if err := legacySet(s, "veth", ethtoolSFLAGS, ethFlagRxVlan); err != nil {
		t.Fatalf("SFLAGS: %v", err)
	}
	if got := legacyValue(t, s, "veth", ethtoolGFLAGS); got != ethFlagRxVlan {
		t.Errorf("GFLAGS after SFLAGS = %#x, want rxvlan only", got)
	}
	if _, _, active, _ := getFeatures(t, s, "veth"); active&feature(bitVlanCtagTX) != 0 {
		t.Error("tx-vlan-hw-insert is on after SFLAGS cleared txvlan")
	}
	// Linux compares all flags with the state, so the request must repeat the
	// flags that are on. LRO alone is a change that the link cannot make.
	requireErr(t, "SFLAGS with LRO", legacySet(s, "veth", ethtoolSFLAGS, ethFlagRxVlan|ethFlagLRO), linuxerr.EOPNOTSUPP)
	requireErr(t, "SFLAGS that changes LRO and TX VLAN", legacySet(s, "veth", ethtoolSFLAGS, ethFlagLRO), linuxerr.EINVAL)
	requireErr(t, "SFLAGS with an unknown flag", legacySet(s, "veth", ethtoolSFLAGS, 1), linuxerr.EINVAL)
}

func TestEthtoolPermissions(t *testing.T) {
	s := ethtoolStack(t, "veth")
	_, err := setFeatures(s, "veth", false, feature(bitHWCsum), false)
	requireErr(t, "SFEATURES without CAP_NET_ADMIN", err, linuxerr.EPERM)
	buf := make(memBuffer, 8)
	hostarch.ByteOrder.PutUint32(buf, 0x7f)
	_, err = s.ethtool("veth", false, buf)
	requireErr(t, "unknown command without CAP_NET_ADMIN", err, linuxerr.EPERM)
	_, err = s.ethtool("veth", true, buf)
	requireErr(t, "unknown command with CAP_NET_ADMIN", err, linuxerr.EOPNOTSUPP)
	if _, _, a, _ := getFeatures(t, s, "veth"); a&feature(bitHWCsum) == 0 {
		t.Error("a refused SFEATURES changed the features")
	}
	_, err = s.ethtool("nosuch", true, buf)
	requireErr(t, "request for a missing link", err, linuxerr.ENODEV)
	_, err = s.ethtool("veth", true, buf[:2])
	requireErr(t, "request with a bad address", err, linuxerr.EFAULT)
}

func TestFeaturesBelongToOneLink(t *testing.T) {
	s := ethtoolStack(t, "veth", "vxlan")
	if _, err := setFeatures(s, "veth", true, feature(bitHWCsum), false); err != nil {
		t.Fatal(err)
	}
	if _, _, a, _ := getFeatures(t, s, "vxlan"); a&feature(bitHWCsum) == 0 {
		t.Error("a change of veth switched the checksum of vxlan off")
	}
}

func TestDriverInfoAndLinkState(t *testing.T) {
	s := ethtoolStack(t, "veth", "vxlan", "bridge", "")
	for _, tc := range []struct {
		link, driver, version string
	}{
		{"veth", "veth", "1"}, {"vxlan", "vxlan", "0.1"}, {"bridge", "bridge", "2.3"}, {"", "virtio_net", "1.0.0"},
	} {
		buf := make(memBuffer, ethtoolDrvinfoSize)
		hostarch.ByteOrder.PutUint32(buf, ethtoolGDRVINFO)
		if _, err := s.ethtool(tc.link, false, buf); err != nil {
			t.Fatalf("GDRVINFO on %q: %v", tc.link, err)
		}
		field := func(off int) string { return strings.TrimRight(string(buf[off:off+32]), "\x00") }
		if field(4) != tc.driver || field(36) != tc.version {
			t.Errorf("GDRVINFO on %q = driver %q, version %q, want %q and %q", tc.link, field(4), field(36), tc.driver, tc.version)
		}
	}
	short := make(memBuffer, 100)
	hostarch.ByteOrder.PutUint32(short, ethtoolGDRVINFO)
	_, err := s.ethtool("veth", false, short)
	requireErr(t, "GDRVINFO into a short buffer", err, linuxerr.EFAULT)
}

func TestLinkSettingsHandshake(t *testing.T) {
	s := ethtoolStack(t, "veth", "vxlan")
	buf := make(memBuffer, ethtoolLinkSetSize+3*linkModeMaskWords*4)
	hostarch.ByteOrder.PutUint32(buf, ethtoolGLINKSETS)
	if _, err := s.ethtool("veth", false, buf); err != nil {
		t.Fatalf("GLINKSETTINGS handshake: %v", err)
	}
	if got := int8(buf[15]); got != -linkModeMaskWords {
		t.Fatalf("link_mode_masks_nwords = %d, want %d", got, -linkModeMaskWords)
	}
	buf[15] = linkModeMaskWords
	if _, err := s.ethtool("veth", false, buf); err != nil {
		t.Fatalf("GLINKSETTINGS: %v", err)
	}
	if speed := le32(buf, 4); speed != 10000 || buf[8] != duplexFull || buf[9] != portTP {
		t.Errorf("veth link settings = speed %d, duplex %d, port %d, want 10000, full, TP", speed, buf[8], buf[9])
	}

	legacy := make(memBuffer, ethtoolCmdSize)
	hostarch.ByteOrder.PutUint32(legacy, ethtoolGSET)
	if _, err := s.ethtool("veth", false, legacy); err != nil {
		t.Fatalf("GSET: %v", err)
	}
	if speed := hostarch.ByteOrder.Uint16(legacy[12:]); speed != 10000 || legacy[14] != duplexFull {
		t.Errorf("GSET speed = %d, duplex = %d, want 10000 and full", speed, legacy[14])
	}
	// vxlan has no link settings, as in Linux.
	_, err := s.ethtool("vxlan", false, legacy)
	requireErr(t, "GSET on vxlan", err, linuxerr.EOPNOTSUPP)
	_, err = s.ethtool("vxlan", false, buf)
	requireErr(t, "GLINKSETTINGS on vxlan", err, linuxerr.EOPNOTSUPP)
}

func TestCarrierOfLinksThatAlwaysHaveOne(t *testing.T) {
	s := ethtoolStack(t, "lo", "vxlan", "veth")
	for id := tcpip.NICID(1); id <= 3; id++ {
		if err := s.Stack.DisableNIC(id); err != nil {
			t.Fatal(err)
		}
	}
	for link, want := range map[string]uint32{"lo": 1, "vxlan": 1, "veth": 0} {
		if got := legacyValue(t, s, link, ethtoolGLINK); got != want {
			t.Errorf("GLINK of %s while it is down = %d, want %d", link, got, want)
		}
	}
}

func TestLinkCarrierPermanentAddressAndTimestamps(t *testing.T) {
	s := ethtoolStack(t, "veth")
	if err := s.Stack.DisableNIC(1); err != nil {
		t.Fatal(err)
	}
	if got := legacyValue(t, s, "veth", ethtoolGLINK); got != 0 {
		t.Errorf("GLINK of a link that is down = %d, want 0", got)
	}
	if err := s.Stack.EnableNIC(1); err != nil {
		t.Fatal(err)
	}
	if got := legacyValue(t, s, "veth", ethtoolGLINK); got != 1 {
		t.Errorf("GLINK of a link that is up = %d, want 1", got)
	}

	perm := make(memBuffer, 8+6)
	hostarch.ByteOrder.PutUint32(perm, ethtoolGPERMADDR)
	hostarch.ByteOrder.PutUint32(perm[4:], 6)
	if _, err := s.ethtool("veth", false, perm); err != nil {
		t.Fatalf("GPERMADDR: %v", err)
	}
	if le32(perm, 4) != uint32(len(s.Stack.NICInfo()[1].LinkAddress)) {
		t.Errorf("GPERMADDR size = %d", le32(perm, 4))
	}
	hostarch.ByteOrder.PutUint32(perm[4:], 2)
	if len(s.Stack.NICInfo()[1].LinkAddress) > 2 {
		_, err := s.ethtool("veth", false, perm)
		if err == nil || !strings.Contains(err.Error(), "too small") {
			t.Errorf("GPERMADDR with a buffer of 2 bytes = %v, want the buffer too small error", err)
		}
	}

	ts := make(memBuffer, ethtoolTSInfoSize)
	hostarch.ByteOrder.PutUint32(ts, ethtoolGETTSINFO)
	if _, err := s.ethtool("veth", false, ts); err != nil {
		t.Fatalf("GET_TS_INFO: %v", err)
	}
	if le32(ts, 4) != 1<<1|1<<3|1<<4 || int32(le32(ts, 8)) != -1 {
		t.Errorf("GET_TS_INFO = flags %#x, phc %d, want software timestamps and no clock", le32(ts, 4), int32(le32(ts, 8)))
	}
}

func TestFeatureStateEndsWithTheLink(t *testing.T) {
	s := ethtoolStack(t, "veth", "vxlan", "bridge")
	for _, link := range []string{"veth", "vxlan", "bridge"} {
		if _, err := setFeatures(s, link, true, feature(bitGRO), false); err != nil {
			t.Fatal(err)
		}
	}
	count := func() int {
		s.offloads.mu.Lock()
		defer s.offloads.mu.Unlock()
		return len(s.offloads.links)
	}
	if got := count(); got != 3 {
		t.Fatalf("%d feature states, want 3", got)
	}

	if err := s.RemoveInterface(context.Background(), 1); err != nil {
		t.Fatalf("RemoveInterface: %v", err)
	}
	if got := count(); got != 2 {
		t.Errorf("%d feature states after the removal of a link, want 2", got)
	}

	// A link that disappears without the event of the stack loses its state at
	// the next request.
	if err := s.Stack.RemoveNIC(2); err != nil {
		t.Fatal(err)
	}
	getFeatures(t, s, "bridge")
	if got := count(); got != 1 {
		t.Errorf("%d feature states after the next request, want 1", got)
	}
}

func TestFeatureStateMovesWithTheLink(t *testing.T) {
	src := ethtoolStack(t, "veth")
	dst := ethtoolStack(t)
	if _, err := setFeatures(src, "veth", true, feature(bitGRO), false); err != nil {
		t.Fatal(err)
	}
	src.moveLinkFeatures(1, dst, 7)
	src.offloads.mu.Lock()
	left := len(src.offloads.links)
	src.offloads.mu.Unlock()
	if left != 0 {
		t.Errorf("the old stack keeps %d feature states after the move", left)
	}
	dst.offloads.mu.Lock()
	moved := dst.offloads.links[7]
	dst.offloads.mu.Unlock()
	if moved == nil || moved.active&feature(bitGRO) != 0 || moved.wanted&feature(bitGRO) != 0 {
		t.Errorf("state after the move = %+v, want GRO off", moved)
	}
}
