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

//go:build linux

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"unsafe"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// The ethtool checks send SIOCETHTOOL with the calls that Calico Felix,
// github.com/safchain/ethtool, and the ethtool tool make: the names of the
// features (ETHTOOL_GSSET_INFO and ETHTOOL_GSTRINGS), the read and write of the
// feature bits (ETHTOOL_GFEATURES and ETHTOOL_SFEATURES), and the legacy
// commands. Felix switches tx-checksum-ip-generic off on vxlan.calico.

const (
	ethGSET      = 0x01
	ethGDRVINFO  = 0x03
	ethGLINK     = 0x0a
	ethGRXCSUM   = 0x14
	ethSRXCSUM   = 0x15
	ethGTXCSUM   = 0x16
	ethSTXCSUM   = 0x17
	ethGSG       = 0x18
	ethSSG       = 0x19
	ethGSTRINGS  = 0x1b
	ethGTSO      = 0x1e
	ethSTSO      = 0x1f
	ethGGSO      = 0x23
	ethSGSO      = 0x24
	ethGGRO      = 0x2b
	ethSGRO      = 0x2c
	ethGSSETINFO = 0x37
	ethGFEATURES = 0x3a
	ethSFEATURES = 0x3b

	ethSSFeatures = 4
	ethFUnsup     = 1
	featureBlocks = 2
	gstringLen    = 32
)

// ifreqData is struct ifreq with the ifr_data member.
type ifreqData struct {
	name [unix.IFNAMSIZ]byte
	data uintptr
	_    [24 - 8]byte
}

// ethtoolIoctl sends one SIOCETHTOOL request for the link. buf holds the
// ethtool structure, which the kernel reads and writes. The result is the
// return value of the ioctl.
func ethtoolIoctl(link string, buf []byte) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)
	var ifr ifreqData
	copy(ifr.name[:], link)
	if len(buf) > 0 {
		ifr.data = uintptr(unsafe.Pointer(&buf[0]))
	}
	r, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), unix.SIOCETHTOOL, uintptr(unsafe.Pointer(&ifr)))
	runtime.KeepAlive(buf)
	if errno != 0 {
		return 0, errno
	}
	return int(r), nil
}

var le = binary.LittleEndian

// ethtoolValue sends a command of struct ethtool_value and returns the data.
func ethtoolValue(link string, cmd uint32, data uint32) (uint32, error) {
	buf := make([]byte, 8)
	le.PutUint32(buf, cmd)
	le.PutUint32(buf[4:], data)
	if _, err := ethtoolIoctl(link, buf); err != nil {
		return 0, err
	}
	return le.Uint32(buf[4:]), nil
}

// featureNames returns the names of ETH_SS_FEATURES, as safchain/ethtool
// reads them: the count with ETHTOOL_GSSET_INFO, then the strings.
func featureNames(link string) ([]string, error) {
	info := make([]byte, 16+4)
	le.PutUint32(info, ethGSSETINFO)
	le.PutUint64(info[8:], 1<<ethSSFeatures)
	if _, err := ethtoolIoctl(link, info); err != nil {
		return nil, fmt.Errorf("ETHTOOL_GSSET_INFO: %w", err)
	}
	if le.Uint64(info[8:]) != 1<<ethSSFeatures {
		return nil, fmt.Errorf("ETHTOOL_GSSET_INFO sset_mask = %#x, want ETH_SS_FEATURES", le.Uint64(info[8:]))
	}
	count := int(le.Uint32(info[16:]))
	strs := make([]byte, 12+count*gstringLen)
	le.PutUint32(strs, ethGSTRINGS)
	le.PutUint32(strs[4:], ethSSFeatures)
	le.PutUint32(strs[8:], uint32(count))
	if _, err := ethtoolIoctl(link, strs); err != nil {
		return nil, fmt.Errorf("ETHTOOL_GSTRINGS: %w", err)
	}
	names := make([]string, count)
	for i := range names {
		raw := strs[12+i*gstringLen : 12+(i+1)*gstringLen]
		names[i] = strings.TrimRight(string(raw), "\x00")
	}
	return names, nil
}

// featureSet is the four masks of ETHTOOL_GFEATURES.
type featureSet struct {
	available, requested, active, neverChanged uint64
}

func getFeatures(link string) (featureSet, error) {
	buf := make([]byte, 8+featureBlocks*16)
	le.PutUint32(buf, ethGFEATURES)
	le.PutUint32(buf[4:], featureBlocks)
	if _, err := ethtoolIoctl(link, buf); err != nil {
		return featureSet{}, fmt.Errorf("ETHTOOL_GFEATURES: %w", err)
	}
	var f featureSet
	for i := range featureBlocks {
		blk := buf[8+i*16:]
		f.available |= uint64(le.Uint32(blk)) << (32 * i)
		f.requested |= uint64(le.Uint32(blk[4:])) << (32 * i)
		f.active |= uint64(le.Uint32(blk[8:])) << (32 * i)
		f.neverChanged |= uint64(le.Uint32(blk[12:])) << (32 * i)
	}
	return f, nil
}

// setFeature sends ETHTOOL_SFEATURES for the bit of one feature and returns
// the flags of the ioctl.
func setFeature(link string, bit int, on bool) (int, error) {
	buf := make([]byte, 8+featureBlocks*8)
	le.PutUint32(buf, ethSFEATURES)
	le.PutUint32(buf[4:], featureBlocks)
	blk := buf[8+(bit/32)*8:]
	le.PutUint32(blk, 1<<(bit%32))
	if on {
		le.PutUint32(blk[4:], 1<<(bit%32))
	}
	return ethtoolIoctl(link, buf)
}

// featureBit returns the bit of the named feature.
func featureBit(link, name string) (int, error) {
	names, err := featureNames(link)
	if err != nil {
		return 0, err
	}
	if i := slices.Index(names, name); i >= 0 {
		return i, nil
	}
	return 0, fmt.Errorf("%s has no feature %q", link, name)
}

// featureState reads the state of the named feature: whether it is requested,
// whether it is active, and whether the guest can change it.
func featureState(link, name string) (requested, active, changeable bool, err error) {
	bit, err := featureBit(link, name)
	if err != nil {
		return false, false, false, err
	}
	f, err := getFeatures(link)
	if err != nil {
		return false, false, false, err
	}
	m := uint64(1) << bit
	return f.requested&m != 0, f.active&m != 0, f.available&m != 0, nil
}

// expectFeature checks the state of a named feature.
func expectFeature(link, name string, wantRequested, wantActive bool) error {
	req, act, _, err := featureState(link, name)
	if err != nil {
		return err
	}
	if req != wantRequested || act != wantActive {
		return fmt.Errorf("%s %s: requested=%t active=%t, want requested=%t active=%t", link, name, req, act, wantRequested, wantActive)
	}
	return nil
}

// toggleFeature switches a feature as Felix does, and checks the result.
func toggleFeature(link, name string, on bool) error {
	bit, err := featureBit(link, name)
	if err != nil {
		return err
	}
	ret, err := setFeature(link, bit, on)
	if err != nil {
		return fmt.Errorf("ETHTOOL_SFEATURES %s %s=%t: %w", link, name, on, err)
	}
	if ret != 0 {
		return fmt.Errorf("ETHTOOL_SFEATURES %s %s=%t returned flags %#x, want 0", link, name, on, ret)
	}
	return expectFeature(link, name, on, on)
}

// ethtoolLinks creates the links of the ethtool checks in the namespace of the
// calling thread: a veth pair, and the vxlan link that Calico creates.
func ethtoolLinks() error {
	if err := netlink.LinkAdd(&netlink.Veth{LinkAttrs: netlink.LinkAttrs{Name: "veth0"}, PeerName: "veth1"}); err != nil {
		return fmt.Errorf("create veth0: %w", err)
	}
	_, err := vxlanDevice("vxlan.calico", 4096, 4789, "", 0, false)
	return err
}

// dropNetAdmin removes CAP_NET_ADMIN from the effective set of the calling
// thread, which never returns to the pool.
func dropNetAdmin() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	data[0].Effective &^= 1 << unix.CAP_NET_ADMIN
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

// ethtoolChecks checks SIOCETHTOOL on a veth pair, a vxlan link, and the
// loopback link in new network namespaces.
func ethtoolChecks() []check {
	var a, b *nsThread
	in := func(t **nsThread, fn func() error) func() error {
		return func() error { return (*t).do(fn) }
	}
	return []check{
		{"ethtool-namespaces-and-links", func() error {
			var err error
			if a, err = newNsThread(); err != nil {
				return err
			}
			if b, err = newNsThread(); err != nil {
				return err
			}
			return a.do(ethtoolLinks)
		}},
		{"ethtool-feature-names-come-from-sset-info-and-strings", in(&a, func() error {
			names, err := featureNames("veth0")
			if err != nil {
				return err
			}
			if len(names) != 64 {
				return fmt.Errorf("ETH_SS_FEATURES has %d names, want 64", len(names))
			}
			seen := map[string]bool{}
			for _, n := range names {
				if n != "" && seen[n] {
					return fmt.Errorf("the feature name %q appears twice", n)
				}
				seen[n] = true
			}
			for _, want := range []string{"tx-checksum-ip-generic", "rx-checksum", "tx-scatter-gather", "tx-tcp-segmentation", "tx-generic-segmentation", "rx-gro"} {
				if !seen[want] {
					return fmt.Errorf("the feature names lack %q", want)
				}
			}
			return nil
		})},
		{"ethtool-new-links-have-offloads-on", in(&a, func() error {
			for _, link := range []string{"veth0", "veth1", "vxlan.calico"} {
				for _, name := range []string{"tx-checksum-ip-generic", "rx-checksum", "tx-scatter-gather", "tx-tcp-segmentation", "tx-generic-segmentation", "rx-gro"} {
					if err := expectFeature(link, name, true, true); err != nil {
						return err
					}
				}
			}
			return nil
		})},
		{"ethtool-felix-switches-tx-checksum-off-on-vxlan", in(&a, func() error {
			if err := toggleFeature("vxlan.calico", "tx-checksum-ip-generic", false); err != nil {
				return err
			}
			// Linux drops the features that need the checksum and keeps the request.
			if err := expectFeature("vxlan.calico", "tx-scatter-gather", true, false); err != nil {
				return err
			}
			if err := expectFeature("vxlan.calico", "tx-tcp-segmentation", true, false); err != nil {
				return err
			}
			// A write on the legacy path reads back the same value.
			if v, err := ethtoolValue("vxlan.calico", ethGTXCSUM, 0); err != nil || v != 0 {
				return fmt.Errorf("ETHTOOL_GTXCSUM = %d, %v, want 0", v, err)
			}
			return expectFeature("veth0", "tx-checksum-ip-generic", true, true)
		})},
		{"ethtool-tx-checksum-on-brings-the-dependent-features-back", in(&a, func() error {
			if err := toggleFeature("vxlan.calico", "tx-checksum-ip-generic", true); err != nil {
				return err
			}
			return expectFeature("vxlan.calico", "tx-scatter-gather", true, true)
		})},
		{"ethtool-rx-checksum-toggles-alone", in(&a, func() error {
			if err := toggleFeature("vxlan.calico", "rx-checksum", false); err != nil {
				return err
			}
			if err := expectFeature("vxlan.calico", "tx-checksum-ip-generic", true, true); err != nil {
				return err
			}
			return toggleFeature("vxlan.calico", "rx-checksum", true)
		})},
		{"ethtool-legacy-offload-commands", in(&a, func() error {
			for _, c := range []struct {
				name     string
				get, set uint32
			}{
				{"tx checksum", ethGTXCSUM, ethSTXCSUM}, {"rx checksum", ethGRXCSUM, ethSRXCSUM}, {"scatter-gather", ethGSG, ethSSG},
				{"TSO", ethGTSO, ethSTSO}, {"GSO", ethGGSO, ethSGSO}, {"GRO", ethGGRO, ethSGRO},
			} {
				if v, err := ethtoolValue("veth1", c.get, 0); err != nil || v != 1 {
					return fmt.Errorf("get %s = %d, %v, want 1", c.name, v, err)
				}
				if _, err := ethtoolValue("veth1", c.set, 0); err != nil {
					return fmt.Errorf("set %s off: %w", c.name, err)
				}
				if v, err := ethtoolValue("veth1", c.get, 0); err != nil || v != 0 {
					return fmt.Errorf("get %s after off = %d, %v, want 0", c.name, v, err)
				}
				if _, err := ethtoolValue("veth1", c.set, 1); err != nil {
					return fmt.Errorf("set %s on: %w", c.name, err)
				}
				if v, err := ethtoolValue("veth1", c.get, 0); err != nil || v != 1 {
					return fmt.Errorf("get %s after on = %d, %v, want 1", c.name, v, err)
				}
			}
			return nil
		})},
		{"ethtool-fixed-features-are-refused-as-in-linux", in(&a, func() error {
			bit, err := featureBit("lo", "tx-checksum-ip-generic")
			if err != nil {
				return err
			}
			ret, err := setFeature("lo", bit, false)
			if err != nil || ret != ethFUnsup {
				return fmt.Errorf("ETHTOOL_SFEATURES of the checksum of lo = %d, %v, want the flag ETHTOOL_F_UNSUPPORTED", ret, err)
			}
			// A fixed feature is on, and the guest never requested it.
			if err := expectFeature("lo", "tx-checksum-ip-generic", false, true); err != nil {
				return err
			}
			if _, err := ethtoolValue("lo", ethSTXCSUM, 0); !errors.Is(err, unix.EOPNOTSUPP) {
				return fmt.Errorf("ETHTOOL_STXCSUM on lo = %v, want EOPNOTSUPP", err)
			}
			bit, err = featureBit("lo", "vlan-challenged")
			if err != nil {
				return err
			}
			if _, err := setFeature("lo", bit, true); !errors.Is(err, unix.EINVAL) {
				return fmt.Errorf("ETHTOOL_SFEATURES of vlan-challenged = %v, want EINVAL", err)
			}
			// TSO is the one offload of lo that the guest can change.
			if _, err := ethtoolValue("lo", ethSTSO, 0); err != nil {
				return fmt.Errorf("ETHTOOL_STSO on lo: %w", err)
			}
			return expectFeature("lo", "tx-tcp-segmentation", false, false)
		})},
		{"ethtool-drvinfo-names-the-driver-and-link-reports-the-carrier", in(&a, func() error {
			for link, want := range map[string]string{"veth0": "veth", "vxlan.calico": "vxlan"} {
				buf := make([]byte, 196)
				le.PutUint32(buf, ethGDRVINFO)
				if _, err := ethtoolIoctl(link, buf); err != nil {
					return fmt.Errorf("ETHTOOL_GDRVINFO on %s: %w", link, err)
				}
				if got := strings.TrimRight(string(buf[4:36]), "\x00"); got != want {
					return fmt.Errorf("driver of %s = %q, want %q", link, got, want)
				}
			}
			if v, err := ethtoolValue("lo", ethGLINK, 0); err != nil || v != 1 {
				return fmt.Errorf("ETHTOOL_GLINK on lo = %d, %v, want 1", v, err)
			}
			buf := make([]byte, 44)
			le.PutUint32(buf, ethGSET)
			if _, err := ethtoolIoctl("veth0", buf); err != nil {
				return fmt.Errorf("ETHTOOL_GSET on veth0: %w", err)
			}
			if speed := le.Uint16(buf[12:]); speed != 10000 {
				return fmt.Errorf("speed of veth0 = %d, want 10000", speed)
			}
			if _, err := ethtoolIoctl("vxlan.calico", buf); !errors.Is(err, unix.EOPNOTSUPP) {
				return fmt.Errorf("ETHTOOL_GSET on vxlan.calico = %v, want EOPNOTSUPP", err)
			}
			return nil
		})},
		{"ethtool-unknown-link-and-command", in(&a, func() error {
			if _, err := ethtoolValue("nosuchlink", ethGTXCSUM, 0); !errors.Is(err, unix.ENODEV) {
				return fmt.Errorf("ETHTOOL_GTXCSUM on a missing link = %v, want ENODEV", err)
			}
			if _, err := ethtoolValue("veth0", 0x7f, 0); !errors.Is(err, unix.EOPNOTSUPP) {
				return fmt.Errorf("an unknown command = %v, want EOPNOTSUPP", err)
			}
			if _, err := ethtoolIoctl("veth0", nil); !errors.Is(err, unix.EFAULT) {
				return fmt.Errorf("a request without data = %v, want EFAULT", err)
			}
			return nil
		})},
		{"ethtool-features-stay-with-a-link-that-changes-namespace", func() error {
			if err := a.do(func() error { return toggleFeature("veth1", "tx-checksum-ip-generic", false) }); err != nil {
				return err
			}
			if err := a.do(func() error {
				link, err := netlink.LinkByName("veth1")
				if err != nil {
					return err
				}
				return netlink.LinkSetNsFd(link, b.fd)
			}); err != nil {
				return fmt.Errorf("move veth1: %w", err)
			}
			return b.do(func() error {
				if err := expectFeature("veth1", "tx-checksum-ip-generic", false, false); err != nil {
					return err
				}
				// The loopback link of the new namespace has its own state.
				return expectFeature("lo", "tx-tcp-segmentation", true, true)
			})
		}},
		{"ethtool-a-new-link-starts-with-the-defaults", in(&a, func() error {
			if err := toggleFeature("vxlan.calico", "tx-checksum-ip-generic", false); err != nil {
				return err
			}
			link, err := netlink.LinkByName("vxlan.calico")
			if err != nil {
				return err
			}
			if err := netlink.LinkDel(link); err != nil {
				return err
			}
			if _, err := vxlanDevice("vxlan.calico", 4096, 4789, "", 0, false); err != nil {
				return err
			}
			return expectFeature("vxlan.calico", "tx-checksum-ip-generic", true, true)
		})},
		{"ethtool-a-set-command-needs-cap-net-admin", func() error {
			c, err := newNsThread()
			if err != nil {
				return err
			}
			defer c.close()
			if err := c.do(ethtoolLinks); err != nil {
				return err
			}
			return c.do(func() error {
				if err := dropNetAdmin(); err != nil {
					return err
				}
				if _, err := getFeatures("veth0"); err != nil {
					return fmt.Errorf("ETHTOOL_GFEATURES without CAP_NET_ADMIN: %w", err)
				}
				bit, err := featureBit("veth0", "tx-checksum-ip-generic")
				if err != nil {
					return err
				}
				if _, err := setFeature("veth0", bit, false); !errors.Is(err, unix.EPERM) {
					return fmt.Errorf("ETHTOOL_SFEATURES without CAP_NET_ADMIN = %v, want EPERM", err)
				}
				if _, err := ethtoolValue("veth0", ethSTXCSUM, 0); !errors.Is(err, unix.EPERM) {
					return fmt.Errorf("ETHTOOL_STXCSUM without CAP_NET_ADMIN = %v, want EPERM", err)
				}
				return expectFeature("veth0", "tx-checksum-ip-generic", true, true)
			})
		}},
	}
}
