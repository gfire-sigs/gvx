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
	"net"
	"os"
	"slices"
	"strings"
	"syscall"
)

// The checks in this file cover the kernel files and netlink requests that
// dockerd needs when it runs with --userland-proxy=false and that docker stats
// and iptables-legacy-save need.

const (
	rtmNewLink = 16
	rtmDelLink = 17
	rtmGetLink = 18
	rtmSetLink = 19

	nlmsgError = 2

	iflaIfname      = 3
	iflaMaster      = 10
	iflaProtinfo    = 12
	iflaLinkinfo    = 18
	iflaStats64     = 23
	iflaInfoKind    = 1
	iflaInfoData    = 2
	vethInfoPeer    = 1
	iflaBrportMode  = 4
	nlaFNested      = 0x8000
	afBridge        = 7
	nlmFRequest     = 0x1
	nlmFAck         = 0x4
	nlmFExcl        = 0x200
	nlmFCreate      = 0x400
	linkStats64Size = 24 * 8
)

// nlAlign rounds n up to a multiple of 4, the alignment of netlink.
func nlAlign(n int) int { return (n + 3) &^ 3 }

// nlAttr returns one netlink attribute.
func nlAttr(typ uint16, data []byte) []byte {
	b := binary.NativeEndian.AppendUint16(nil, uint16(4+len(data)))
	b = binary.NativeEndian.AppendUint16(b, typ)
	b = append(b, data...)
	return append(b, make([]byte, nlAlign(len(b))-len(b))...)
}

func nlString(typ uint16, s string) []byte { return nlAttr(typ, append([]byte(s), 0)) }

// ifInfoMsg returns a struct ifinfomsg.
func ifInfoMsg(family uint8, index int) []byte {
	b := []byte{family, 0}
	b = binary.NativeEndian.AppendUint16(b, 0)
	b = binary.NativeEndian.AppendUint32(b, uint32(index))
	b = binary.NativeEndian.AppendUint32(b, 0)
	return binary.NativeEndian.AppendUint32(b, 0)
}

// nlRequest sends one NETLINK_ROUTE request and returns the payloads of the
// answers and the error from the acknowledgment.
func nlRequest(typ, flags uint16, body []byte) ([][]byte, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)

	msg := binary.NativeEndian.AppendUint32(nil, uint32(16+len(body)))
	msg = binary.NativeEndian.AppendUint16(msg, typ)
	msg = binary.NativeEndian.AppendUint16(msg, flags|nlmFRequest|nlmFAck)
	msg = binary.NativeEndian.AppendUint32(msg, 1)
	msg = binary.NativeEndian.AppendUint32(msg, 0)
	msg = append(msg, body...)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, err
	}

	var answers [][]byte
	buf := make([]byte, 1<<16)
	for {
		n, err := syscall.Read(fd, buf)
		if err != nil {
			return nil, err
		}
		for rest := buf[:n]; len(rest) >= 16; {
			length := int(binary.NativeEndian.Uint32(rest))
			if length < 16 || length > len(rest) {
				return nil, fmt.Errorf("netlink message of %d bytes in %d", length, len(rest))
			}
			payload := rest[16:length]
			if binary.NativeEndian.Uint16(rest[4:]) == nlmsgError {
				if code := int32(binary.NativeEndian.Uint32(payload)); code != 0 {
					return answers, syscall.Errno(-code)
				}
				return answers, nil
			}
			answers = append(answers, slices.Clone(payload))
			rest = rest[min(nlAlign(length), len(rest)):]
		}
	}
}

// createLink creates a link of the given kind. data is the IFLA_INFO_DATA
// attribute or nil.
func createLink(name, kind string, data []byte) error {
	info := nlString(iflaInfoKind, kind)
	if data != nil {
		info = append(info, data...)
	}
	body := append(ifInfoMsg(syscall.AF_UNSPEC, 0), nlString(iflaIfname, name)...)
	body = append(body, nlAttr(iflaLinkinfo, info)...)
	_, err := nlRequest(rtmNewLink, nlmFCreate|nlmFExcl, body)
	return err
}

func deleteLink(name string) error {
	body := append(ifInfoMsg(syscall.AF_UNSPEC, 0), nlString(iflaIfname, name)...)
	_, err := nlRequest(rtmDelLink, 0, body)
	return err
}

func linkIndex(name string) (int, error) {
	i, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return i.Index, nil
}

// confDirNames lists the entries of a /proc/sys/net conf directory.
func confDirNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names, nil
}

// checkLinkConfDirectories checks that every link has a conf directory with
// route_localnet, as dockerd needs for the bridge, and that a deleted link
// loses it.
func checkLinkConfDirectories() error {
	const confDir = "/proc/sys/net/ipv4/conf"
	names, err := confDirNames(confDir)
	if err != nil {
		return err
	}
	for _, want := range []string{"all", "default", "lo"} {
		if !slices.Contains(names, want) {
			return fmt.Errorf("%s lists %v, want %s", confDir, names, want)
		}
	}
	if err := createLink("probebr0", "bridge", nil); err != nil {
		return fmt.Errorf("create bridge: %w", err)
	}
	defer deleteLink("probebr0")
	if names, err = confDirNames(confDir); err != nil {
		return err
	}
	if !slices.Contains(names, "probebr0") {
		return fmt.Errorf("%s lists %v, want the new link probebr0", confDir, names)
	}
	path := confDir + "/probebr0/route_localnet"
	for _, v := range []string{"1\n", "0\n"} {
		if err := os.WriteFile(path, []byte(v), 0o644); err != nil {
			return fmt.Errorf("write %q to %s: %w", v, path, err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != v {
			return fmt.Errorf("read %s after writing %q = %q, %v", path, v, got, err)
		}
	}
	if err := deleteLink("probebr0"); err != nil {
		return fmt.Errorf("delete bridge: %w", err)
	}
	if _, err := os.Stat(confDir + "/probebr0"); !errors.Is(err, syscall.ENOENT) {
		return fmt.Errorf("stat of the conf directory of a deleted link = %v, want ENOENT", err)
	}
	return nil
}

// checkBridgePortHairpin sets the hairpin mode of a veth end on a bridge, as
// dockerd does. Linux refuses the mode on a link that no bridge holds.
func checkBridgePortHairpin() error {
	veth := nlAttr(iflaInfoData, nlAttr(vethInfoPeer, append(ifInfoMsg(syscall.AF_UNSPEC, 0), nlString(iflaIfname, "probepv1")...)))
	if err := createLink("probepv0", "veth", veth); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}
	defer deleteLink("probepv0")
	if err := createLink("probebr1", "bridge", nil); err != nil {
		return fmt.Errorf("create bridge: %w", err)
	}
	defer deleteLink("probebr1")
	port, err := linkIndex("probepv0")
	if err != nil {
		return err
	}
	br, err := linkIndex("probebr1")
	if err != nil {
		return err
	}
	if _, err := nlRequest(rtmSetLink, 0, append(ifInfoMsg(syscall.AF_UNSPEC, port), nlAttr(iflaMaster, binary.NativeEndian.AppendUint32(nil, uint32(br)))...)); err != nil {
		return fmt.Errorf("enslave veth: %w", err)
	}

	setHairpin := func(index int, mode byte) error {
		body := append(ifInfoMsg(afBridge, index), nlAttr(iflaProtinfo|nlaFNested, nlAttr(iflaBrportMode, []byte{mode}))...)
		_, err := nlRequest(rtmSetLink, 0, body)
		return err
	}
	if err := setHairpin(port, 1); err != nil {
		return fmt.Errorf("hairpin on a bridge port: %w", err)
	}
	if err := setHairpin(port, 0); err != nil {
		return fmt.Errorf("hairpin off on a bridge port: %w", err)
	}
	if err := setHairpin(port, 2); !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("hairpin mode 2 = %v, want EINVAL", err)
	}
	peer, err := linkIndex("probepv1")
	if err != nil {
		return err
	}
	if err := setHairpin(peer, 1); !errors.Is(err, syscall.EOPNOTSUPP) {
		return fmt.Errorf("hairpin on a link without a bridge = %v, want EOPNOTSUPP", err)
	}
	return nil
}

// devCounters returns the receive and transmit byte counters of a link from
// /proc/net/dev.
func devCounters(name string) (rx, tx uint64, err error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		label, counters, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(label) != name {
			continue
		}
		f := strings.Fields(counters)
		if len(f) < 9 {
			break
		}
		if _, err := fmt.Sscan(f[0], &rx); err != nil {
			return 0, 0, err
		}
		if _, err := fmt.Sscan(f[8], &tx); err != nil {
			return 0, 0, err
		}
		return rx, tx, nil
	}
	return 0, 0, fmt.Errorf("no %s line in /proc/net/dev", name)
}

// checkLinkStats64 reads the counters of the loopback link through netlink, as
// docker stats does for the links of a container, and compares them with
// /proc/net/dev.
func checkLinkStats64() error {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err := conn.WriteTo([]byte("counters"), conn.LocalAddr()); err != nil {
		return err
	}
	lo, err := linkIndex("lo")
	if err != nil {
		return err
	}
	answers, err := nlRequest(rtmGetLink, 0, ifInfoMsg(syscall.AF_UNSPEC, lo))
	if err != nil {
		return err
	}
	if len(answers) != 1 || len(answers[0]) < 16 {
		return fmt.Errorf("RTM_GETLINK answered %d messages, want 1", len(answers))
	}
	var stats []byte
	for attrs := answers[0][16:]; len(attrs) >= 4; {
		length := int(binary.NativeEndian.Uint16(attrs))
		if length < 4 || length > len(attrs) {
			return fmt.Errorf("attribute of %d bytes in %d", length, len(attrs))
		}
		if binary.NativeEndian.Uint16(attrs[2:]) == iflaStats64 {
			stats = attrs[4:length]
		}
		attrs = attrs[min(nlAlign(length), len(attrs)):]
	}
	if len(stats) != linkStats64Size {
		return fmt.Errorf("IFLA_STATS64 has %d bytes, want %d", len(stats), linkStats64Size)
	}
	rxBytes := binary.NativeEndian.Uint64(stats[2*8:])
	txBytes := binary.NativeEndian.Uint64(stats[3*8:])
	wantRx, wantTx, err := devCounters("lo")
	if err != nil {
		return err
	}
	if rxBytes == 0 || txBytes == 0 || rxBytes != wantRx || txBytes != wantTx {
		return fmt.Errorf("lo counters rx=%d tx=%d, want the non-zero /proc/net/dev values rx=%d tx=%d", rxBytes, txBytes, wantRx, wantTx)
	}
	return nil
}

// checkIPTablesNames checks the files that iptables-legacy-save reads to find
// the tables.
func checkIPTablesNames() error {
	for _, file := range []string{"/proc/net/ip_tables_names", "/proc/net/ip6_tables_names"} {
		data, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		tables := strings.Fields(string(data))
		for _, want := range []string{"filter", "nat"} {
			if !slices.Contains(tables, want) {
				return fmt.Errorf("%s lists %v, want %s", file, tables, want)
			}
		}
	}
	return nil
}

// checkBridgeNetfilterSysctl checks the file that dockerd stats before it runs
// without the userland proxy.
func checkBridgeNetfilterSysctl() error {
	const path = "/proc/sys/net/bridge/bridge-nf-call-iptables"
	got, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(got) != "1\n" {
		return fmt.Errorf("%s = %q, want 1", path, got)
	}
	return nil
}
