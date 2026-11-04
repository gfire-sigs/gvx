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
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// linkCounters are the files of /sys/class/net/<link>/statistics that
// cAdvisor reads.
var linkCounters = []string{
	"rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
	"rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
}

// linkCounter returns one counter of a link.
func linkCounter(link, name string) (uint64, error) {
	text, err := readValue("/sys/class/net/" + link + "/statistics/" + name)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(text, 10, 64)
}

// diskSectors returns the sectors read and written of the disk vda in
// /proc/diskstats.
func diskSectors() (read, written uint64, err error) {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return 0, 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 14 || f[2] != "vda" {
			continue
		}
		if read, err = strconv.ParseUint(f[5], 10, 64); err != nil {
			return 0, 0, err
		}
		written, err = strconv.ParseUint(f[9], 10, 64)
		return read, written, err
	}
	return 0, 0, fmt.Errorf("/proc/diskstats has no line for vda:\n%s", data)
}

// statsChecks checks the link and disk statistics. The probe reads a stream
// from the TCP server at addr to drive eth0, and it writes and reads a file to
// drive the disk.
func statsChecks(addr string) []check {
	var rxBefore, txBefore, rxPacketsBefore uint64
	var readBefore, writtenBefore uint64
	var received int64
	const fileSize = 4 << 20
	return []check{
		{"link-directories-list-the-links", func() error {
			entries, err := os.ReadDir("/sys/class/net")
			if err != nil {
				return err
			}
			var names []string
			for _, e := range entries {
				names = append(names, e.Name())
			}
			if len(names) != 2 || names[0] != "eth0" || names[1] != "lo" {
				return fmt.Errorf("/sys/class/net lists %v, want [eth0 lo]", names)
			}
			return nil
		}},
		{"link-attributes", func() error {
			iface, err := net.InterfaceByName("eth0")
			if err != nil {
				return err
			}
			// Linux prints six zero bytes for a link that has no hardware address.
			address := "00:00:00:00:00:00"
			if len(iface.HardwareAddr) > 0 {
				address = iface.HardwareAddr.String()
			}
			for name, want := range map[string]string{
				"address":   address,
				"mtu":       strconv.Itoa(iface.MTU),
				"ifindex":   strconv.Itoa(iface.Index),
				"operstate": "up",
			} {
				if err := expectValue("/sys/class/net/eth0/"+name, want); err != nil {
					return err
				}
			}
			return expectValue("/sys/class/net/lo/operstate", "unknown")
		}},
		{"link-statistics-files-exist", func() error {
			for _, link := range []string{"lo", "eth0"} {
				for _, name := range linkCounters {
					if _, err := linkCounter(link, name); err != nil {
						return fmt.Errorf("%s %s: %w", link, name, err)
					}
				}
			}
			return nil
		}},
		{"counters-before", func() error {
			var err error
			if rxBefore, err = linkCounter("eth0", "rx_bytes"); err != nil {
				return err
			}
			if txBefore, err = linkCounter("eth0", "tx_bytes"); err != nil {
				return err
			}
			if rxPacketsBefore, err = linkCounter("eth0", "rx_packets"); err != nil {
				return err
			}
			if readBefore, writtenBefore, err = diskSectors(); err != nil {
				return err
			}
			return nil
		}},
		{"network-traffic", func() error {
			conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
			if err != nil {
				return err
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Write([]byte("go\n")); err != nil {
				return err
			}
			received, err = io.Copy(io.Discard, conn)
			if err != nil {
				return err
			}
			if received == 0 {
				return fmt.Errorf("the server at %s sent no data", addr)
			}
			return nil
		}},
		{"disk-io", func() error {
			path := "/tmp/statsfile"
			if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, fileSize), 0o644); err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if len(data) != fileSize {
				return fmt.Errorf("read %d bytes, want %d", len(data), fileSize)
			}
			return os.Remove(path)
		}},
		{"eth0-counters-grow", func() error {
			rx, err := linkCounter("eth0", "rx_bytes")
			if err != nil {
				return err
			}
			tx, err := linkCounter("eth0", "tx_bytes")
			if err != nil {
				return err
			}
			rxPackets, err := linkCounter("eth0", "rx_packets")
			if err != nil {
				return err
			}
			if rx < rxBefore+uint64(received) {
				return fmt.Errorf("rx_bytes grew from %d to %d, want at least %d more", rxBefore, rx, received)
			}
			if tx <= txBefore || rxPackets <= rxPacketsBefore {
				return fmt.Errorf("tx_bytes %d to %d, rx_packets %d to %d, want growth", txBefore, tx, rxPacketsBefore, rxPackets)
			}
			return nil
		}},
		{"sysfs-agrees-with-proc-net-dev", func() error {
			sys, err := linkCounter("eth0", "rx_bytes")
			if err != nil {
				return err
			}
			rx, _, err := devCounters("eth0")
			if err != nil {
				return err
			}
			// The two reads come one after the other, and the guest has no other traffic.
			if rx < sys {
				return fmt.Errorf("/proc/net/dev rx %d is below /sys/class/net rx_bytes %d", rx, sys)
			}
			return nil
		}},
		{"diskstats-counters-grow", func() error {
			read, written, err := diskSectors()
			if err != nil {
				return err
			}
			if want := writtenBefore + fileSize/512; written < want {
				return fmt.Errorf("sectors written grew from %d to %d, want at least %d", writtenBefore, written, want)
			}
			if want := readBefore + fileSize/512; read < want {
				return fmt.Errorf("sectors read grew from %d to %d, want at least %d", readBefore, read, want)
			}
			return nil
		}},
	}
}

// devCounters returns the receive and transmit byte counters of a link from
// /proc/net/dev.
func devCounters(name string) (rx, tx uint64, err error) {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		label, counters, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(label) != name {
			continue
		}
		f := strings.Fields(counters)
		if len(f) < 9 {
			break
		}
		if rx, err = strconv.ParseUint(f[0], 10, 64); err != nil {
			return 0, 0, err
		}
		tx, err = strconv.ParseUint(f[8], 10, 64)
		return rx, tx, err
	}
	return 0, 0, fmt.Errorf("no %s line in /proc/net/dev", name)
}
