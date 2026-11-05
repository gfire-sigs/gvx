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

package tuning

import "time"

const (
	kib = int64(1) << 10
	mib = int64(1) << 20
	gib = int64(1) << 30
	tib = int64(1) << 40
)

// This block is the one table of tunables. Add a tunable here and nowhere
// else: the SDK, the rungv flags, "rungv tune list", and the table in
// docs/cli.md follow. Run "go test ./pkg/gvx/tuning -run TestDocsMatchRegistry
// -update" after a change. Do not add a limit that Linux controls through a
// sysctl file, a module parameter, or a netlink request. The guest sets
// those itself.
var (
	// NATMTU is the MTU of eth0 in the network mode "nat". The guest can
	// change it with "ip link set dev eth0 mtu N".
	NATMTU = defineInt("net.nat.mtu", 1500, 68, 65535, "bytes",
		"MTU of eth0 in the nat network mode at the start of the guest.")
	// NATUDPSessions is the number of NAT UDP sessions that live at once.
	NATUDPSessions = defineInt("net.nat.udp_sessions", 512, 1, 1<<20, "sessions",
		"Number of guest UDP flows that the NAT relays at once; a new flow ends the oldest one.")
	// UDPIdleTimeout ends a UDP session without traffic.
	UDPIdleTimeout = defineDuration("net.udp.idle_timeout", 30*time.Second, 10*time.Millisecond, 24*time.Hour,
		"Time without a datagram in either direction after which the NAT or a published UDP port ends a session.")
	// NATDialTimeout bounds a host connection that the NAT opens.
	NATDialTimeout = defineDuration("net.nat.dial_timeout", 10*time.Second, 100*time.Millisecond, 10*time.Minute,
		"Time that the NAT waits for a host TCP connection before it refuses the guest connection.")
	// NATSynBacklog is the number of guest TCP connections that wait for a host dial.
	NATSynBacklog = defineInt("net.nat.syn_backlog", 1024, 1, 1<<20, "connections",
		"Number of guest TCP connection requests that the NAT holds while it dials the host.")
	// DNSTimeout bounds a request of the guest to the DNS relay.
	DNSTimeout = defineDuration("net.dns.timeout", 4*time.Second, 100*time.Millisecond, time.Minute,
		"Time that the DNS relay at 10.0.2.3 waits for a guest query, a host lookup, and a reply.")
	// DNSUpstreamTimeout bounds one exchange with one host DNS server.
	DNSUpstreamTimeout = defineDuration("net.dns.upstream_timeout", 2*time.Second, 100*time.Millisecond, time.Minute,
		"Time that one exchange of the DNS relay with one host DNS server may take.")
	// ForwardUDPSessions is the number of client sessions of one published UDP port.
	ForwardUDPSessions = defineInt("net.forward.udp_sessions", 1024, 1, 1<<20, "sessions",
		"Number of host client sessions that one published UDP port relays at once.")
	// ForwardGuestDialWindow bounds the wait of a published TCP port for the guest listener.
	ForwardGuestDialWindow = defineDuration("net.forward.guest_dial_window", 3*time.Second, 10*time.Millisecond, 10*time.Minute,
		"Time that a published TCP port waits for the guest to listen before it closes the host client.")
	// ForwardGuestDialInterval is the pause between two dials of the guest listener.
	ForwardGuestDialInterval = defineDuration("net.forward.guest_dial_interval", 15*time.Millisecond, time.Millisecond, 10*time.Second,
		"Pause between two attempts of a published TCP port to reach the guest listener.")
	// ForwardMaxPortRange is the largest port range of one publish specification.
	ForwardMaxPortRange = defineInt("net.forward.max_port_range", 1024, 1, 65535, "ports",
		"Largest number of ports in one range of a publish specification, such as 30000-32767.")
	// WGQueueLength is the length of the packet queue of eth0 in the network mode "wg".
	WGQueueLength = defineInt("net.wg.queue_length", 512, 1, 1<<20, "packets",
		"Number of packets that the eth0 queue holds in the wg network mode.")
	// WGResolveTimeout bounds the lookup of the peer endpoint.
	WGResolveTimeout = defineDuration("net.wg.resolve_timeout", 10*time.Second, 100*time.Millisecond, 10*time.Minute,
		"Time that the sandbox waits to resolve the host name of the WireGuard peer endpoint.")

	// MemoryGuardPollInterval is the poll interval of the memory limit of the sandbox.
	MemoryGuardPollInterval = defineDuration("memory.guard.poll_interval", 5*time.Millisecond, time.Millisecond, 10*time.Second,
		"Time between two readings of the guest memory use when the sandbox has a memory limit.")
	// MemoryGuardHostPollInterval is the poll interval when the limit is the host RAM.
	MemoryGuardHostPollInterval = defineDuration("memory.guard.host_poll_interval", 100*time.Millisecond, time.Millisecond, 10*time.Second,
		"Time between two readings of the guest memory use when the limit is the RAM of the host.")
	// MemoryCgroupPollInterval is the poll interval of a cgroup near its memory.max.
	MemoryCgroupPollInterval = defineDuration("memory.cgroup.poll_interval", 5*time.Millisecond, time.Millisecond, 10*time.Second,
		"Shortest time between two checks of memory.max while a cgroup uses half of its limit.")
	// MemoryCgroupIdlePollInterval is the poll interval of cgroups far from memory.max.
	MemoryCgroupIdlePollInterval = defineDuration("memory.cgroup.idle_poll_interval", 25*time.Millisecond, time.Millisecond, 10*time.Second,
		"Time between two checks of memory.max while every limited cgroup uses less than half of its limit.")
	// MemoryCgroupScanRatio limits the CPU share of the memory.max checks.
	MemoryCgroupScanRatio = defineInt("memory.cgroup.scan_ratio", 4, 1, 1000, "ratio",
		"The checks of memory.max use at most one over this number of a CPU.")

	// OCIMaxJSONBytes bounds each index, manifest, and config body.
	OCIMaxJSONBytes = defineSize("oci.max_json_bytes", 8*mib, 64*kib, gib,
		"Largest index, manifest, or config body that a pull accepts.")
	// OCIMaxBlobBytes bounds one compressed layer.
	OCIMaxBlobBytes = defineSize("oci.max_blob_bytes", 32*gib, mib, tib,
		"Largest compressed layer that a pull accepts.")
	// OCIMaxLayerBytes bounds the decompressed tar stream of one layer.
	OCIMaxLayerBytes = defineSize("oci.max_layer_bytes", 64*gib, mib, tib,
		"Largest decompressed tar stream of one layer.")
	// OCIMaxImageBytes bounds the decompressed layers of one image.
	OCIMaxImageBytes = defineSize("oci.max_image_bytes", 128*gib, mib, tib,
		"Largest sum of the decompressed layers of one image.")
	// OCIMaxEntryBytes bounds one regular file in a layer.
	OCIMaxEntryBytes = defineSize("oci.max_entry_bytes", 32*gib, kib, tib,
		"Largest regular file in a layer.")
	// OCIMaxEntries bounds the tar entries of one layer.
	OCIMaxEntries = defineInt("oci.max_entries", 2_000_000, 1, 1<<40, "entries",
		"Largest number of tar entries in one layer.")
	// OCIMaxArchiveEntries bounds the members of an image archive.
	OCIMaxArchiveEntries = defineInt("oci.max_archive_entries", 1_000_000, 1, 1<<40, "entries",
		"Largest number of members in an image archive.")
	// OCIMaxZstdWindowBytes bounds the zstd window, and so the decoder memory.
	OCIMaxZstdWindowBytes = defineSize("oci.max_zstd_window_bytes", 128*mib, mib, 16*gib,
		"Largest zstd window that a layer may ask for; the decoder allocates this much memory.")
	// OCIRegistryIdleTimeout ends a registry request without data.
	OCIRegistryIdleTimeout = defineDuration("oci.registry_idle_timeout", time.Minute, time.Second, 24*time.Hour,
		"Time that a registry request may go without data before the pull fails.")
)
