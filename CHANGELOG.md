# Changelog

This file records the observable changes of each `gvx` release. The release workflow `.github/workflows/release.yml` publishes the section of a tag as its release notes. A tag with a hyphen, such as `v0.1.0-rc.1`, publishes a pre-release.

## [v0.8.10002026110200] - 2026-11-05

This release lets an unmodified `k3s` node run in a sandbox (GVXIP-005). It adds the Linux kernel interfaces that the `kubelet`, `containerd`, `runc`, and `k3s` read and write (phase P1). It adds the service data path of `kube-proxy` in the iptables mode (phase P2), the `wireguard` and `vxlan` links between nodes (phase P3), and the enforcement of `cpu.max` (phase P4). It adds no flag and no SDK field. [`docs/kubernetes.md`](docs/kubernetes.md) shows how to start a single node and a cluster with two nodes.

### Features

- **`memory.stat` at the root cgroup**: `/sys/fs/cgroup/memory.stat` exists and reports all memory of the sandbox, as in Linux. The cAdvisor of the `kubelet` reads it for the memory of the node, so `kubectl top node` shows memory. The root still has no `memory.current` and no `memory.max`.
- **`cpu.stat` usage of a removed cgroup stays in its parent**: `usage_usec` of a parent counts its live children and the children that it removed. It fell to 0 when a child was removed. Pod cgroups of the `kubelet` lost the CPU time of finished containers, so `kubectl top pod` showed 0.
- **`/dev/kmsg`**: the character device 1:11 opens for read and write. A non-blocking read returns `EAGAIN`, and a blocking read waits. `lseek` with offset 0 returns 0 for `SEEK_SET`, `SEEK_DATA`, and `SEEK_END`. A write goes to the Sentry log and returns its length. The `kubelet` no longer exits with `open /dev/kmsg: no such file or directory`. The Sentry has no kernel ring buffer, so a reader never gets a record.
- **Sysctls of the `kubelet` and the container runtime**: `vm/overcommit_memory` accepts 0, 1, and 2 and returns `EINVAL` for other values. `vm/panic_on_oom`, `kernel/panic`, `kernel/panic_on_oops`, `kernel/keys/root_maxkeys`, and `kernel/keys/root_maxbytes` store a value in the range of Linux. `net/netfilter/nf_conntrack_max`, `nf_conntrack_tcp_timeout_established`, `nf_conntrack_tcp_timeout_close_wait`, and `/sys/module/nf_conntrack/parameters/hashsize` store their values. The files change no behavior of the Sentry.
- **`ip_unprivileged_port_start`**: each network namespace has the sysctl. The root namespace of the sandbox is the namespace of the container. It starts at 0, as in a Docker container, and no bind changes there. A namespace that the guest creates starts at 1024, as on Linux. A `bind` of a TCP or UDP socket of IPv4 or IPv6 to a lower port fails with `EACCES` unless the caller has `CAP_NET_BIND_SERVICE`. `runc` no longer fails every pod sandbox with `open /proc/sys/net/ipv4/ip_unprivileged_port_start: no such file or directory`.
- **Safe sysctls of Kubernetes**: `net/ipv4/ip_local_port_range`, `tcp_syncookies`, `ping_group_range`, `ip_local_reserved_ports`, `tcp_keepalive_time`, `tcp_keepalive_intvl`, `tcp_keepalive_probes`, `tcp_fin_timeout`, and `kernel/shm_rmid_forced` are writable. The files take the range of Linux, so `ping_group_range` goes up to 4,294,967,294 and the keepalive and FIN-WAIT-2 times accept 0. The network values belong to the network namespace of the process, so a write in a pod namespace leaves the value of the node. The port range, the keepalive values of new sockets, the FIN-WAIT-2 time, and `tcp_syncookies=2` reach the network stack. The stack gets each time as at least one second and the probe count from 1 to 127. `ping_group_range` and `ip_local_reserved_ports` only store their values, and `tcp_syncookies=0` still sends cookies when the accept queue is full.
- **Capacity of the node**: with `-m`, `MemTotal` in `/proc/meminfo` and `totalram` of `sysinfo(2)` equal the memory limit when it is below the host RAM. The value belongs to each sandbox, so several sandboxes in one process, such as in the SDK, each see their own limit. A tmpfs mount without a size and `size=N%` still follow the host RAM. With `--cpus`, the online CPUs, `sched_getaffinity`, `/sys/devices/system/cpu/online`, and `nproc` already showed the whole CPUs of the quota. Without the options nothing changes.
- **Generic netlink**: `socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC)` works. The controller family `nlctrl` answers `CTRL_CMD_GETFAMILY` by name, by ID, and as a dump. It sends the attributes that `libnl`, `libmnl`, and `github.com/mdlayher/genetlink` read. An unknown family returns `ENOENT`, and an unknown command returns `EOPNOTSUPP`. A dump is at most 192 KiB. A larger dump fails with `ENOBUFS` and never ends with a partial list.
- **`wireguard` link** (GVXIP-005, phase P3): `ip link add wg0 type wireguard`, `wg set`, `wg show`, and `wg-quick` work. The link has the MTU 1420. The family `wireguard` of `include/uapi/linux/wireguard.h` sets and reads the private key, the listen port (0 picks a free port), the mark, and the peers. A peer has a key, a preshared key, an endpoint, a keepalive, and allowed IP addresses. A read also returns the last handshake time and the byte counters.
  - Both commands need `CAP_NET_ADMIN`, and the answer holds the private key and the preshared keys, as on Linux. A request that sets the listen port or the mark needs `CAP_NET_ADMIN` in the user namespace of the namespace that created the link.
  - A set request applies the mark, the port, the removal of every peer, the private key, and the peers in the order of Linux. A listen port that another socket uses fails with `EADDRINUSE`, and the device keeps its port and its peers. A peer protocol version other than 1 fails with `EPFNOSUPPORT`.
  - A sandbox has at most 256 `wireguard` links, and a device has at most 4,096 peers. Both limits fail with `ENOMEM`.
  - The device is `wireguard-go`. It sends and receives UDP through the network stack of the namespace where the link was created. The encrypted packets leave through the routes of the guest. A published UDP port (`-p 51820:51820/udp`) or a keepalive admits the peers.
  - `ip link del` and the end of the namespace close the device. A netstack link has no down state, so the device owns its UDP port at creation. The mark is stored and reported, but it marks no socket.
- **`vxlan` link** (GVXIP-005, phase P3): `ip link add vxlan1 type vxlan id 42 dstport 4789 local 10.0.0.1 dev eth0 nolearning` works, and so does the call of `github.com/vishvananda/netlink` that `flannel` makes. The link is an Ethernet device. Its MTU is the MTU of the underlay link minus 50 (70 for IPv6). That is 1450 on `eth0`. The MTU stays between 68 and 65,485. `ip -d link show` and `RTM_GETLINK` report the kind and the attributes in `IFLA_INFO_DATA`, so `flannel` can compare its configuration with the link.
  - A request reads the VNI, the destination port (8472 when absent), `local` and `group` (IPv4 or IPv6), and the underlay link. It also reads learning (on when absent), TTL, TOS, DF, ageing, limit, the source port range, GBP, and the UDP checksum flags. The link reports each of them.
  - A VNI above 16,777,215 fails with `ERANGE`. A second link with the same VNI, address family, and port fails with `EEXIST`. Links with the same family and port and different VNIs share one UDP endpoint on the wildcard address.
  - A multicast group, `external` (flow-based), and GPE fail with `EOPNOTSUPP`. So does a request that changes an existing link with `IFLA_INFO_DATA`, such as `ip link set vxlan1 type vxlan`. The same holds for a `wireguard` link.
  - The link sends each frame as a VXLAN datagram (RFC 7348) through the routes of the network stack that created it. The outer packets leave through `eth0` and its NAT, or through `wg0`. An outer route that leaves through a `vxlan` link drops the packet.
  - The link receives the datagrams on a UDP endpoint of that stack. It gives each frame to the link with the VNI of the datagram. The outer source port comes from a hash of the flow, inside the source port range, as in Linux. The UDP checksum of an IPv4 outer packet is off unless `udpcsum` is set.
  - A frame goes to the remotes of the FDB entry for its destination address, or to the all-zeros entry. With learning on, the link learns the source address of each received frame. A learned entry ends after the ageing time, and a frame that would move a static entry is dropped.
  - One FDB holds at most 65,536 entries, or the link limit when that is smaller. A new entry beyond the limit fails with `ENOSPC`. An entry has at most 1,024 remotes.
  - The link binds its port at creation, because a netstack link has no down state. The link stores and reports `ttl inherit`, `df inherit`, `label`, `udp6zerocsumrx`, `remcsumtx`, `remcsumrx`, `remcsum_nopartial`, `proxy`, `l2miss`, `l3miss`, and `rsc` without enforcing them. It does not send to a multicast group.
- **Neighbor and FDB netlink** (GVXIP-005, phase P3): `RTM_NEWNEIGH`, `RTM_DELNEIGH`, and `RTM_GETNEIGH` work for IPv4 and IPv6 and for the family `AF_BRIDGE`. `ip neigh replace 10.244.2.0 lladdr 02:42:ac:11:00:02 dev flannel.1 nud permanent` and `bridge fdb append 00:00:00:00:00:00 dst 10.0.0.2 dev vxlan1` work, and so do `NeighSet`, `NeighAppend`, `NeighDel`, and `NeighList` of `github.com/vishvananda/netlink`.
  - A permanent or noarp entry becomes a static neighbor of the stack. A dump lists the entries of every link, with the states of the neighbor cache as `NUD_*` values. A dynamic state in a request fails with `EOPNOTSUPP`, and so does a link without address resolution, such as `lo` and `wg0`. `NLM_F_EXCL`, `NLM_F_REPLACE`, and `NLM_F_CREATE` follow Linux.
  - A link has at most 65,536 static neighbors for each IP family. One more fails with `ENOBUFS`, and a change of an existing entry still works.
  - An FDB request needs a `vxlan` link and the state `NUD_PERMANENT` or `NUD_REACHABLE`. It reads `NDA_LLADDR`, `NDA_DST`, `NDA_PORT`, `NDA_VNI`, and `NDA_IFINDEX`. `NLM_F_APPEND` adds a remote to the all-zeros address and to a multicast address, and `NLM_F_REPLACE` changes the remote of a unicast address, as `vxlan_fdb_update` does.
  - A delete with a remote removes that remote, and the last remote removes the entry. A delete without a remote removes the entry. A dump lists one message for each remote.
  - A dump accepts both request forms, because `bridge fdb show` sends `struct ifinfomsg` and the Go library sends `struct ndmsg`. It honors the interface index and the master.
  - A route with `onlink` is accepted. The route dump does not report that flag.
- **Statistics**: `/sys/class/net/<link>` lists the links of the network namespace of the reader. Each link has `address`, `mtu`, `operstate`, `ifindex`, and the counters `statistics/{rx,tx}_{bytes,packets,errors,dropped}`. `/proc/diskstats` has one line for the disk `vda`. Its counters come from the read and write system calls of the processes of the sandbox, so they include sockets and pipes. A sandbox does not count the calls of another sandbox.
- **`iptables -m statistic`**: the match has two modes. `--mode random --probability P` picks flows at random, and `--mode nth --every N --packet K` picks every Nth flow. Both accept `!` inversion. The probability is a 31-bit fraction, as in `xt_statistic`. Each rule has its own `nth` counter, and `iptables-restore` resets it. `iptables-save` and `iptables -C` print and find the rule unchanged. `kube-proxy` uses the match to spread a service over its endpoints.
- **`iptables -m recent`**: the match records the source or destination address of a packet in a named list, and a later rule matches the addresses that the list saw recently. It takes `--set`, `--rcheck`, `--update`, `--remove`, `--seconds`, `--hitcount`, `--reap`, `--rttl`, and `--mask`. A list keeps 100 addresses, as on Linux. `kube-proxy` uses the match for the session affinity of a Service, so the session affinity tests of the Kubernetes conformance suite can pass.
- **Bridge netfilter**: with `/proc/sys/net/bridge/bridge-nf-call-iptables` at 1, an IPv4 frame that a bridge forwards between two ports passes the iptables hooks PREROUTING, FORWARD, and POSTROUTING. `bridge-nf-call-ip6tables` does the same for IPv6. A DNAT rule can move the destination to another host of the bridge, and the frame then leaves through the port of that host. A destination at the bridge itself or behind another route reaches the IP layer as the frame arrived, so the IP layer reuses the connection of the bridge. Conntrack undoes the NAT of each reply, and a SNAT rule changes the source address. With 0, the bridge forwards the frames as before. Each network namespace has its own switches.
- **`ctnetlink`**: `conntrack -L`, `conntrack -G`, and `conntrack -D` work, and so do `ConntrackTableList` and `ConntrackDeleteFilters` of the Go library `github.com/vishvananda/netlink`. An entry has both tuples, the status, the timeout, the mark, the ID, the use count, and the TCP state. A delete expires the entry, so the next packet of the flow runs the NAT rules again. A dump has no size limit: the socket sends one chunk at a time, as Linux does, so `ConntrackDeleteFilters` of `kube-proxy` removes every matching flow on a busy node. The table keeps no counters, timestamps, labels, zones, or mark, and `conntrack -I` and `conntrack -U` fail with `EOPNOTSUPP`.

- **`cpu.max` of cgroup v2**: the tasks of a cgroup subtree use at most the quota in each period, on all CPUs together. `docker run --cpus 0.5` becomes `cpu.max` at `50000 100000`. A busy loop in that cgroup used 0.50 CPU over 5 seconds on every backend. `max` removes the limit, and a child obeys the limit of every ancestor.
  - A task that spent the quota stops at its next return to guest code. It runs again at the next period. System calls count toward the quota, as in Linux.
  - `cpu.stat` reports `nr_periods`, `nr_throttled`, and `throttled_usec`. The first two follow the period ends of Linux. `throttled_usec` is one wall-clock interval for the cgroup. Linux sums the time of each CPU.
  - A write follows the Linux limits. A period must be 1 ms to 1 s, and a quota must be 1 ms or more. Any other value fails with `EINVAL`. A new value releases a throttled task at once. A task that moves to another cgroup stops waiting for the old period end.
  - `usage_usec` is now the measured time that the tasks ran. A busy Go program read 1.1 to 1.3 CPU before. The ticker billed a whole tick to each sampled thread. It reads 1.01 to 1.03 now.
  - A sandbox without a finite `cpu.max` pays one atomic load for each return to guest code. `cpu.weight` stays unenforced. The burst fields of Linux stay unenforced too.
  - A stall of the Sentry can delay the charge of a task by many periods. The charge now counts for each period that it covers, and each period gives the quota again. Before, the whole charge counted against the current period. A task in a cgroup with enough quota then lost many periods to a debt that it never made. The test A14 on Windows `systrap` saw such a loop throttled for 8 periods.

### Bug Fixes

- **`EINTR` from a blocked socket call on Windows and macOS**: a signal ended a blocked `recvfrom`, `recvmsg`, `accept`, or `connect` with `EINTR`, also when the handler had `SA_RESTART`. Linux restarts the call. A signal that the Go runtime sends, such as `SIGURG` or `SIGCHLD`, is enough. `kubectl exec` then failed at random with `unable to start container process: reading from parent failed: fetch packet length from socket: interrupted system call`, because `runc` reads its sync socket with `recvfrom`.
  - `Error.ToError` returned `linuxerr.EINTR` on those hosts, and `linuxerr.ConvertIntr` does not match that value. It now returns `linuxerr.ErrInterrupted`. A handler without `SA_RESTART` still gives `EINTR`.
  - The error came with the fix for the host panic on `ENOTCONN`. It showed on `windows/arm64` in 6 of 40 `kubectl exec` runs. `darwin` had the same fault.
- **Busy loops that cannot stop on the Windows `systrap` engine**: `Interrupt` stops a running thread with the single-step flag. The step exception clears that flag. When the step landed in engine code, the engine continued the thread without the flag. The thread then ran on, and every later `Interrupt` returned without a stop.
  - A guest loop without system calls then ignored `SIGKILL`, and the sandbox did not exit. The engine now sets the flag again before it continues the thread.
  - The code is shared by `windows/amd64` and `windows/arm64`. The hang showed on `windows/amd64`.
- **A write to a private mapping of a file on a volume or bind mount stopped the Sentry on Windows**: the first write to a private file mapping on a `hostfs` or `ext4lite` file ended with `panic: invalid allocation length: 0x0`. The Windows `systrap` engine keeps each 64 KiB chunk of such a file in its own range of the memory file, so the file returns one translation for each chunk. A translation can end before the faulting page. The Sentry then broke copy-on-write for that translation and asked for a copy of 0 bytes.
  - A `k3s` server on `windows/arm64` ended with this panic. The Sentry now breaks copy-on-write only for the translation that holds the faulting page. Other platforms keep a chunk in one range and never showed the panic.
- **`oom_kill` in the cgroup of the victim**: an OOM kill counted only in `memory.events` of the cgroup that passed its limit and of its ancestors. The `kubelet` gives a pod cgroup and its container cgroup the same limit, and the pod cgroup also holds the pause container, so the pod cgroup often passed the limit first. The container cgroup then showed no kill. containerd watches that cgroup, so the `kubelet` reported the reason `Error` or `Completed` instead of `OOMKilled`. A kill now counts in the cgroup of the victim and its ancestors, as in Linux. The OOM event stays in the cgroup that passed its limit.
- **`memory.oom.group` of a child cgroup**: the enforcer obeyed `memory.oom.group` only in the cgroup that passed its limit. The `kubelet` sets it in each container cgroup, below the pod cgroup. When the pod cgroup passed its limit, only the largest process of the container ended. Now the highest cgroup with `memory.oom.group` between the victim and the limited cgroup loses all its processes, as `mem_cgroup_get_oom_group` selects it. The enforcer also checks a child before its parent and ends a process once in one pass, so nested limits count one kill.
- **Pod traffic of a Kubernetes node**: a ping or a connection from a pod to the bridge gateway, to another pod, or to a ClusterIP service failed at random on a node with several pods. A bridge flooded each frame for its own address to every port. It also sent each IP packet of its own stack to every port. A veth end passed a frame with another destination address to its IP layer, so each pod with IP forwarding forwarded the frames of its neighbors. The copies looped between the pods, and one ping got hundreds of replies. The bridge now keeps a frame for its own address on the bridge. It sends an IP packet only to the port of the destination address. It learns an address again when the address moves to another port. A veth end drops a unicast frame for another address before the IP layer, as `ip_rcv` does for `PACKET_OTHERHOST`. Packet sockets still see the frame.
- **A SYN reopens a closed TCP connection in the connection table**: the table kept the entry of a closed connection for 120 seconds. A new connection with the same addresses and ports then kept the NAT target of the old connection, and the NAT rules did not run again. A SYN on a connection in TIME_WAIT or CLOSE now removes the old entry and starts a new one, as `nf_conntrack_proto_tcp` does. A client that reuses its source port now reaches the current endpoint of a Kubernetes service.
- **`connect` to a service without endpoints**: `kube-proxy` rejects such a connection with `-j REJECT --reject-with icmp-port-unreachable` in the OUTPUT chain. The ICMP error came back over the loopback link while `connect` still held the lock of the endpoint, and `connect` never returned. A read of `/proc/net/tcp` then waited for that lock without end. `connect` now fails with `ECONNREFUSED` at once. A `k3s` server hung in this way when a process of the node connected to a ClusterIP address whose pod was not ready.
- **`fsync` and `fdatasync` on an `ext4lite` volume**: a sync of a file could wait for a write to the same file without end, and the write waited for the sync. The sync held the write lock of the file while the flush of the volume waited for every running write to finish. A write that had entered the volume but not yet taken the lock then never finished, and every later write to the volume waited. The sync now takes the lock only for the write-back of mapped pages. A `k3s` server on a volume hung in this way on `windows/amd64`.
- **`SIGKILL` of a guest that reads its standard input**: a guest process that waited in a `read` of a pipe on its standard input ignored `SIGKILL`, so the cancel of `Run` did not end the sandbox. The host read ran in the task, and a host read cannot be interrupted. A helper goroutine now reads the host stream, and the guest `read` waits until data arrives or a signal ends it, as on Linux. `poll` and `epoll` report the input of such a stream.
- **`wireguard` devices after the end of their network stack**: a device kept its goroutines and its UDP socket after its sandbox or network namespace ended, and it logged handshake errors for the rest of the host process. The end of a network stack now removes the links that the guest created.
- **Failure reason of the control shim after its deadline**: when the lifecycle deadline of `containerd-shim-gvx-v2` passed, a failed action exited with status 1 and wrote nothing to standard error. The shim now writes the reason within one second.
- **A client port that `bind` took on the wildcard address**: after `bind(0.0.0.0:P)` and `connect`, the port stayed in use for the life of the sandbox, even after the connection closed. A second `bind` to `P` failed with `EADDRINUSE`. The endpoint now releases the port under the address that `bind` used. A client such as `curl --local-port` or `nc -p` can reuse its source port, as on Linux.

### Behavior Changes

- **MTU of `eth0` with `-net=nat`**: `eth0` has the MTU 1500, as on a Linux node or in a Docker container. It had 65,536. The loopback device keeps 65,536. Software that derives tunnel MTUs from `eth0` now gets the Linux values: `flannel` uses 1450 for `vxlan` and 1420 for WireGuard.
  - With 65,536, tunnel datagrams exceeded the 9,216 bytes that macOS sends through a UDP socket, and the NAT relay lost them.
  - A guest TCP transfer through the NAT link is slower with the smaller MTU. The table lists the measured rates in MiB/s, as download and upload.

    | Backend | MTU 65,536 | MTU 9,000 | MTU 1,500 |
    | :--- | :--- | :--- | :--- |
    | `hvf` | 1,307 / 2,086 | 844 / 1,339 | 341 / 355 |
    | Linux `systrap` (`ubuntu-24.04`) | 653 / 2,258 | 378 / 551 | 181 / 190 |
    | Windows `whpx` | 363 / 1,213 | 147 / 463 | 175 / 224 |
    | Windows `systrap` | 686 / 1,300 | 633 / 759 | 217 / 232 |
- **UDP sessions of the NAT relay**: the relay keeps at most 512 UDP sessions. A new session beyond the limit ends the session with the oldest datagram. Before, the count had no limit, and each session held two 64 KiB buffers from its start. The buffers now come from a pool.
- **Bridged IP frames pass the iptables hooks**: `bridge-nf-call-iptables` and `bridge-nf-call-ip6tables` started at 1 and stored their values. They now switch the hooks, so the rules of the guest apply to the traffic between two ports of a bridge. Before, `docker run --icc=false` did not separate two containers of one bridge. It now does, because the `FORWARD` rule of `dockerd` applies. The switches only take effect after the guest writes an iptables table.
- **`NETLINK_NETFILTER` sockets open without `nftables`**: `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` failed with `EPROTONOSUPPORT`. It now succeeds. A message of a subsystem that the guest lacks, such as `nfacct` or `nftables`, fails with `EINVAL`, and a batch of such a subsystem fails with `EOPNOTSUPP`, as on Linux. `conntrack` no longer prints `mnl_socket_open: Protocol not supported`.
- **Forwarding sysctls belong to the network namespace**: `/proc/sys/net/ipv4/ip_forward`, `conf/all/forwarding`, `conf/default/forwarding`, and the IPv6 `forwarding` files show the values of the network namespace of the reader. Before, `ip_forward` showed the root namespace to every reader. For each IP family, `ip_forward` and `conf/all/forwarding` are one switch, and a write to it also sets `conf/default/forwarding` and every link that exists. A write to `conf/default/forwarding` changes only the links that the guest creates later. A new network namespace gets the IPv4 switches of the root namespace, and its IPv6 switches start at 0. `/proc/sys/net/ipv4/ip_local_port_range` also follows the namespace of the reader.
- **A guest network namespace enforces `ip_unprivileged_port_start`**: a namespace that the guest creates, such as one that `unshare -n` makes, now needs `CAP_NET_BIND_SERVICE` to bind a TCP or UDP port below 1024. Before, it needed nothing. The root namespace of the sandbox keeps 0.
- **`tcp_keepalive_*` and `ip_local_reserved_ports` are writable**: the files were read-only stubs that showed 0 for `tcp_keepalive_intvl` and `tcp_keepalive_probes`. They now show the defaults of Linux (75 and 9).

### Known limitations

- Sometimes new connections that a pod starts time out for 30 to 120 seconds, while established connections and connections from the host work. One or two `[sig-network] Services` conformance tests then fail at random. The cause is under investigation. Section 4.3 of [`docs/kubernetes.md`](docs/kubernetes.md) lists the other limits of a node.

## [v0.7.10002026110200] - 2026-11-04

This release adds Docker and `ext4lite` features and fixes HotSpot 21, `membarrier`, and `brk` on the Windows `systrap` engine. It also changes the format of `.gvx_meta`, so an older release cannot open a workspace that this release wrote. Read the upgrade note under Behavior Changes before the upgrade.

### Features

- **`dockerd --userland-proxy=false`**: `docker:dind` now starts with the option. The guest has `/proc/sys/net/ipv4/conf/<link>/route_localnet`, which changes the martian filter of that link only, and `/proc/sys/net/ipv6/conf/<link>/accept_ra` for each link, `/proc/sys/net/bridge/bridge-nf-call-*`, and the hairpin mode of a bridge port. A connection to `127.0.0.1` and a published port reaches the container in the guest, and the host port still works. The bridge does not pass frames through `iptables`, so `--icc=false` does not separate containers of one bridge.
- **`docker stats`**: the command shows the memory, the CPU time, and the network counters of a container. The guest now reports `IFLA_STATS64` for each link, and `memory.stat` exists in each memory cgroup. A container that wrote 64 MiB shows 64 MiB on `hvf` and 101 MiB on Linux systrap, because `memory.current` counts page cache and mapped pages. `BLOCK I/O` stays at `0B`.
- **`iptables-legacy-save`**: the command prints the rules of the tables `filter`, `nat`, `mangle`, and `raw`. The guest has `/proc/net/ip_tables_names` and `/proc/net/ip6_tables_names`.
- **`memory.max` of nested cgroups**: `docker run -m 32m` ends the process with the highest score when the container passes the limit. The exit code is 137, `docker inspect` shows `OOMKilled: true`, and `memory.events` counts `oom` and `oom_kill`. The Sentry compares anonymous memory plus tmpfs data with the limit, never ends the init process or a process with `oom_score_adj` of -1000, and checks every 5 ms or more while a container uses half of its limit, otherwise every 25 ms. `memory.oom.group` ends every process. A container can pass the limit by what it allocates between two checks. The enforcer stays off under the Windows `systrap` engine. `memory.high`, `cpu.max`, and `cpu.weight` stay unenforced. See `docs/docker-engine.md`, section 6.4.
- **`O_TMPFILE` on `ext4lite` volumes**: `open` with `O_TMPFILE` creates an unnamed file instead of failing with `EOPNOTSUPP`. The volume frees the file at the last close, and a crash cannot leak it, because the orphan list of ext4 holds the inode. `O_TMPFILE` without `O_EXCL` files accept `linkat` with `AT_EMPTY_PATH` and through `/proc/self/fd`. The link moves the inode out of the orphan list in one transaction. A file with no link from `O_TMPFILE|O_EXCL` or from `unlink` still refuses `linkat` with `ENOENT`.
- **`fallocate` modes on `ext4lite` volumes**: `FALLOC_FL_ZERO_RANGE` (with and without `FALLOC_FL_KEEP_SIZE`), `FALLOC_FL_COLLAPSE_RANGE`, and `FALLOC_FL_INSERT_RANGE` work. The checks and the error codes follow Linux: block alignment gives `EINVAL`, a collapse that reaches the end of the file gives `EINVAL`, and a size above the limit gives `EFBIG`. Each call is one journal transaction, and `e2fsck -fn` accepts the image after it.
- **`RWF_*` flags on `ext4lite` volumes**: `preadv2` and `pwritev2` accept `RWF_NOWAIT`, `RWF_APPEND`, and `RWF_NOAPPEND`, as well as `RWF_HIPRI`, `RWF_DSYNC`, and `RWF_SYNC` for both calls. `RWF_APPEND` with `RWF_NOAPPEND` gives `EINVAL`, and an unknown flag gives `EOPNOTSUPP`. `RWF_NOWAIT` never returns `EAGAIN`, because the volume has no page cache between a call and the engine.
- **Hole punching on Windows `hostfs`**: `fallocate` with `FALLOC_FL_PUNCH_HOLE` marks the file sparse and calls `FSCTL_SET_ZERO_DATA`, so NTFS frees the clusters of the range. Before, the call wrote zeros and freed nothing. A volume without sparse files, such as FAT or exFAT, and a file whose NTFS attribute list is full keep the zero-fill. The guest `st_blocks` still shows the logical size on Windows.

### Bug Fixes

- **HotSpot 21 on the Windows `arm64` `systrap` engine**: `java` exited with `Could not allocate compressed class space: 1073741824 bytes`. HotSpot on `arm64` asks for the class space at 38 fixed addresses between 4 GiB and 1 TiB, and the guest had no address there. Guests now get all 38 addresses on `windows/arm64` and `windows/amd64`. A middle window from `0x7fff0000` to 66 GiB holds 9 of them, and a window of 2 GiB holds each of the other 29. The high window now starts at 4 TiB instead of 16 TiB. The memory manager supports several address holes, so the platform reports the ranges between the windows. The kernel places the initial stack and the PEB of every stub between 4 GiB and 1 TiB, and it refuses to move the PEB. About 12% of the new stubs therefore hold part of a window. The engine ends such a stub and starts another one, up to 12 times. A platform that drops a window writes a warning to the log. AddressSanitizer and Wine 64-bit still need `whpx`. `TestE2EGateJVM` runs Temurin 21 on every backend: C2, eight threads, the garbage collector, a parallel stream, and `membarrier`. Temurin 25 started on `windows/arm64` without the window. See `docs/systrap-windows.md`, sections 3.10 and 6.2.
- **`membarrier` on `hvf`, `whpx`, and Windows `systrap`**: the global and private expedited commands of `membarrier(2)` returned `EINVAL`, and `MEMBARRIER_CMD_QUERY` reported none of them. The commands now succeed, and the query reports them. A call returns after every guest thread that ran guest code at the call has left the guest or stopped once. Idle threads cost nothing. On Windows (`whpx` and `systrap`), the call also orders the Sentry threads with `FlushProcessWriteBuffers`. On macOS, the call orders guest code only and does not order a Sentry thread that copies data for a system call in progress. On `whpx`, a running guest task returns from `Switch` once for each call and the kernel runs it again. `hvf` and Windows `systrap` resume the guest without a return. Linux platforms keep the host `membarrier`.
- **`fsckLite` repair of an unlinked inode that a directory names**: a power loss between the write of a directory entry and the write of its inode could leave an entry that names an inode with link count zero. The repair kept the count, and the next lookup failed with `EUCLEAN`. The repair now gives the inode the rebuilt count. Only a mount that runs `fsckLite` makes this repair, which a volume without a journal needs after a crash.
- **Directory link count on Windows `hostfs`**: `stat` of a directory reported 2 links on NTFS for every directory. It now reports 2 plus the number of subdirectories, as Linux does. Tools such as `find` use that count.
- **Large `truncate` on Windows `hostfs`**: a growth above the free disk space failed with `ENOSPC`, and a size above the NTFS file limit failed with `EIO`. The growth now leaves a hole, as on Linux, and the size above the limit fails with `EFBIG`.
- **brk heap on the Windows `systrap` engine** (`windows/amd64` and `windows/arm64`): `brk` stopped after 0 MiB to 111 MiB, at a random place in each process. The engine placed a trampoline island at a random address up to 120 MiB above the code, where the heap grows. The engine now looks below the code first. `TestE2EGateETExecBrkGrowth` moves the break of an `ET_EXEC` program by 1 GiB on every backend. An `arm64` Go program at `0x10000` has no address below its code and keeps the old limit; the Go runtime never calls `brk`.
- **Windows `systrap` engine errata** (`windows/amd64` and `windows/arm64`): three defects of the engine are fixed.
  - A guest that wrote code through one view of a memory file and ran it through another view kept running the old code. A write through a second view of a frame now drops the patched copies of that frame in every address space. A frame without a patched copy costs no extra fault.
  - On `windows/arm64`, a fast `svc` overwrote a live `x18` of the guest with a stale value, unless the guest set `x18` with `mov x18, xN`. The `svc` slot now saves `x18` first, so every `svc` keeps it. A guest whose stack pointer is invalid still gets its system call through the debug path. The patcher no longer rewrites `mov x18, xN`, which leaves 289 rewritten encodings instead of 320.
  - On `windows/arm64`, every `ic ivau` of a guest cost one debug stop. The engine now replaces the instruction with `nop`, and `CTR_EL0` reports `DIC` and `IDC` for the guest. Guests that obey these bits, such as V8, skip the instruction.
- **Windows `systrap` engine, writes into running code** (`windows/amd64` and `windows/arm64`): two kinds of write into code now have the Linux result.
  - A store into the page of the storing instruction, or into the frame that the thread executes through a second view, ended with SIGSEGV. The engine now completes the store with a single step, and the page runs the new bytes. Self-modifying code and data in a writable and executable code page work. On `windows/arm64`, a store exclusive (`stxr`, `stlxr`, `stxp`, `stlxp`) into its own page still ends with SIGSEGV.
  - A write of the Sentry into guest memory left a stale patched copy of the page: the copy-out of `read`, `pread`, and `recv` into a mapped page, `write` to a file that a guest maps, and `process_vm_writev`. The memory manager and the memory file now report each such write, and the engine drops the copies of the written frames. The report costs one atomic operation for a write into a frame without a copy, and the other platforms keep an empty hook.

### Behavior Changes

- **`fallocate` modes other than 0 reach `ext4lite` and `hostfs`**: the system call returned `ENOTSUP` for every mode other than 0 on every file system, so `FALLOC_FL_KEEP_SIZE` and `FALLOC_FL_PUNCH_HOLE` never reached a driver from a guest. The call now forwards the mode to a file description that serves modes, which `ext4lite` and `hostfs` do. Other file systems keep `ENOTSUP`. A mode other than 0 skips the `RLIMIT_FSIZE` check of the system call, because only a call that grows the file reaches the limit, and the drivers check it there. The change adds a seam to `pkg/sentry/syscalls/linux/sys_file.go`.
- **Host `inotify` cap of `hostfs`**: the cap of watched objects for one workspace was 8,192 on every host. It now follows the host. On Linux and macOS it is the soft `RLIMIT_NOFILE` minus the descriptors that the sandbox keeps, between 2,048 and 65,536. A limit of 1,048,576 gives 65,536, and the stock macOS limit of 10,240 gives 5,120. On Windows it is 32,768, and the buffer of each watch shrinks from 64 KiB to 4 KiB. A watch above the cap still fails with `ENOSPC`. The poll backend of Linux, and the fallback timer of macOS, now wait three times as long as a pass takes when a pass takes longer than 200 ms, so a large watch set uses at most a quarter of one core.
- **`.gvx_meta` keys its records on file identity** (`hostfs`, journal version 4): a record belongs to a file and not to a path. The identity is the volume serial number and the 128-bit file id on Windows, the device, the inode number, and the birth time on Linux, and the device and the inode number on macOS. The birth time tells a new file from an old one with the same inode number, which ext4 reuses at the next create. APFS never reuses an inode number, and it lowers the birth time when a process sets an earlier modification time, so the macOS key holds no birth time. Measured on an Apple M1 with APFS, with the benchmarks of `HOSTFS_BENCH=1`:

  | Operation | Table size | Before | After |
  | :--- | ---: | ---: | ---: |
  | Listing of a directory with 100 files | 10,000 records | 216 us | 165 us |
  | Listing of a directory with 100 files | 100,000 records | 789 us | 140 us |
  | Rename of a directory with 2,000 children | 10,000 records | 527 us | 87 us |
  | Rename of a directory with 2,000 children | 100,000 records | 1.8 ms | 73 us |
  | `chmod` through one name of a file with 4 names | 10,000 records | 276 ms | 4 us |
  | `chmod` through one name of a file with 4 names | 100,000 records | 2.5 s | 3 us |
  | Flush of one change | 10,000 records | 4.9 ms | 4.0 ms |
  | Flush of one change | 100,000 records | 5.0 ms | 4.0 ms |
  | Open of a workspace | 10,000 records | 59 ms | 25 ms |
  | Open of a workspace | 100,000 records | 450 ms | 165 ms |

  - A host process that renames a file or a directory keeps the mode, the owner, and the extended attributes of the guest. A guest symbolic link follows its directory. Before, the record stayed behind at the old path.
  - A host process that creates a file at the path of a file that still exists no longer gives it the record of that file. A host editor that saves by writing a temporary file and renaming it over the document keeps the record: a file with no record adopts the record that the guest last saw under the same directory and name, when the recorded file is gone, and it loses the set-user-ID and set-group-ID bits. On Linux and macOS, a host process that deletes a file and creates another one under the same name, or that moves a file to another directory and creates a new one in its place, gives the record to the new file, because only Windows can ask the host whether the recorded file still exists.
  - On macOS, `utimensat` to a time before the creation of a file lowers its APFS birth time, as `tar`, `cp -a`, and `rsync -a` cause. The key holds no birth time, so the record of the file and the guest links of a directory keep their key. The loader reads the birth time of a key that an earlier build stored as zero.
  - The names of a hard-linked file share one record. A `chmod`, `chown`, or `setxattr` makes no scan of the table, and a `link` needs no new record. A listing scans no table either, and a rename of a directory scans one only when the table holds path records, which path-key volumes and entries without an identity have.
  - The open of a workspace no longer checks each record against the host. A background collector removes the records whose file is gone. It starts 30 s after the open and works in small steps. A record dies when two complete passes in a row miss it and a lookup by its hint path confirms the loss. When that lookup finds a new file of the same kind, such as the result of a host editor save between the passes, the record moves to the new file instead. A directory that the host denies access to is skipped, and a skipped directory keeps its records. A record that a conversion could not resolve because of a host error stays as a path record until the next open. A path record whose path is absent at the open stays too. When the collector moves a record to a replaced file, it lists no directory, and a guest stat of many files that a host process replaced lists their directory at most once each second.
  - The cap of the table is now 128 MiB of estimated memory, about 300,000 plain records. The old cap was 262,144 records. A record with large extended attributes counts more than a plain record.
  - A volume without trustworthy file identities keeps its records by guest path, as before. The probe at the open needs a real birth time on Linux, a nonzero inode number on macOS, or `FILE_ID_INFO` on Windows. On macOS the volume must be APFS, because HFS+ can reuse an inode number. On Linux, 64 rounds of create and unlink of a hidden `~gvx~tmp.probe.*` file must give 64 different keys. The rounds run once at each open of a writable workspace and cost 256 system calls. The identity must stay the same across a write. `WorkspaceCaps.StableIDs` reports the result. A bind mount of one file keeps its records in memory only, as before.
  - An entry of a file system that the guest mounts inside the workspace, and that reports no usable identity, keeps its records by guest path in the same table. A create, `chmod`, `chown`, `setxattr`, `utimensat`, and guest symbolic link work there. A directory rename and `RENAME_EXCHANGE` move those records, and the collector meets them in its walk. On macOS, an entry on another device than the workspace root counts as an entry without an identity, unless that device is APFS.
  - A host directory that lies inside another mounted host directory keeps its own `.gvx_meta` table. When a non-aligned layout lets the guest reach one file through both mounts, the two views can show different metadata for it.
  - `hostfs.ReadMeta` names each record by the path where it finds the file in the host tree, and it leaves out the record of a file that no longer exists.
  - **Upgrade note**: the first write to a workspace or a volume that has an older `.gvx_meta` converts the file to version 4. The conversion reads the host once for each recorded path, drops the records of paths that name nothing, and merges the records of hard links. A release before this one cannot open a converted workspace: it fails with an error for the unsupported version. Keep a copy of `.gvx_meta` before you convert a workspace that an older release must open again. A session that changes nothing leaves the older file as it is.

- **Faster `hostfs` and a journal for `.gvx_meta`**: `hostfs` serves `-workspace`, bind mounts, and `driver=hostfs` volumes. Measured on an Apple M1 with `hvf`, the guest creates 10,000 files in 1.2 s to 2.0 s (was 2.4 s to 2.6 s), runs `ls -lR` over them in 0.4 s (was 1.0 s), extracts a tree of 2,000 files with `tar x` in 0.7 s (was 1.6 s), and runs 300 rounds of `dd conv=fsync` plus `mv` in 3.8 s (was 10.4 s). A `docker pull nginx:alpine` on `hostfs` went from 44 s to 41 s, because the host file system dominates that workload.
  - Every lookup, mutation, and directory listing now goes through the pinned handle of the directory. A `create`, `rename`, `chmod`, `utimensat`, or `link` at depth 5 made 7 to 34 host system calls and now makes 2 to 8.
  - A directory listing reads the entry type and the inode number from the directory record, and no longer stats each entry. A `stat` of each entry after an `ls` makes no host call. Metadata that a host process changes for an existing entry shows up after 1 s, as for every other host change.
  - A write no longer drops the cached identity of a file, so an `fstat` of an open file makes no path lookup.
  - `.gvx_meta` is an append-only journal with checksummed frames and periodic compaction. A flush of one change with 100,000 records took 83 ms and now takes 7.9 ms (13.4 ms and 6.8 ms with 10,000 records). `fsync`, `fdatasync`, `sync`, and writes with `O_SYNC` keep their durability, and a table without changes costs no host call. A crash can leave a torn last frame, which the next start ignores.
  - **Upgrade note**: the first write to a workspace or a volume that has a JSON `.gvx_meta` converts the file to the journal form. A release before this one cannot open a converted workspace: it fails with a parse error for `.gvx_meta`. Keep a copy of `.gvx_meta` before you convert a workspace that an older release must open again. A session that changes nothing leaves the JSON file as it is.

## [v0.6.10002026110200] - 2026-11-03

This release updates the Sentry to gVisor `release-20261102.0` and introduces a new version format. `AGENTS.md`, section 5.2, defines the format.

### Behavior Changes

- **Upstream gVisor `release-20261102.0`**: the Sentry now comes from the `go` branch commit `1cea747e`. That commit is the first merge that contains the release commit `7a675ac6`. The guest vDSO reads a new `CLOCK_BOOTTIME` offset from the parameter page.
- **Upstream diff budget**: `tools/upstream -mode=audit` accepts a charged share of up to 2.0% of upstream files. The old limit was 1.0%.
- **Version format**: the PATCH field of a release tag joins the digit `1`, a three-digit release counter, the upstream release date, and the two-digit upstream release suffix. `v0.6.10002026110200` is the first release in `0.6` and contains gVisor `release-20261102.0`.

## [v0.5.2] - 2026-11-03

This release lets Node.js build TypeScript and JavaScript projects on the Windows `amd64` `systrap` engine. The engine runs when the host has no Windows Hypervisor Platform, or with `-platform=systrap`.

### Bug Fixes

- **Node.js on the Windows `amd64` `systrap` engine** (issue #24): `npm install`, `tsc`, `transpileModule()`, esbuild, and `vite build` ended with SIGSEGV (exit code 139), SIGTRAP (exit code 133), or SIGILL (exit code 132) in Node.js 20, 22, and 24. Three engine defects caused this:
  - The repair of a lost FS base ran the faulting `%fs` instruction again, and Windows could reset the base again first. After eight repairs, the engine reported SIGSEGV. The Sentry now runs the instruction and moves past it, so each repair makes progress.
  - The engine patched false system call and GS sites in the data that V8 keeps beside its code in writable and executable anonymous memory. V8 then read changed pointers. On `amd64`, such pages now run unpatched. A writable segment of an ELF file stays patched.
  - The scan saw only 15 bytes before a page, and it found a GS instruction inside a `lea` of Node.js 20. The scan now starts 64 bytes before the page.

## [v0.5.1] - 2026-11-02

This release lets the unmodified `docker:dind` image run as a persistent Docker Engine that the `docker` command of the host controls. `docs/docker-engine.md` describes the setup on macOS and Windows.

### Features

- **Guest overlay upper layer on `ext4lite` and `hostfs`**: a guest `mount -t overlay` with `upperdir` on a named volume, a volume image, or a bind mount no longer fails with `EINVAL`. The overlay storage driver of `dockerd` therefore works with `-v NAME:/var/lib/docker` and with `-v /host/dir:/var/lib/docker`, with the containerd snapshotter and with `overlay2`. Whiteouts, opaque directories, and copy-up data survive a restart and a SIGKILL. `ext4lite` is the faster choice. `hostfs` is slower. See `docs/cli.md`, section 4.4.
- **`iptables -m addrtype`**: the guest has the `addrtype` match in revisions 0 and 1, for IPv4 and IPv6. It knows the types `UNICAST`, `LOCAL`, `BROADCAST`, `MULTICAST`, and `UNSPEC`, and the options `--limit-iface-in` and `--limit-iface-out`. An unmodified `docker:dind` image now starts with the default `--iptables=true`. It failed with `Extension addrtype revision 0 not supported`. `docker run -p`, the default `bridge` network, user-defined networks, `docker build`, and `docker compose up` work in the guest.
- **Port ranges in `-p`**: `-p 8000-8009:8000-8009` and `-p 8000-8009` publish one port for each number, up to 1024 ports. Two ranges must have the same length.
- **Unix socket publishing**: `-p unix:PATH:GUEST` forwards a host Unix socket to a guest TCP port, for example `-p unix:~/.gvx/docker.sock:2375` for the Docker API. The SDK field is `PortForward.HostSocket`.

### Behavior Changes

- **`--privileged` on by default**: `rungv run` turns on `--net-raw`, `--allow-packet-socket-write`, and `--allow-suid` unless `--privileged=false` is given. A flag of the three that you set wins over `--privileged`. These privileges stay inside the sandbox. The SDK fields keep their zero values off.

### Bug Fixes

- **`hostfs` and `ext4lite` as overlay layers**: both drivers returned `EOPNOTSUPP` for the POSIX ACL query of the overlay, so a mount with one of them as a layer failed. They now report no ACL.
- **Failed overlay mount**: an error after the root dentry of the overlay existed made the Sentry panic. The mount now fails with the error.
- **Program starts from a `hostfs` layer of an overlay**: the second start of an executable on a `hostfs` lower or upper layer ended with SIGBUS or `Bad address`, for example `nginx` in a container on a `hostfs` Docker root. `hostfs` now opens a handle when a new mapping finds none.
- **Inverted input interface in `iptables`**: a rule such as `! -i docker0 -j DNAT` came back from the guest as `-i docker0`. `iptables -C` and `iptables -D` did not find the rule. The guest now reports the `!` of `-i`, for IPv4 and IPv6.
- **`DNAT` rule deletion**: the `DNAT` target of revision 2 reported a size of 72 bytes, but it has 80 bytes. `iptables -C` and `iptables -D` did not find a `DNAT` rule, so `dockerd` left the rule of a removed container behind. The size is now correct.

## [v0.4.1] - 2026-11-02

This release makes `docker exec` work in a guest.

### Bug Fixes

- **`docker exec` in a guest**: runc refused `docker exec`, healthchecks, and `docker compose exec` with `namespace NEWNS is not supported`. The root mount namespace of the guest had no nsfs inode, so `/proc/[pid]/ns/mnt` could not be read. The kernel now gives the namespace its inode, as in runsc. `setns(2)` into a mount namespace also works.
- **Linux `FutexWait` with a timeout**: a signal handler that ran during the wait, such as the SIGURG of Go preemption, made the wait return as if a wake had come. The Sentry synchronization code on Linux hosts now parks again for the time that is left.

## [v0.4.0] - 2026-11-02

This release closes the gaps to runsc that systemd, Docker in the guest, and desktop workloads hit. It also fixes a guest-triggered host panic and a slowdown of every system call on macOS.

### Features

- **`rungv run --pull=always|missing|never`**: the flag selects when an image comes from its registry, as in Docker. The default is `missing`, as in Docker. The SDK has `Config.PullPolicy` with `PullAlways`, `PullMissing`, and `PullNever`, and `Config.Warnings` for the warning line. `missing` uses the cache first. `never` uses only the cache.
- **ext4lite volume at any host path**: `--mount type=volume,src=/disk/vols/pg.ext4,dst=/data` stores the volume in that image file instead of the `volumes` directory of the cache. A source with a path separator names the file. The sandbox creates a missing file but not its directory. The SDK field is `Mount.ImagePath`.
- **`--net-raw` and `--allow-packet-socket-write`**: the guest can open raw sockets and use `iptables-legacy`, as with the runsc flags of the same names. `dockerd` needs them. The SDK fields are `Config.NetRaw` and `Config.AllowPacketSocketWrite`. Both are off by default.
- **`--allow-suid`**: the guest obeys the set-user-ID and set-group-ID bits, as with the runsc flag. `sudo` then works for a user that is not root. The SDK field is `Config.AllowSUID`. It is off by default.
- **Container runtimes in the guest**: the guest root file system is now a mount on a hidden read-only root, as in runsc, so `pivot_root(2)` works. A new network namespace gets a stack with `lo`; `unshare -n` hung before. The kernel has `mqueue` at `/dev/mqueue`, `cgroup2` at `/sys/fs/cgroup`, `/dev/fuse`, `/dev/net/tun`, and `NETLINK_KOBJECT_UEVENT` and netfilter netlink sockets.
- **`reboot(2)`**: a power off or a halt by root in the guest ends the run with exit code 0, and a restart ends it with 129. `systemctl poweroff` stopped no run before.
- **Task watchdog**: the kernel logs the stacks of a task that stays in the Sentry for 3 minutes. `GVX_DEBUG_LOG=1` shows the log.

### Behavior Changes

- **`rungv run` uses the cached image first**: the default pull policy is now `missing`, as in Docker. A run of a cached reference sends no registry request, so a tag that moved in the registry keeps the cached image. Use `--pull=always` or `rungv pull` to get the new image. The SDK default of `Config.PullPolicy` is `PullMissing`.
- **Host RAM as the guest memory size**: `MemTotal` and `sysinfo(2)` report the physical RAM of the host, as in runsc. Before, they reported 2 GiB. A tmpfs mount without a size option gets half of that RAM, and `size=N%` now resolves. systemd failed at boot on `size=20%` before. Without `--memory`, the memory guard stops a guest that passes the host RAM.
- **Network links**: the guest links have the names `lo` and `eth0`, so `ip addr` lists them and Docker host networking finds them. Every guest stack has ARP, local delivery, SACK, receive buffer tuning, and a default TTL of 64, as the runsc stack has.
- **NAT mode routing**: `eth0` is now a link to a second in-memory stack that stands for the host network, and not a loopback device of the guest stack. The guest stack therefore forwards and translates packets as a Linux router does. `dockerd --net-raw` with its default `bridge` network now reaches the internet, and `docker build` works. A connection from a bridge container to `10.0.2.15` still fails, because the guest stack sends the reply through `eth0`, the link of that address.

### Performance

- **Root file system lookups**: the overlay of the root file system keeps up to 4096 unused dentries. Before, it destroyed a dentry at its last reference and looked up each path component in each layer again. On `hvf` (Apple M1), `stat(2)` of a file two directories below the root fell from 8.6 us to 2.3 us, a path with 8 more components from 20.8 us to 2.4 us, and a file in the merged `/tmp` from 13.4 us to 2.0 us. A plain tmpfs takes 2.0 us.
- **`darwin` system calls**: see the `GOMAXPROCS` fix below. A 1-byte `pread` stays at about 1.9 us after the first second, where it rose to 42 us.

### Bug Fixes

- **Guest-triggered host panic on `darwin` and `windows`**: a failed `sendmsg` on a Unix socket (for example `su` or `logger` in an Alpine guest) stopped the host with `unknown host errno "errno 107"`. `syserr.Error.ToError` returned a Linux number as a host `unix.Errno`, and `syserr.FromError` then looked it up in the host table. `ToError` now returns the `linuxerr` error on those hosts, and `FromError` keeps the Linux number.
- **`darwin` host performance after lockdown**: `GOMAXPROCS` fell from the CPU count to 1 about one second after `hostlockdown.Apply`, and every guest system call became about 20 times slower. The Go runtime re-read `hw.ncpu` with `sysctl`, and Seatbelt rejected the call. `Apply` now pins `GOMAXPROCS` before it applies the profile.
- **`/proc/cpuinfo` on `darwin/arm64` and `windows/arm64`**: `CPU architecture`, `CPU implementer`, `CPU part`, and `BogoMIPS` were 0. containerd then chose the platform `linux/arm64/unknown`. The fields now show architecture 8, the fields of the `MIDR_EL1` value that the guest reads, and `BogoMIPS` of twice the `CNTFRQ_EL0` frequency in MHz (48.00 for a 24 MHz counter). `hvf` guests show implementer 0x61 (Apple). The `hvf` backend writes that `MIDR_EL1` value to every vCPU, so the guest value does not depend on the Apple chip of the host.
- **`rungv run` of a loaded image**: after `rungv load -i img.tar`, `rungv run mylocal/app:1` failed with a registry 401, because the run always asked the registry first. The default policy `missing` now uses the cached image without a registry request. With `--pull=always`, the run uses the cached image when the registry answers 401, 403, or 404, and it prints one warning line. `oci.ErrAuthRequired` names a registry that demands credentials that the Docker configuration does not hold.
- **systemd mount units**: `run-lock.mount` and other units with `KeyringMode=shared` failed with status 237/KEYRING, because `keyctl(KEYCTL_LINK)` of the user keyring returned ENOSYS. That link now succeeds. The Sentry has no user keyring, so the link adds no key.
- **Host crash when a guest init exits**: `rungv` stopped with a nil pointer panic when the guest init exited with a netlink socket open, as systemd does at power off. The sandbox held the last reference of the init file table and released it without a task.
- **Docker schema 1 images**: `rungv pull` and `rungv run` now report `image uses Docker manifest schema 1, which is not supported; rebuild or re-push it with a current Docker`. Before, a signed schema 1 manifest such as `sshipway/xclock` failed with `content digest mismatch`, because the registry reports the digest of the unsigned payload. `oci.ErrSchema1Unsupported` names the error.

## [v0.3.0] - 2026-11-02

This release makes the CPU features that a guest sees agree with the features that it can use.

### Bug Fixes

- **`whpx` on `windows/amd64`**: guests can use AVX, AVX2, FMA, F16C, and AVX-512. XCR0 was 3 (x87 and SSE), while CPUID and `/proc/cpuinfo` reported the AVX family. A program that checked only CPUID or `/proc/cpuinfo` got `SIGILL`, and x86-64-v3 images (RHEL 10 family) did not start. The backend now selects the `ProcessorXsaveFeatures` property and XCR0 together. It moves the compacted XSAVE state through `WHvGetVirtualProcessorState` and `WHvSetVirtualProcessorState`.
- **`whpx` feature set on `windows/amd64`**: `/proc/cpuinfo`, signal frames, and sigreturn checks list only the features of the partition. MPX, AMX, and protection keys no longer appear.
- **`AT_HWCAP` on `darwin/arm64` and `windows/arm64`**: the value was 0, and the `Features` line of `/proc/cpuinfo` was empty. `hvf` guests now get the bits of the `hw.optional` sysctl keys. `whpx` guests on `windows/arm64` get the host bits that `hvcommon.DefaultIDRegisters` also reports. glibc and OpenSSL then use LSE atomics, AES, SHA, and CRC32.

### Performance

Each value is the median of 3 runs. The baseline is `v0.2.0`.

| Workload | Host | Before | After |
| :--- | :--- | ---: | ---: |
| AES-128-GCM, `openssl speed` 16 KiB blocks in `alpine/openssl` on `hvf` | Apple M1 | 0.22 GB/s | 7.45 GB/s |
| SHA-256, same method | Apple M1 | 0.45 GB/s | 2.84 GB/s |
| ChaCha20-Poly1305, same method | Apple M1 | 0.68 GB/s | 2.12 GB/s |
| Vector state pull and push with one system call on `whpx` | `windows-latest` (AMD, AVX2, nested Hyper-V) | 68.9 us | 63.4 us |
| Vector state push on `whpx` | same | 16.1 us | 13.6 us |
| System call round trip on `whpx` | same | 18.4 us | 15.9 us |

The `hvf` microbenchmarks of `e2e/microbench_e2e_test.go` (`getpid`, `open_close`, `pipe_pingpong`, `futex_pingpong`, `fork_wait`, `fork_exec_true`) show no change outside the variation between runs.

### Not verified

- `TestRealZMMSurvivesTheSentryAndProcessorSharing` skips on a CI runner without AVX-512.
- The `windows/arm64` `AT_HWCAP` path has no run on a Windows host.

## [v0.2.0] - 2026-11-01

This release makes the `whpx` backend run guests on `windows/arm64`. The other backends and targets have no behavior change.

### Bug Fixes

- **`whpx` on `windows/arm64`**: the partition now starts guests. The backend configures GICv3 before partition setup, assigns one redistributor to each virtual processor, and starts every virtual processor active. With v0.1.0 on Windows 11 build 28000, partition setup failed without the GICv3 parameters, and secondary processors stayed suspended.
- **`whpx` stub exit on `windows/arm64`**: WHP consumes `HVC #0` without an exit to the host. The EL1 stub now returns to the host through a load from an unbacked guest physical page that only EL1 can read.

### Performance

- **`whpx` on `windows/arm64`**: each system call and fault stop costs one extra `WHvSetVirtualProcessorRegisters` call. The memory exit leaves the program counter at the load, so the host writes the program counter before it resumes the processor.

### Not verified

- The contributor ran the native `whpx` suites and the image gates on Windows 11 build 28000 only. The project has no native result on Windows 11 24H2 (build 26100), the documented minimum.
- CI cannot run `whpx` on `windows/arm64`, because the `windows-11-arm` runner has no Windows Hypervisor Platform.
- The extra program counter write has no latency measurement.

## [v0.1.0] - 2026-11-01

This section describes the first release. The API of `pkg/gvx`, the flags of `rungv`, and the on-disk formats of the image store and of `ext4lite` volumes can change before `v1.0.0`.

### Features

- **`rungv` CLI**: runs OCI images and Linux ELF64 binaries in the foreground with Docker-style flags. The commands are `run`, `pull`, `images`, `inspect`, `tag`, `rmi`, `save`, `load`, `login`, `logout`, `stub`, `license`, and `version`. [`docs/cli.md`](docs/cli.md) is the reference.
- **`pkg/gvx` SDK**: embeds one sandbox in a Go host program.
- **Execution backends**: `hvf` on `darwin/arm64`, `whpx` on `windows/amd64` and `windows/arm64`, the `gvx` `systrap` engine on `windows/amd64` and `windows/arm64`, and the upstream `systrap` platform on Linux.
- **OCI images**: pulls multi-arch images and compiles each layer in memory into a cached `.erofs` file. The guest architecture must equal the host architecture.
- **Storage**: `-workspace` and `-v` bind mounts through `hostfs`, and named volumes in one journaled `.ext4` file through `ext4lite`.
- **Network**: `-net=nat` with `-p` port forwarding, and `-net=wg` with an in-memory WireGuard tunnel.
- **Host lockdown**: Windows Restricted Token and Job Object, macOS Seatbelt, and Linux `seccomp`. The lockdown starts before the guest entrypoint runs.
- **Control shim**: the optional `containerd-shim-gvx-v2` command implements the control endpoints of runtime `io.containerd.gvx.v2`.
- **Release identity**: `rungv version` and `rungv --version` print the module version, the source commit, and the Go toolchain of the binary.
- **Release provenance**: each release archive has a SLSA v1 build provenance attestation (SLSA Build Level 2). `gh attestation verify` checks it. Section 2.4 of [`README.md`](README.md) gives the procedure.

### Known limitations

- The control shim rejects sandbox and workload creation with `Unimplemented`. It does not implement CRI.
- macOS has no `systrap` engine. `rungv` on macOS needs `Hypervisor.framework` and a binary signed with `entitlements.plist`.
- `darwin/amd64` is not supported.
- On Linux, a workspace, a bind mount, or a `hostfs` volume leaves `Status.UnboundFileOpenBlocked` false. Section 3.9 of [`docs/architecture.md`](docs/architecture.md) gives the reason.
- The release archive for macOS has an ad-hoc signature, not a Developer ID signature or notarization. Section 2.4 of [`README.md`](README.md) gives the install procedure.
- `whpx` on `windows/arm64` does not start a guest in this release. Use `-platform=systrap` on `windows/arm64`. v0.2.0 fixes `whpx`.

### Not verified

- CI cannot run `hvf`, because the hosted macOS runner has no hypervisor. The project verifies `hvf` on an Apple Silicon development host only.
- CI runs `whpx` on `windows/amd64` only. The `windows-11-arm` runner has no Windows Hypervisor Platform, so `whpx` on `windows/arm64` has no CI run.
- The control shim has no successful native sandbox creation and no guest workload on any platform.
