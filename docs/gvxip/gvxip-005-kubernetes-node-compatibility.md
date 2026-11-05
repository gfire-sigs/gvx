# GVXIP-005: Kubernetes Node Compatibility

This specification defines how a `gvx` sandbox can join a real multi-node Kubernetes cluster as a worker or a control-plane node. The method adds no `gvx` API: no flag, no SDK field, and no code that knows Kubernetes. It adds the Linux kernel behavior that unmodified `k3s`, `kubelet`, `containerd`, `runc`, `flannel`, and `wg-quick` expect, and it fixes the tests that prove each behavior.

| Field | Value |
| :--- | :--- |
| **Document ID** | `GVXIP-005` |
| **Title** | Kubernetes Node Compatibility |
| **Status** | Implemented |
| **Isolation Tier** | Tier 2 (`_xplat.go` siblings in upstream packages) and Tier 1 (new directories that `tools/upstream` lists in `tier1Prefixes`) |
| **Target Platforms** | `darwin/arm64` (`hvf`), `windows/amd64` (`whpx`, `systrap`), `windows/arm64` (`systrap`), `linux/amd64` and `linux/arm64` (`systrap`) |
| **Companion Specs** | [`../docker-engine.md`](../docker-engine.md), [`../architecture.md`](../architecture.md) |

The phases below have a fixed order. A phase ends when every test of its exit criterion passes.

| Phase | Content | State |
| :--- | :--- | :--- |
| P1 | Kernel interfaces of `kubelet` and the container runtime | Done. A1 to A7 and B1, B2, B7, B8, and B11 pass on every platform of section 4.4. |
| P2 | Service data path (`statistic`, `recent`, bridge netfilter, `ctnetlink`) | Done. A8 to A11 and B3 to B6 pass on every platform of section 4.4. |
| P3 | Links between nodes (generic netlink, `wireguard`, `vxlan`, neighbor and FDB netlink) | Done. A12, A13, C1, C2, and C3 pass on every platform of section 4.4. |
| P4 | Enforcement of `cpu.max` | Done. A14, B9, B10, C4, and C5 pass on every platform of section 4.4. |
| P5 | IP sets and NetworkPolicy (`ipset`, `set` match, `SET` target, `icmp`, `limit`, `physdev`, `NFLOG`) | Done. A15, A16, and B12 pass on the platforms that the CHANGELOG lists. |

---

## 1. Evidence (Reference Module)

An unmodified `rancher/k3s:v1.31.4-k3s1` image ran on `hvf` on an Apple Silicon host. The API server, `kine`, `kubelet`, `containerd`, `kube-proxy`, and `flannel` started, and the node reached `Ready`. Each failure below stopped the run until a workaround inside the guest bypassed it.

| Order | Failure | Missing kernel behavior |
| :--- | :--- | :--- |
| 1 | `kubelet` exits: `open /dev/kmsg: no such file or directory` | The `/dev/kmsg` device |
| 2 | `Failed to start ContainerManager` | A writable `vm/overcommit_memory`, and the files `vm/panic_on_oom`, `kernel/panic`, and `kernel/panic_on_oops` |
| 3 | `kube-proxy exited: iptables is not available on this host` | `nftables`; the `k3s` detection script selected `nft` |
| 4 | Every pod sandbox fails: `open /proc/sys/net/ipv4/ip_unprivileged_port_start: no such file or directory` | The sysctl `ip_unprivileged_port_start` |

The run also logged errors that did not stop it: the `nf_conntrack` sysctls, `conf/all/forwarding`, `conf/default/forwarding`, `/sys/class/net`, and `/proc/diskstats`.

---

## 2. Method (Descriptive Module)

The Sentry implements the Linux behavior that the cluster software reads and writes. The user configures the cluster with standard Kubernetes, `k3s`, and WireGuard settings, and with the existing `gvx` options `-p`, `-m`, `--cpus`, `--mount`, and `--net=nat`.

### 2.1 Topologies

Two topologies cover the target clusters. Both use only standard tools inside the guest.

| Topology | Cluster | Node-to-node path | Kernel behavior that it needs |
| :--- | :--- | :--- | :--- |
| T1 | `k3s` | The `k3s` agent tunnel carries API server traffic to the `kubelet` over an outbound TCP connection. Pod traffic uses `flannel` with the `wireguard-native` back end. A published UDP port (`-p 51820:51820/udp`) or a WireGuard keepalive admits the peers. | The `wireguard` link and generic netlink |
| T2 | Any cluster (`kubeadm` and others) | `wg-quick` in the guest builds a WireGuard mesh over the NAT link `eth0`. The `kubelet` uses `--node-ip` with the `wg0` address. The CNI uses VXLAN over `wg0`. | The `wireguard` and `vxlan` links, and neighbor and FDB netlink |

T2 needs no special network mode of `gvx`. The guest builds its WireGuard interface on top of `eth0`, as a Linux server does.

### 2.2 Placement of the Code

The new code lives next to the upstream code that calls it. This rule keeps the upstream diff budget unchanged.

| Rule | Example |
| :--- | :--- |
| A change in an upstream package goes into a sibling `_xplat.go` file. | `pkg/sentry/fsimpl/proc/tasks_sys_xplat.go` |
| A change inside an upstream function uses a seam with an entry in `tools/upstream/buildtag_allowlist.txt`. | The bind check of `ip_unprivileged_port_start` |
| A new directory gets an entry in `tier1Prefixes` of `tools/upstream/diff_audit.go` and in `tools/upstream/file_mask.txt`. | `pkg/sentry/socket/netlink/genetlink`, `pkg/tcpip/link/vxlan` |

---

## 3. Scope (Reference Module)

The tables list every change of this specification. A change outside these tables needs an update of this document first.

### 3.1 P1: Kernel Interfaces of the Node Agent

The `kubelet`, `containerd`, `runc`, and `k3s` read or write these files. The first four rows stopped the `k3s` run.

| Item | Behavior | Location |
| :--- | :--- | :--- |
| `/dev/kmsg` (character device 1:11) | Opens for read and write. `lseek` with offset 0 returns 0 for `SEEK_SET`, `SEEK_DATA`, and `SEEK_END`. A non-zero offset returns `ESPIPE`, and another `whence` returns `EINVAL`. A non-blocking read with no new record returns `EAGAIN`. A write goes to the Sentry log and returns its length. | `pkg/sentry/devices/memdev/kmsg_xplat.go`; registration in `pkg/gvx/kernel_runner.go` |
| `vm/overcommit_memory` | Accepts 0, 1, and 2, and stores the value. Other values return `EINVAL`. | `pkg/sentry/fsimpl/proc/tasks_sys_node_xplat.go` |
| `vm/panic_on_oom`, `kernel/panic`, `kernel/panic_on_oops`, `kernel/keys/root_maxkeys`, `kernel/keys/root_maxbytes` | Store an integer and return it. A value outside the Linux range returns `EINVAL`. | `tasks_sys_node_xplat.go` |
| `net/ipv4/ip_unprivileged_port_start` | One value for each network namespace. The root namespace of a sandbox is the container namespace and starts at 0, as in a Docker container. A namespace that the guest creates starts at 1024. A bind below the value needs `CAP_NET_BIND_SERVICE`. | `tasks_sys_node_xplat.go`; `pkg/sentry/socket/netstack/sysctl_store_xplat.go`; `bindport_xplat.go` and a seam in the bind path; the root value in `pkg/gvx/kernel_runner.go` |
| Safe sysctls of Kubernetes | `net/ipv4/ip_local_port_range`, `tcp_syncookies`, `ping_group_range`, `ip_local_reserved_ports`, `tcp_keepalive_time`, `tcp_keepalive_intvl`, `tcp_keepalive_probes`, `tcp_fin_timeout`, and `kernel/shm_rmid_forced` are writable. The network values belong to each network namespace. | `tasks_sys_node_xplat.go`; `pkg/sentry/socket/netstack/sysctl_xplat.go`; `pkg/tcpip/transport/tcp/keepalive_xplat.go`; `pkg/sentry/kernel/ipc_namespace_xplat.go` |
| `net/ipv4/ip_forward`, `net/ipv4/conf/all/forwarding`, `net/ipv4/conf/default/forwarding` | `ip_forward` and `conf/all/forwarding` are one switch for the namespace. A write to it also sets `conf/default/forwarding` and every link that exists. A write to `conf/default/forwarding` changes only the links that the guest creates later. A new network namespace gets the IPv4 switches of the root namespace, and its IPv6 switches start at 0. | `tasks_sys_node_xplat.go`; `tasks_sys.go`; `pkg/sentry/socket/netstack/sysctl_store_xplat.go`; `pkg/tcpip/stack/forwarding_xplat.go` |
| `net/netfilter/nf_conntrack_max`, `nf_conntrack_tcp_timeout_established`, `nf_conntrack_tcp_timeout_close_wait`, `/sys/module/nf_conntrack/parameters/hashsize` | Store and return their values. | `tasks_sys_node_xplat.go`; `pkg/sentry/fsimpl/sys/netclass_xplat.go` |
| Node capacity | `MemTotal` follows `-m`, and the online CPUs, `sched_getaffinity`, and `/sys/devices/system/cpu/online` follow `--cpus`. The total belongs to the kernel of each sandbox. Without the options, the values stay as they are. | `pkg/gvx/hostmem.go`; `pkg/sentry/kernel/total_memory_xplat.go`; seams in `pkg/sentry/fsimpl/proc` and `pkg/sentry/syscalls/linux` |
| Statistics | `/sys/class/net/<link>/statistics/*` and `/proc/diskstats` exist, and their counters grow with traffic and I/O. The disk counters count the read and write system calls of the sandbox. | `pkg/sentry/fsimpl/sys/netclass_xplat.go`; `pkg/sentry/fsimpl/proc/diskstats_xplat.go`; `pkg/sentry/kernel/io_totals_xplat.go` |

### 3.2 P2: Service Data Path

`kube-proxy` programs these features in the iptables mode. They decide whether a service reaches every endpoint.

| Item | Behavior | Location |
| :--- | :--- | :--- |
| `-m statistic` | The match takes `--mode random --probability P` and `--mode nth --every N --packet K`, with `!` inversion. The probability is a 31-bit fraction, as in `xt_statistic`. Each rule has its own `nth` counter, and `iptables-restore` resets it. `iptables-save` prints the rule back unchanged. | `pkg/sentry/socket/netfilter/statistic_matcher_xplat.go` |
| `-m recent` | The match takes `--set`, `--rcheck`, `--update`, and `--remove`, with `--seconds`, `--hitcount`, `--reap`, `--rttl`, `--mask`, `--rsource`, `--rdest`, and `!` inversion, as in `xt_recent`. Rules of one network namespace that name one list share it, with the mask of the first rule. The list goes away with its last rule. A list keeps 100 addresses, as on Linux. `kube-proxy` uses the match for the session affinity of a Service. `/proc/net/xt_recent` does not exist. | `pkg/sentry/socket/netfilter/recent_matcher_xplat.go` |
| Bridge netfilter | With `bridge-nf-call-iptables` at 1, an IPv4 frame that the bridge forwards between two ports passes PREROUTING, FORWARD, and POSTROUTING. PREROUTING runs connection tracking and DNAT. POSTROUTING runs SNAT and MASQUERADE. A DNAT rule can move the destination to another host of the bridge. The neighbor cache of the bridge then gives the new Ethernet address, and the frame leaves through the port of that host. Conntrack undoes the NAT of each reply. With 0, the bridge keeps the current behavior. The same rules apply to `bridge-nf-call-ip6tables` and IPv6. Each network namespace has its own switches, and both start at 1. Group frames, frames for the bridge, and frames for a port go to the IP layer as before. | `pkg/tcpip/stack/bridge_netfilter_xplat.go` and a seam in `bridge.go`; `pkg/sentry/socket/netstack/bridge_netfilter_xplat.go`; `pkg/sentry/fsimpl/proc/tasks_sys_xplat.go` |
| `ctnetlink` | `NETLINK_NETFILTER` sockets open without `nftables`. `IPCTNL_MSG_CT_GET` lists the table (`NLM_F_DUMP`) or returns one entry by tuple. `IPCTNL_MSG_CT_DELETE` removes one entry by tuple. A partial tuple, or only the family, selects every matching entry instead. An entry has `CTA_TUPLE_ORIG`, `CTA_TUPLE_REPLY`, `CTA_STATUS`, `CTA_TIMEOUT`, `CTA_MARK`, `CTA_ID`, `CTA_USE`, and, for TCP, `CTA_PROTOINFO`. The next packet of a deleted flow runs the NAT rules again, and so does a SYN on a closed TCP flow. A message of another subsystem fails with `EINVAL`. A batch of an absent subsystem fails with `EOPNOTSUPP`, as on Linux. | `pkg/sentry/socket/netlink/netfilter/ctnetlink_xplat.go` and a seam in `protocol.go`; `pkg/tcpip/stack/conntrack_xplat.go` |

The limits of P2 are these. The table keeps no counters, timestamps, labels, zones, or connection mark, so `CTA_MARK` is always 0. `IPCTNL_MSG_CT_NEW` fails with `EOPNOTSUPP`, and the expectation table is empty. A frame that a DNAT rule sends to the bridge or to another route enters the IP layer as it arrived. The IP layer reuses the connection that the bridge created. A frame with an unknown destination passes FORWARD and POSTROUTING once and then goes to every port.

`kube-proxy` rejects a connection to a service without endpoints with `-j REJECT --reject-with icmp-port-unreachable` in the OUTPUT chain. The ICMP error returns over the loopback link inside the call that sends the SYN, while `connect` holds the lock of the endpoint. The endpoint therefore ends the pending connection in a new goroutine, after `connect` returns. The call fails with `ECONNREFUSED`. The code is `pkg/tcpip/transport/tcp/icmp_error_xplat.go`, with one call in `onICMPError` of `endpoint.go`. Without this behavior, `connect` to such a service never returned, and a read of `/proc/net/tcp` waited for it.

A ctnetlink dump has no size limit. The socket builds each chunk when the reader consumes the previous one, as `netlink_dump` does in Linux. `kube-proxy` therefore sees every flow on a busy node.

The bridge and the veth ends of P2 also follow Linux for the frames that pass the service path. A frame for the address of the bridge stays on the bridge. A known unicast address has one egress port, and an address that moves to another port is learned again. A veth end that is not a bridge port drops a unicast frame for another address before the IP layer. A pod then never forwards the flooded frame of a neighbor. A SYN on a TCP connection in TIME_WAIT or CLOSE starts a new connection and runs the NAT rules again.

### 3.3 P3: Links Between Nodes

These items connect the guest to other nodes with standard tools. The Sentry has no generic netlink today.

| Item | Behavior | Location |
| :--- | :--- | :--- |
| Generic netlink | `NETLINK_GENERIC` sockets and the controller family (`CTRL_CMD_GETFAMILY`). A registry lets other families plug in. | `pkg/sentry/socket/netlink/genetlink/genetlink.go` and `controller.go` (Tier 1) |
| `wireguard` link | `RTM_NEWLINK` with the kind `wireguard`, and the WireGuard generic netlink family (`WG_CMD_GET_DEVICE`, `WG_CMD_SET_DEVICE`). The device uses `wireguard-go` and sends UDP from the network namespace of the guest. A sandbox has at most 256 such links, and a device has at most 4,096 peers. | `pkg/sentry/socket/netlink/genetlink/wireguard` (Tier 1); the registry of link kinds in `pkg/sentry/socket/netstack/linkkind_xplat.go`, with one seam in `stack.go` |
| `vxlan` link | `RTM_NEWLINK` with the kind `vxlan`: VNI, destination port, local address, `nolearning`, and an MTU of 1450 by default. `RTM_GETLINK` reports the attributes in `IFLA_INFO_DATA`. | `pkg/tcpip/link/vxlan` (Tier 1) for the endpoint and the FDB. The link kind registers from `pkg/sentry/socket/netstack/vxlan_xplat.go` with `RegisterLinkKind`, so it needs no new seam. |
| Neighbor and FDB netlink | `RTM_NEWNEIGH`, `RTM_DELNEIGH`, and `RTM_GETNEIGH` for permanent IPv4 and IPv6 entries, and for FDB entries of the family `AF_BRIDGE` on a `vxlan` link | `pkg/sentry/socket/netlink/route/neigh_xplat.go`, with one call in `ProcessMessage` of `protocol.go`, a file that the audit already counts |
| Link MTU | `RTM_SETLINK` with `IFLA_MTU` and `ioctl(SIOCSIFMTU)` change the MTU of `eth0`, of a veth link, and of a bridge. `eth0` accepts 68 to 65535, or 68 to 65503 in the `wg` network mode, and a veth link or a bridge accepts 68 to 65535. A value outside the range fails with `EINVAL`. Each end of a veth pair has its own MTU. A link with an MTU below 1280 loses its IPv6 addresses and routes. `eth0` starts with 1500, or with the value of the tunable `net.nat.mtu`. The host end of the NAT link follows the change. | `pkg/netbackend/nat_forwarder.go`, `pkg/sentry/socket/netstack/linkmtu_xplat.go`, `pkg/tcpip/stack/nic_mtu_xplat.go` |
| Host tunables | One registry holds each host-side limit that Linux has no knob for, such as the NAT UDP session limit. `--tune`, `--tune-file`, and `gvx.Config.Tuning` set the values. [`cli.md`](../cli.md), section 3.3, lists them. | `pkg/gvx/tuning` (Tier 1) |

### 3.4 P4: Enforcement of `cpu.max`

The Sentry stores `cpu.max` today and does not enforce it. P4 adds the CFS bandwidth model of Linux.

| Item | Behavior | Location |
| :--- | :--- | :--- |
| `cpu.max` | The tasks of a cgroup run for at most the quota in each period. `cpu.stat` reports `nr_periods`, `nr_throttled`, and `throttled_usec`. | `_xplat.go` files in `pkg/sentry/kernel`, and a seam in `pkg/sentry/fsimpl/cgroup2fs/cpu.go` |

### 3.5 P5: IP Sets and NetworkPolicy

`k3s` runs the network policy controller of `kube-router`. It keeps the pod addresses of each policy in IP sets, and it matches them in iptables rules with the match `set`. Calico uses the same kernel interfaces. Before P5 the guest had no `ipset`, so `k3s` logged `Skipping network policy controller start, ipset save failed`, and a NetworkPolicy had no effect.

| Item | Behavior | Location |
| :--- | :--- | :--- |
| IP sets | A registry holds the named sets of one network namespace. The types are `hash:ip`, `hash:net`, `hash:ip,port`, `hash:net,port`, `hash:ip,port,ip`, `hash:ip,port,net`, `hash:net,net`, `bitmap:port`, and `list:set`, with the revision ranges of Linux 7.0. The options are `family`, `timeout`, `counters`, `comment`, `skbinfo`, `forceadd`, `maxelem`, `hashsize`, `bucketsize`, `netmask`, `bitmask`, and `nomatch`. A net set tests the longest prefix first. A set with a timeout drops an element at its time. | `pkg/ipset` (Tier 1) |
| `NFNL_SUBSYS_IPSET` | `NETLINK_NETFILTER` serves the protocol versions 6 and 7: `PROTOCOL`, `CREATE`, `DESTROY`, `FLUSH`, `RENAME`, `SWAP`, `LIST`, `SAVE`, `ADD`, `DEL`, `TEST`, `HEADER`, `TYPE`, `GET_BYNAME`, and `GET_BYINDEX`. An error message carries the request and, in a batch, the line number of the failed element, as in Linux. A listing sends one message for each read of the socket, so it has no size limit. | `pkg/sentry/socket/netlink/netfilter/ipset_xplat.go` and a seam in `pkg/sentry/socket/netlink/socket.go` |
| Limits | The limits follow Linux. The default `maxelem` is 65536. The file `/sys/module/ip_set/parameters/max_sets` has the default 256. A network namespace that starts after a write takes that size for its table of sets. The table grows by 64 sets when it is full, up to the 16-bit index space. | `pkg/ipset/registry.go`; `pkg/sentry/fsimpl/sys/ipset_xplat.go` |
| `-m set` | The revisions 1 to 4 take `--match-set NAME flags`, `!`, `--return-nomatch`, and the counter conditions. The match holds a reference to its set until the table that holds the rule goes away. A rule for a set that does not exist fails with `ENOENT`. `iptables-save` prints the rule back unchanged. | `pkg/sentry/socket/netfilter/set_matcher_xplat.go` |
| `-j SET` | The revisions 1 to 3 take `--add-set`, `--del-set`, `--exist`, `--timeout`, and `--map-set`. | `pkg/sentry/socket/netfilter/set_target_xplat.go` |
| `SO_IP_SET` | `iptables` resolves a set name to its index with `getsockopt(SOL_IP, SO_IP_SET)`: `IP_SET_OP_VERSION`, `GET_BYNAME`, `GET_BYINDEX`, and `GET_FNAME`. | `pkg/sentry/socket/netfilter/ipset_sockopt_xplat.go` and a seam in `pkg/sentry/socket/netstack/netstack.go` |
| `-m icmp`, `-m icmp6` | The matches select a packet by ICMP type and code, with `!` inversion. | `pkg/sentry/socket/netfilter/icmp_matcher_xplat.go` |
| `-m limit` | The match is a token bucket for each rule. | `pkg/sentry/socket/netfilter/limit_matcher_xplat.go` |
| `-m physdev` | The match knows the frames that a bridge switches between two ports. A packet that the IP layer routes through the bridge is not bridged. | `pkg/sentry/socket/netfilter/physdev_matcher_xplat.go`; the bridge code marks the packet in `pkg/tcpip/stack/bridge_netfilter_xplat.go` |
| `-j NFLOG` | The target accepts the rule and does nothing, because no listener of an `nflog` group exists. | `pkg/sentry/socket/netfilter/nflog_target_xplat.go` |
| `-j LOG` | The target takes `--log-level` and `--log-prefix`. It writes the line to the log of the Sentry, because `/dev/kmsg` holds no records yet. | `pkg/sentry/socket/netfilter/log_target_xplat.go` |

The match `set` of a rule keeps the index of its set. `ipset swap` exchanges the sets and the names behind the two indexes, so a rule sees the new data at once. A swap of two sets with different types fails. A destroy of a set fails with `EBUSY` while a rule, a `list:set` set, or a running listing refers to it.

The marshaled entries now carry the revision of each match. Before P5, `iptables -S` printed `[unsupported revision]` for the matches `mark` and `multiport`. An `iptables -I` on a table with such a rule then broke the table, and the later commands failed with `can't initialize iptables table 'filter': Incompatible with this kernel`. `kube-router` hit this fault at its first sync.

### 3.6 Out of Scope

These items stay outside this specification. The documentation of the feature lists each one as a limit.

| Item | Reason and replacement |
| :--- | :--- |
| `nftables` (`iptables-nft`) | The upstream implementation is marked `TESTONLY`. The `k3s` image reads `IPTABLES_MODE=legacy`, which is a setting of `k3s`. |
| `nflog` listeners | No netlink group of `NFNL_SUBSYS_ULOG` or `NFNL_SUBSYS_QUEUE` exists. |
| IPVS, eBPF, and kernel modules | The Sentry does not provide these interfaces. |
| `memory.max` on Windows `systrap` | A separate engine change. The documentation tells the user to taint such a node. |

---

## 4. Tests (Reference Module)

Every test uses unmodified upstream images and standard settings. No test uses a workaround inside the guest. The thresholds are the first values; a change of a threshold needs a change of this document.

### 4.1 Kernel Behavior (A)

These tests check one kernel behavior each. A Go program without an image runs the tests that need no tools. A test that needs `ip`, `wg`, `bridge`, `iptables`, or `conntrack` runs in an Alpine guest and installs the tools.

| ID | Behavior | Pass criterion |
| :--- | :--- | :--- |
| A1 | `/dev/kmsg` | The open succeeds. `lseek` returns 0 for `SEEK_SET`, `SEEK_DATA`, and `SEEK_END` with offset 0, `ESPIPE` for another offset, and `EINVAL` for another `whence`. A non-blocking read returns `EAGAIN`. A write of `<6>x` returns 4, the length of the text. |
| A2 | Stored sysctls | Each file of section 3.1 returns the value that the test wrote. `overcommit_memory` rejects 3 with `EINVAL`. |
| A3 | `ip_unprivileged_port_start` | The root namespace starts at 0, and a child namespace starts at 1024. At 1024, a bind to port 80 without `CAP_NET_BIND_SERVICE` fails with `EACCES`. At 0, it succeeds. A change in a child network namespace leaves the parent value. |
| A4 | Safe sysctls | Each network value is writable in a network namespace and keeps its old value in the parent namespace. |
| A5 | `conf/all/forwarding` | Three namespaces A, R, and B: with the value 1 in R, A reaches B with ICMP echo. With 0, it does not. `conf/default/forwarding` changes only the links that R creates later. A new namespace gets the IPv4 values of the root namespace. |
| A6 | Capacity | With `-m 2g --cpus 2`, `MemTotal` is 2 GiB within one page, `nproc` prints 2, and `cpu/online` reads `0-1`. |
| A7 | Statistics | After traffic and disk I/O, `rx_bytes` of `eth0` and the line of the root disk in `/proc/diskstats` have grown. |
| A8 | `statistic` random | With `--probability 0.5`, each of two targets gets 50% ± 5% of 2,000 connections. |
| A9 | `statistic` nth | With `--every 3 --packet 0`, exactly one connection in three matches. |
| A9a | `recent` | With the session affinity rules of `kube-proxy`, 40 connections of one client reach one backend. Without the rules, the same split reaches both backends. |
| A10 | Bridge netfilter | Two namespaces on one bridge connect over TCP through a DNAT rule for a virtual address when `bridge-nf-call-iptables` is 1. With 0, the DNAT rule does not apply to bridged frames. |
| A11 | `ctnetlink` | `conntrack -L` lists a UDP flow. After `conntrack -D` for the flow, the next packet follows the new DNAT target. |
| A12 | `wireguard` | `ip link add` and `wg set` configure a device, and `wg show` prints the configuration. Two sandboxes on one host exchange ICMP echo over `wg0`, once with a published UDP port and once with a keepalive only. After `wg set ... peer ... remove`, the traffic stops. |
| A13 | `vxlan` and FDB | Two sandboxes exchange ICMP echo over `vxlan1` with the setup of `flannel`: an FDB entry and a permanent neighbor entry. The MTU is 1450. Two namespaces of one guest do the same on `whpx`. After `bridge fdb del`, the traffic stops. |
| A14 | `cpu.max` | With `cpu.max` at `50000 100000`, a busy loop uses 0.5 ± 0.1 CPU over 5 seconds, and `nr_throttled` grows. |
| A15 | `ipset` tool | A set of each type takes `add`, `test`, and `del`. `ipset save` and `ipset restore` give the same sets back. `swap`, `rename`, a timeout, a listing of 6,000 elements, and the error messages of the tool work. `/sys/module/ip_set/parameters/max_sets` reads 256. |
| A16 | `set` match and `SET` target | A rule `-m set --match-set S src -j DROP` drops the traffic of a member and not of a non-member. `iptables-save` prints the rule back. `ipset destroy` fails while the rule exists. `--return-nomatch`, a counter condition, `!`, and `-j SET --add-set` and `--del-set` work, and a rule for IPv6 loads. |

### 4.2 Single-Node `k3s` (B)

These tests run `rancher/k3s` with `IPTABLES_MODE=legacy` and no other setting outside `k3s` defaults, except the flags in each row.

| ID | Behavior | Pass criterion |
| :--- | :--- | :--- |
| B1 | Node start | The node reaches `Ready` within 120 seconds. |
| B2 | System pods | `coredns` and `local-path-provisioner` run, and a deployment of `nginx` with 2 replicas becomes ready. |
| B3 | Service load balancing | Both endpoints answer within 50 requests to the service. |
| B4 | Hairpin | A pod reaches a service whose only endpoint is that pod. |
| B5 | NodePort | The host reaches a NodePort through a published port, and a pod reaches it through the node address. |
| B6 | DNS after a restart | Name resolution works again within 10 seconds after a restart of the `coredns` pod. |
| B7 | Pod access | `kubectl logs`, `kubectl exec`, and `kubectl port-forward` work. |
| B8 | Pod sysctls | A pod with `securityContext.sysctls` sees the values inside the container. |
| B9 | Resource limits | A pod with a CPU limit of 500m uses at most 0.6 CPU. A pod above its memory limit ends with `OOMKilled`, except on Windows `systrap`. |
| B10 | Metrics | `kubectl top node` and `kubectl top pod` print values. |
| B11 | Restart | After a stop and a start of the sandbox, the node returns to `Ready` with the same name, and the pods start again. |
| B12 | NetworkPolicy | `k3s` starts its network policy controller without the `ipset` warning. A policy that denies all ingress to a server pod stops two client pods. A second policy that names one client lets only that client through. After the policies end, both clients reach the server again. |

### 4.3 Multiple Nodes (C)

Several sandboxes on one host form the clusters, so CI can run these tests. C3 adds a node with a real Linux kernel.

| ID | Behavior | Pass criterion |
| :--- | :--- | :--- |
| C1 | T1 join | Setup: a server sandbox and an agent sandbox with NAT and `flannel` `wireguard-native`. The agent reaches `Ready`, and pods on the two nodes connect by pod address. A service with endpoints on both nodes answers. `kubectl logs` and `exec` work for a pod on the agent. |
| C2 | T2 join | Setup: a `wg0` link in each guest, made with `ip link` and `wg set`, `flannel` VXLAN over `wg0`, and `--node-ip` set to the `wg0` address. The agent tunnel is off. Pods on the two nodes connect, and the API server reaches the `kubelet` directly. |
| C3 | Mixed kernels | A native `k3s` server on a Linux runner and a `gvx` agent on the same runner pass the criteria of C1. |
| C4 | Control plane | Three server sandboxes with embedded etcd: after the end of the leader sandbox, the API answers again within 30 seconds. The test records the output of `etcdctl check perf`. |
| C5 | Conformance | `sonobuoy --mode quick` and the `[sig-network] Services` conformance tests pass with the test pods on the `gvx` node. |

### 4.4 Platform Matrix

Hosted runners cover Linux and Windows. The hosted macOS runner cannot run `hvf`, so an Apple Silicon development host runs those tests by hand.

| Platform | Where | Tests |
| :--- | :--- | :--- |
| Linux `systrap` (`amd64`, `arm64`) | CI | A, B, C. C5 runs on `amd64` only. |
| Windows `systrap` (`amd64`, `arm64`) | CI | A, B, C1, C2 |
| Windows `whpx` (`amd64`) | CI | A, B |
| `hvf` | Development host, by hand | A, B, C1, C2, C4, C5 |

The `whpx` backend runs one partition in each host process, and a test runs its sandboxes in one process. The tests with several sandboxes therefore skip `whpx`.

---

## 5. Exit Criteria of the Phases (Reference Module)

Each phase ends when its tests pass on every platform of section 4.4. The table lists the tests of each phase.

| Phase | Tests |
| :--- | :--- |
| P1 | A1 to A7, B1, B2, B7, B8, B11 |
| P2 | A8 to A11, B3 to B6 |
| P3 | A12, A13, C1, C2, C3 |
| P4 | A14, B9, B10, then C4 and C5 |
| P5 | A15, A16, B12 |

---

## 6. Sources (Reference Module)

The external facts of this specification come from these sources. The `gvx` facts come from the files that each section names.

| Source | Supports |
| :--- | :--- |
| [`k3s-root` `iptables-detect.sh`](https://github.com/k3s-io/k3s-root/blob/master/iptables-detect/iptables-detect.sh) | The selection of `nft` and the variable `IPTABLES_MODE`. |
| [Kubernetes sysctl documentation](https://kubernetes.io/docs/tasks/administer-cluster/sysctl-cluster/) | The list of safe sysctls. |
| [Linux `wireguard` netlink API](https://github.com/torvalds/linux/blob/master/include/uapi/linux/wireguard.h) | The WireGuard generic netlink commands and attributes. |
| [Linux `if_link.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_link.h) | The VXLAN link attributes. |
| [Linux CFS bandwidth control](https://docs.kernel.org/scheduler/sched-bwc.html) | The semantics of `cpu.max` and `cpu.stat`. |
