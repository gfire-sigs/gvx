# Driverless Networking Backend: `netbackend` and Guest Overlays

This specification describes `pkg/netbackend` alongside guest overlay packages `pkg/tcpip/link/vxlan`, `pkg/tcpip/link/wgtun`, `pkg/ipset`, and `pkg/sentry/socket/netlink/genetlink`. Together they provide unprivileged networking, port forwarding, DNS relay, bandwidth shaping, host firewalling, and Kubernetes-grade guest overlays.

---

## 1. Purpose and Scope

Guest containers expect full Linux networking, including raw sockets, bridges, legacy `iptables`, VXLAN, and WireGuard interfaces. Standard host virtual-network drivers require administrator rights or kernel extensions that break single-process sandboxing.

`pkg/netbackend` attaches gVisor's pure-Go `pkg/tcpip` (Netstack) directly to unprivileged host sockets or an in-memory `wireguard-go` endpoint. All guest packet switching, NAT state tracking, and netfilter chains execute inside Go memory without host TUN devices.

The table below contrasts the two driverless attachment tracks supported by `netbackend`.

| Attribute | Track A: NAT and Port Forwarder (`-net=nat`, default) | Track B: In-Memory WireGuard (`-net=wg`) |
| :--- | :--- | :--- |
| **Attachment layer** | L2 in-memory `pipe` link to a peer host Netstack (`tcp.NewForwarder`, `udp.NewForwarder`) | L3 `wgtun.Endpoint` directly attached to `wireguard-go` in memory |
| **Host transport** | Unprivileged host Go `net` sockets (IOCP, `kqueue`, `epoll`) | One pre-bound unprivileged host UDP socket (`:0`) |
| **Host/LAN reachability** | Permitted by default (`10.0.2.2` maps to `127.0.0.1`; optional `-isolate-lan`) | Cryptographically isolated; all egress exits via WireGuard |
| **Inbound exposure** | Static `-p` (TCP, UDP, ranges up to 1,024, `unix:`), `--auto-publish`, `port add`, `port-forward` | Tunnel peers only |

---

## 2. Design and Invariants

![Dual-Track Netstack Backend](../assets/netbackend.svg)

### 2.1 Track A: L2-Bridged NAT Relay, MTU, and Error Translation

In `-net=nat` mode, guest `eth0` attaches via an in-memory `pipe` link to a promiscuous, spoofing peer Netstack representing the host network. Because raw Ethernet frames cross the pipe unchanged, guest bridges, network namespaces, and `iptables` NAT behave like Linux.

- **MTU rules**: Guest `eth0` starts at `1500` (`net.nat.mtu`; `lo` keeps `65,536`). Guests adjust MTU via netlink or `SIOCSIFMTU` (`68..65,535` NAT; `68..65,503` WireGuard Unix; `68..1,984` WireGuard Windows). Dropping MTU below `1280` strips IPv6 routes; macOS raises host UDP `SO_SNDBUF` to `128 KiB`.
- **Session ceilings**: NAT relays cap concurrent flows at `4,096` TCP connections (excess reset), `512` UDP sessions (`net.nat.udp_sessions`, oldest evicted), and `256` DNS flows.
- **TCP dial error translation**: The peer stack completes the guest TCP handshake only after the host dial succeeds (`net.nat.dial_timeout`). Host `ECONNREFUSED` sends RST; `EHOSTUNREACH`/`ENETUNREACH` emits ICMPv4 unreachable from `10.0.2.2` quoting the SYN header; dial timeouts drop silently for Linux SYN retries (~127 s).

### 2.2 Port Forwarder, `--auto-publish`, and DNS Relay

- **Inbound forwarding (`port_forwarder.go`, `dynamic_forwarder.go`)**: Static `-p` TCP, UDP, range, and `unix:` listeners bind before `hostlockdown.Apply()`. Host connections dial `10.0.2.15:GUEST`, falling back to `127.0.0.1:GUEST` on `lo`. `--auto-publish` polls guest listeners and `DNAT` rules every `net.forward.dynamic_poll_interval` (`200 ms`) onto `127.0.0.1` (`64` ports max).
- **DNS relay (`dns_relay.go`)**: Answers UDP and TCP queries to `10.0.2.3:53` in `-net=nat` and `-net=wg`. Before lockdown, it collects `/etc/resolv.conf` (falling back to `/run/systemd/resolve/resolv.conf`) or `--host-dns` servers. It randomizes query IDs, caps concurrency at 64, retries truncated UDP via TCP, and answers internal names. Without an IPv6 route on `eth0`, it returns empty `NOERROR` for external `AAAA` queries.

### 2.3 Bandwidth Shaping and Host NAT Policy

Each sandbox owns one transmit and one receive token bucket (`--net-tx-bps`, `--net-rx-bps`; 256 KiB burst per direction) shared across NAT, DNS, and tunnels. Stream relays throttle while full packet queues drop, and bucket state stays excluded from checkpoints.

An immutable host NAT firewall policy (`--nat-policy-file`, `.json`/`.yaml`/`.yml`; 64 KiB max; 1,024 rules per direction) filters IPv4 and IPv6 traffic outside the guest. `net.policy_set` replaces the active policy and drops newly denied relays. Protected checkpoints require a policy file on restore, `-isolate-lan` overrides `allow`, and NAT dials to the sandbox's TCP control listener fail.

### 2.4 Track B: WireGuard (`-net=wg`) and In-Guest Overlay Primitives

In `-net=wg` mode, `wireguard_endpoint.go` links `pkg/tcpip/link/wgtun.Endpoint` (default MTU `1420`, 16-packet batching, `Suspend`/`Resume` hooks) directly to `wireguard-go` over one pre-bound host UDP socket.

Inside the guest kernel, `gvx` implements the full overlay stack required by `dockerd`, Flannel, and Calico:

- **In-guest `wireguard` links (`genetlink/wireguard`)**: `RTM_NEWLINK` kind `wireguard` over `NETLINK_GENERIC` shares `wgtun.Endpoint` and supports `fwmark` and netns moves. Memory charges (`64 KiB + 48 KiB/CPU` per link, `32 KiB` per peer) bill to per-sandbox accounting.
- **In-guest `vxlan` links (`pkg/tcpip/link/vxlan`)**: RFC 7348 Ethernet encapsulation with flow-hashed UDP source ports, FDB learning (300 s ageing), `IFLA_VXLAN_LIMIT` (`maxaddr`), and `AF_BRIDGE` netlink FDB control.
- **IP sets (`pkg/ipset`)**: Implements `hash:ip`, `hash:net`, `hash:ip,port`, `hash:net,port`, `hash:ip,port,ip`, `hash:ip,port,net`, `hash:net,net`, `bitmap:port`, and `list:set` over `NETLINK_NETFILTER` plus `-m set`/`-j SET`.

---

## 3. Component Limits

Consult [`../compatibility.md`](../compatibility.md) for host-wide limits; the invariants below apply specifically to `netbackend` and overlays:

- **No IPv6 ICMP unreachable synthesis**: Unreachable IPv6 NAT dials time out rather than emitting ICMPv6 errors.
- **Windows WireGuard MTU cap**: `eth0` in `-net=wg` mode caps at `1,984` bytes on Windows.
- **Policy and `StreamInterceptor` interaction**: Go SDK bandwidth limits and NAT policies cannot combine with a custom `Config.StreamInterceptor`.
- **Unbounded default VXLAN FDB**: Without `maxaddr`, 200,000 FDB entries consume roughly 38 MB (~190 bytes/entry); set `maxaddr` or `-m` for untrusted guests.
- **Guest WireGuard source selection and link-local IPv6**: Replies use the route-selected source address, and IPv6 endpoints drop `sin6_scope_id`.

---

## 4. Implementation Map

This table maps the networking packages, implementation files, and test suites.

| Package and Files | Role |
| :--- | :--- |
| `pkg/netbackend/` (`nat_forwarder.go`, `udp_sessions.go`, `tcp_dial_answer*.go`, `udp_sendbuf*.go`, `stack_options.go`) | Track A NAT relay, UDP table, Linux dial-error synthesis, macOS send-buffer raise. |
| `pkg/netbackend/` (`port_forwarder.go`, `dynamic_forwarder.go`, `dynamic_control.go`, `dns_relay.go`, `dns_servers_*.go`) | Static `-p`, `--auto-publish`, runtime `port add/rm`, DNS relay and resolver discovery. |
| `pkg/netbackend/` (`bandwidth.go`, `nat_bandwidth_packets.go`, `nat_policy.go`, `nat_policy_packets.go`) | Per-sandbox token buckets and immutable host NAT firewall policy. |
| `pkg/netbackend/` (`wireguard_endpoint.go`, `wireguard_bind.go`, `wireguard_tun.go`) & `pkg/tcpip/link/wgtun/` | Track B `-net=wg` tunnel and shared `wireguard-go` link endpoint. |
| `pkg/tcpip/link/vxlan/`, `pkg/ipset/`, `pkg/sentry/socket/netlink/genetlink/` | Guest VXLAN device, IP sets, Generic Netlink router, and in-guest WireGuard family. |
| Tests | `pkg/netbackend/*_test.go`, `pkg/ipset/*_test.go`, `e2e/nat_*`, `e2e/wireguard_*`, `e2e/vxlan_*`, `e2e/ipset_*`. |
