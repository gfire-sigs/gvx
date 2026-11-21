# Run a Kubernetes Node with `gvx`

This guide shows how to run an unmodified `k3s` node inside a `gvx` sandbox, either as a single-node cluster or as part of a multi-node cluster. `gvx` supplies the Linux kernel behavior that `k3s`, `kubelet`, `containerd`, `runc`, `flannel`, and Calico CNI expect without any Kubernetes-specific flags.

## 1. How It Works

`rungv` runs the official `rancher/k3s` image. The table lists the key settings for a node.

| Part | What it does |
| :--- | :--- |
| `IPTABLES_MODE=legacy` | Forces `k3s` to use legacy `iptables` because the guest has no `nftables`. |
| `-v k3s:/var/lib/rancher` | Persists cluster state, images, and containers in `k3s.ext4`, where `containerd`'s `overlayfs` snapshotter runs natively. |
| `-p 127.0.0.1:6443:6443` | Publishes the Kubernetes API server to host loopback. |
| `--write-kubeconfig` | Writes the cluster kubeconfig into a bind-mounted host directory for your host `kubectl`. |
| `--hostname` | Sets the Kubernetes node name (must be unique per node). |
| `-m` and `--cpus` | Set reported node capacity (`MemTotal` and online CPUs). |

By default, the sandbox locks itself down before startup, so publish static ports like `6443`, UDP `51820`, or a NodePort range with `-p`. For local TCP NodePorts, you can also pass `--auto-publish` to bind guest listeners and `DNAT` ports on host `127.0.0.1` automatically.

## 2. Start a Single-Node Cluster

These steps boot a `k3s` server and connect your host `kubectl`. They work on macOS, Windows, and Linux.

> [!IMPORTANT]
> Pick unused host ports. `rungv` exits with `address already in use` if any static `-p` port is busy.

1. Create a host directory for the kubeconfig.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the server in the foreground.

   ```sh
   rungv run \
     -e IPTABLES_MODE=legacy \
     -p 127.0.0.1:6443:6443 \
     -p 127.0.0.1:30000-30019:30000-30019 \
     -v k3s:/var/lib/rancher \
     --mount type=bind,src=$HOME/.gvx/k3s,dst=/output \
     rancher/k3s:v1.31.4-k3s1 server \
     --disable=traefik,servicelb \
     --write-kubeconfig=/output/kubeconfig.yaml \
     --write-kubeconfig-mode=644
   ```

3. Wait for `k3s is up and running`.

4. Point `kubectl` at the cluster in a second terminal.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   ```

5. Verify the node status.

   ```sh
   kubectl get nodes
   ```

   The node shows `Ready`.

Any `NodePort` Service using ports `30000` to `30019` is now reachable on host `127.0.0.1:<port>`.

## 3. Start a Two-Node Cluster

These steps run a server and an agent in two sandboxes on one host. The agent connects to the server through the host's published port at `10.0.2.2`, and `flannel` carries inter-node pod traffic over WireGuard on UDP port `51820`.

> [!IMPORTANT]
> Stop the single-node server from Section 2 first, because both setups bind host port `6443`.

1. Create a host directory for the kubeconfig.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the server in the foreground (replace `my-token` with your own secret).

   ```sh
   rungv run \
     -e IPTABLES_MODE=legacy \
     --hostname server \
     -p 127.0.0.1:6443:6443 \
     -p 127.0.0.1:51820:51820/udp \
     -v k3s-server:/var/lib/rancher \
     --mount type=bind,src=$HOME/.gvx/k3s,dst=/output \
     rancher/k3s:v1.31.4-k3s1 server \
     --token my-token \
     --tls-san 10.0.2.2 \
     --advertise-address 10.0.2.2 \
     --advertise-port 6443 \
     --node-external-ip 10.0.2.2 \
     --flannel-backend=wireguard-native \
     --flannel-external-ip \
     --disable=traefik,servicelb \
     --write-kubeconfig=/output/kubeconfig.yaml \
     --write-kubeconfig-mode=644
   ```

3. Wait for `k3s is up and running`.

4. Start the agent in a second terminal using the same token.

   ```sh
   rungv run \
     -e IPTABLES_MODE=legacy \
     --hostname agent \
     -v k3s-agent:/var/lib/rancher \
     rancher/k3s:v1.31.4-k3s1 agent \
     --server https://10.0.2.2:6443 \
     --token my-token \
     --node-external-ip 192.0.2.1
   ```

5. Point `kubectl` at the cluster in a third terminal.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   ```

6. Verify both nodes.

   ```sh
   kubectl get nodes
   ```

   Both nodes show `Ready`.

The agent publishes no ports; it initiates the WireGuard handshake so the server learns the agent's endpoint. `k3s agent` rejects `--flannel-external-ip`, so `--node-external-ip 192.0.2.1` acts as a placeholder. Both nodes report internal address `10.0.2.15`, and `kubectl logs` and `kubectl exec` reach the agent through the `k3s` tunnel.

## 4. Run Calico Instead of flannel

Calico replaces `flannel` and enforces `NetworkPolicy` using VXLAN mode with legacy `iptables`. The guest kernel provides the policy routing rules, route types, proxy ARP, `rpfilter` match, and `ipset` tables that Felix requires.

> [!IMPORTANT]
> Run `mount --make-rshared /` before starting `k3s`. `calico-node` requires a shared `/sys/fs` mount; because the sandbox has no systemd init, this matches what `kind` does at startup.

1. Download `calico-vxlan.yaml` from Calico v3.28.2.
2. In the manifest, set `CALICO_IPV4POOL_CIDR` to `10.42.0.0/16` and add `FELIX_IPTABLESBACKEND=Legacy` to `calico-node`.
3. Save the manifest as `calico.yaml` in `$HOME/.gvx/k3s` (mounted at `/output`).
4. Start the server; the shell wrapper copies `calico.yaml` into the `k3s` manifest directory.

   ```sh
   rungv run \
     -e IPTABLES_MODE=legacy \
     -p 127.0.0.1:6443:6443 \
     -v k3s:/var/lib/rancher \
     --mount type=bind,src=$HOME/.gvx/k3s,dst=/output \
     --entrypoint /bin/sh \
     rancher/k3s:v1.31.4-k3s1 -c '
       mount --make-rshared /
       mkdir -p /var/lib/rancher/k3s/server/manifests
       cp /output/calico.yaml /var/lib/rancher/k3s/server/manifests/calico.yaml
       exec k3s server --flannel-backend=none --disable-network-policy \
         --cluster-cidr=10.42.0.0/16 --disable=traefik,servicelb \
         --write-kubeconfig=/output/kubeconfig.yaml --write-kubeconfig-mode=644'
   ```

5. Wait until `kubectl -n kube-system get pods` reports `calico-node` and `calico-kube-controllers` as `Ready`.

`TestE2EK3sCalico` automates these steps and verifies Ready pods, `coredns`, pod IPs, pod-to-pod and pod-to-service traffic, a deny-all `NetworkPolicy`, and an allow policy.

## 5. Reference

The tables below summarize verified test coverage and known limits for `gvx` Kubernetes nodes.

### 5.1 Verified Single-Node Behavior

`TestE2EK3sSingleNode` verifies these behaviors on each backend.

| Check | Result |
| :--- | :--- |
| Node start | `Ready` within 120 seconds |
| System pods | `coredns`, `local-path-provisioner`, and `metrics-server` run |
| Services | Multi-endpoint services answer, a pod reaches its own backing service, and NodePorts answer from the host and from pods |
| DNS | Resolution recovers after restarting `coredns` |
| Pod access | `kubectl logs`, `kubectl exec`, and `kubectl port-forward` work |
| Pod sysctls | `securityContext.sysctls` apply inside containers |
| Limits | A `500m` CPU limit caps a busy pod near `0.5` CPU; exceeding a memory limit triggers `OOMKilled` |
| Metrics | `kubectl top node` and `kubectl top pod` report live values |
| Restart | The node returns with the same name and restarts its pods |

`TestE2EK3sNetworkPolicy` verifies `k3s`'s built-in `kube-router` network policy controller using guest `ipset` and `-m set`.

| Check | Result |
| :--- | :--- |
| Controller start | `k3s` does not log `Skipping network policy controller start, ipset save failed` |
| Deny all | An ingress deny-all `NetworkPolicy` blocks client pods from reaching the selected server pod |
| Allow by label | Adding an allow policy for a labeled client unblocks only that client |
| Sets and rules | The guest kernel holds `KUBE-*` IP sets and `-m set --match-set` rules |
| Policy removal | Traffic resumes once policies are deleted |

`TestE2EK3sCalico` runs `k3s` with Calico 3.28.2 in VXLAN mode (see Section 4).

| Check | Result |
| :--- | :--- |
| Calico start | `calico-node` and `calico-kube-controllers` become `Ready`, and `coredns` runs |
| Addresses | Pods receive IPs from Calico's `10.42.0.0/16` pool |
| Traffic | Pods reach other pods and services by ClusterIP and DNS name |
| Deny all | A deny-all `NetworkPolicy` blocks clients directly and via ClusterIP |
| Allow by label | A labeled allow policy admits only matching clients |
| Policy removal | Traffic resumes once policies are deleted |

### 5.2 Verified Multi-Node Behavior

Tests in `e2e/k3s_multinode_e2e_test.go`, `e2e/k3s_wgmesh_e2e_test.go`, and `e2e/k3s_conformance_e2e_test.go` run unmodified images on one host with no `gvx`-specific options (copying Alpine's `wg` binary for C2/C4, `etcdctl` for C4, and `sonobuoy` for C5).

| Test | Topology | Result |
| :--- | :--- | :--- |
| C1 | Section 3: agent joins through the published API port with `flannel` `wireguard-native` | Both nodes become `Ready`; cross-node pod traffic, multi-endpoint services, DNS, `kubectl logs`, and `kubectl exec` pass. |
| C2 | Direct `wg0` WireGuard mesh between guests (`--flannel-iface wg0`, `--egress-selector-mode disabled`) | All C1 checks pass, and the API server reaches the agent kubelet directly over `wg0`. |
| C3 | A `gvx` agent joins a native Linux `k3s` server | All C1 checks pass. |
| C4 | Three-server HA cluster with embedded `etcd` over the `wg0` mesh | Cluster survives `etcd` leader loss; a surviving server accepts writes within 30 s (measured 5 to 9 s). |
| C5 | `sonobuoy` with the `e2e` plugin | `Quick` mode and `[sig-network] Services` pass. |

### 5.3 Known Limits

These limits stem from the user-space guest kernel.

| Limit | Effect |
| :--- | :--- |
| `nftables` | Set `IPTABLES_MODE=legacy`; components requiring `iptables-nft` fail. |
| Calico | Verified in VXLAN mode with legacy `iptables` (`IPTABLES_MODE=legacy`, `FELIX_IPTABLESBACKEND=Legacy`). eBPF and BIRD BGP are untested; Felix logs non-fatal XDP/BPF warnings and continues. |
| NFLOG | `-j NFLOG` accepts rules, but no listener receives packets. |
| IPVS, eBPF, and kernel modules | `kube-proxy` must use `iptables` mode; eBPF-based CNIs like Cilium cannot run. |
| Memory limits | The Sentry enforces `memory.max` by polling, so sub-interval spikes can escape detection (see [`docker-engine.md`](docker-engine.md) Section 7.4). |
| Windows `systrap` | Supported. The Sentry queries stub working sets during scans and unmaps so pod memory metrics and `memory.max` match Linux. |
| MTU | `eth0` starts at `1500`, so `flannel` uses `1450` (VXLAN) and `1420` (WireGuard). Override with `--tune net.nat.mtu=N` or `ip link set dev eth0 mtu N` (`68` to `65535`). |
| WireGuard reply address | A `wireguard` interface replies from the route-selected source IP rather than the destination IP the peer sent to (matters on multi-address interfaces). |
| WireGuard link-local endpoints | IPv6 endpoints drop `sin6_scope_id`; use global addresses. |
| Neighbor table | Static neighbors and VXLAN FDB entries are unbounded (as on Linux). Dynamic neighbors use per-namespace `gc_thresh1..3` (`128`, `512`, `1024`; `gc_thresh1` is a no-op). Set `maxaddr` on a VXLAN link to bound its FDB. |
| `xt_recent` parameters | Root can write `ip_list_tot` and `ip_pkt_list_tot` only before any `recent` rule exists (write them before `kube-proxy` starts; later writes return `EINVAL`). |
| Connection tracking | `/proc/sys/net/netfilter` controls TCP, UDP, ICMP, and ICMPv6 timeouts plus `nf_conntrack_max` (default `262144`, writable in root netns only). When full, timed-out or unassured entries evict first; otherwise new flows drop. `kube-proxy` updates `nf_conntrack_max` and TCP timeouts at startup. `nf_conntrack_buckets` is read-only (`16384`). |
