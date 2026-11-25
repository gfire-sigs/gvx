# Running Kubernetes (`k3s`) Inside gvx

This guide shows how to boot an unmodified `rancher/k3s` node inside a `gvx` sandbox as a single-node or multi-node cluster. Supported topologies cover Flannel WireGuard and Calico VXLAN networking.

`gvx` provides the Linux kernel interfaces expected by `k3s`, `kubelet`, `containerd`, `runc`, Flannel, and Calico without Kubernetes-specific flags. Cluster state persists inside an `ext4lite` volume while `kubectl` communicates over host loopback `127.0.0.1:6443`.

The commands below pin `rancher/k3s:v1.31.4-k3s1` and Calico `v3.28.2` matching CI verification; consult [`../troubleshooting.md`](../troubleshooting.md#5-kubernetes-k3s-failures) if a node stays `NotReady`.

## 1. Architecture of a Node

`rungvx` executes the official `rancher/k3s` image. The table below summarizes the key arguments.

| Argument | Purpose |
| :--- | :--- |
| `-e IPTABLES_MODE=legacy` | Selects legacy `iptables`, because the Sentry guest kernel omits `nftables`. |
| `-v k3s:/var/lib/rancher` | Stores cluster state, images, and container layers in `k3s.ext4` for `containerd`'s `overlayfs` snapshotter. |
| `-p 127.0.0.1:6443:6443` | Exposes the Kubernetes API server on host loopback. |
| `--write-kubeconfig` | Writes the cluster kubeconfig into a bind-mounted host directory for host `kubectl`. |
| `--hostname` | Sets a unique Kubernetes node name. |
| `-m` and `--cpus` | Set reported node capacity (`MemTotal` and online CPU count). |

Because host self-lockdown seals socket binds at startup, publish static ports such as `6443`, UDP `51820`, or a NodePort range with `-p`. For dynamic local TCP NodePorts, pass `--auto-publish`.

## 2. Starting a Single-Node Cluster

These steps start a single-node `k3s` server and attach host `kubectl` on macOS, Windows, or Linux.

> [!IMPORTANT]
> Confirm that host ports `6443` and `30000` through `30019` are unused. `rungvx` exits immediately with `address already in use` if any `-p` port is occupied.

1. Create a host directory for `kubeconfig.yaml`.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the `k3s` server in the foreground.

   ```sh
   rungvx run \
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

3. Wait for `k3s is up and running` in the terminal log.

4. Export `KUBECONFIG` in a second terminal.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   ```

5. Verify that the node reaches `Ready`.

   ```sh
   kubectl get nodes
   ```

   Expected status: `Ready`. Any `NodePort` Service on ports `30000` to `30019` answers on host `127.0.0.1:<port>`.

## 3. Starting a Two-Node Cluster

These steps run a `k3s` server and a `k3s` agent in two sandboxes on one host. The agent connects via the host gateway (`10.0.2.2`), while Flannel transports cross-node pod traffic over WireGuard UDP port `51820`.

> [!IMPORTANT]
> Stop the single-node server from Section 2 before starting the two-node server. Both servers bind host port `6443`.

1. Create the host directory for `kubeconfig.yaml`.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the server sandbox (replace `my-token` with a secret).

   ```sh
   rungvx run \
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

4. Start the agent sandbox in a second terminal with the same token.

   ```sh
   rungvx run \
     -e IPTABLES_MODE=legacy \
     --hostname agent \
     -v k3s-agent:/var/lib/rancher \
     rancher/k3s:v1.31.4-k3s1 agent \
     --server https://10.0.2.2:6443 \
     --token my-token \
     --node-external-ip 192.0.2.1
   ```

5. Export `KUBECONFIG` in a third terminal and list both nodes.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   kubectl get nodes
   ```

   Expected output: both `server` and `agent` report `Ready`.

The agent publishes no host ports; it initiates the WireGuard handshake so the server learns its endpoint. Because `k3s agent` rejects `--flannel-external-ip`, `--node-external-ip 192.0.2.1` provides a placeholder. `kubectl logs` and `kubectl exec` reach the agent through the `k3s` tunnel.

## 4. Using Calico VXLAN Instead of Flannel

Calico replaces Flannel and enforces `NetworkPolicy` using VXLAN encapsulation and legacy `iptables`. The guest kernel implements the policy routing tables, route types, proxy ARP, `rpfilter` match, and `ipset` tables required by Felix.

> [!IMPORTANT]
> Run `mount --make-rshared /` before launching `k3s`. `calico-node` requires a recursively shared `/sys/fs` mount because the sandbox boots without systemd.

1. Download the pinned Calico `v3.28.2` manifest and apply the `k3s` adjustments.

   ```sh
   mkdir -p ~/.gvx/k3s
   curl -fsSL https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico-vxlan.yaml \
     | awk '
         /^[[:space:]]*# - name: CALICO_IPV4POOL_CIDR$/ {
           print "            - name: CALICO_IPV4POOL_CIDR"
           getline
           print "              value: \"10.42.0.0/16\""
           next
         }
         /^[[:space:]]*- name: CLUSTER_TYPE$/ {
           print "            - name: FELIX_IPTABLESBACKEND"
           print "              value: \"Legacy\""
         }
         { print }
       ' > ~/.gvx/k3s/calico.yaml
   ```

2. Verify both entries in `~/.gvx/k3s/calico.yaml`.

   ```sh
   grep -n -A1 -E 'CALICO_IPV4POOL_CIDR|FELIX_IPTABLESBACKEND' ~/.gvx/k3s/calico.yaml
   ```

3. Start the server, mark `/` shared, and copy `calico.yaml` into the manifest directory.

   ```sh
   rungvx run \
     -e IPTABLES_MODE=legacy \
     -p 127.0.0.1:6443:6443 \
     -v k3s-calico:/var/lib/rancher \
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

4. Wait until all Calico pods reach `Ready`.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   kubectl -n kube-system get pods
   ```

`TestE2EK3sCalico` automates this flow and verifies pods, `coredns`, direct and ClusterIP traffic, and deny/allow `NetworkPolicy` rules.

## 5. Reference: Verified Behavior and Known Limits

These tables summarize automated Kubernetes verification and platform boundaries on `gvx`.

### 5.1 Verified Single-Node Behavior

`TestE2EK3sSingleNode`, `TestE2EK3sNetworkPolicy`, and `TestE2EK3sCalico` verify single-node `k3s`, built-in `kube-router` policies, and Calico VXLAN.

| Area | Verified Outcome |
| :--- | :--- |
| Node startup | Reaches `Ready` within 120 seconds. |
| System pods | `coredns`, `local-path-provisioner`, and `metrics-server` run. |
| Services | Multi-endpoint Services, hairpin calls, and NodePorts answer from host and pods. |
| DNS recovery | Resolution recovers after restarting `coredns`. |
| Pod operations | `kubectl logs`, `kubectl exec`, and `kubectl port-forward` succeed. |
| Pod sysctls | `securityContext.sysctls` apply inside pods. |
| Resource limits | `500m` CPU throttles near 0.5 CPU; exceeding memory triggers `OOMKilled`. |
| Metrics and persistence | `kubectl top` reports live figures; nodes restart pods from `ext4lite`. |
| Built-in `NetworkPolicy` | `kube-router` starts without `ipset save failed` warnings and enforces deny-all and label rules. |
| Calico VXLAN | `calico-node` and controllers reach `Ready`, assign `10.42.0.0/16`, and enforce `NetworkPolicy`. |

### 5.2 Verified Multi-Node Behavior

Multi-node and conformance suites (`e2e/k3s_multinode_e2e_test.go`, `e2e/k3s_wgmesh_e2e_test.go`, `e2e/k3s_conformance_e2e_test.go`) verify these cluster topologies.

| Topology | Verified Outcome |
| :--- | :--- |
| Two-node Flannel WireGuard (`k3s` agent via host gateway) | Both nodes reach `Ready`. Cross-node pods, Services, DNS, `logs`, and `exec` pass. |
| Direct `wg0` WireGuard mesh (`--flannel-iface wg0`) | All cross-node checks pass; API server reaches agent kubelet over `wg0`. |
| Hybrid `gvx` agent + native Linux `k3s` server | Agent joins native Linux control plane and passes cross-node pod and Service checks. |
| Three-server HA cluster with embedded `etcd` over `wg0` | Cluster survives `etcd` leader loss and accepts writes within 30 s (measured 5 to 9 s). |
| Kubernetes Conformance (`sonobuoy`) | `Quick` mode and `[sig-network] Services` pass. |

### 5.3 Known Limits

Consult [`../compatibility.md`](../compatibility.md) for host-wide limits; the items below apply directly to Kubernetes nodes on `gvx`.

| Limit | Practical Effect |
| :--- | :--- |
| `nftables` | Set `IPTABLES_MODE=legacy`; components requiring `iptables-nft` fail. |
| Calico modes | Only VXLAN with legacy `iptables` is verified. eBPF and BIRD BGP are untested; Felix logs non-fatal XDP warnings. |
| `NFLOG` | `-j NFLOG` rules are accepted and saved, while no listener receives logged packets. |
| IPVS, eBPF, and kernel modules | Run `kube-proxy` in `iptables` mode; eBPF CNIs such as Cilium fail. |
| Memory limits | Sentry polling enforces `memory.max`, so sub-interval spikes escape detection (see [`docker-engine.md`](docker-engine.md#74-memory-limits-of-containers)). |
| Windows `systrap` | Supported; stub working-set queries report pod memory metrics and enforce `memory.max`. |
| Link MTU | `eth0` starts at `1500` (`flannel` uses `1450` VXLAN, `1420` WireGuard). Override via `net.nat.mtu` or `ip link set`. |
| WireGuard reply source and IPv6 | Replies use the route-selected source IP. IPv6 endpoints drop `sin6_scope_id`; use global IPv6 addresses. |
| Neighbor and VXLAN tables | Static entries are unbounded unless `maxaddr` is set. Dynamic neighbors follow `gc_thresh1..3` (`128`, `512`, `1024`). |
| `xt_recent` parameters | Write `ip_list_tot` and `ip_pkt_list_tot` before creating `recent` rules; later writes return `EINVAL`. |
| Connection tracking | `/proc/sys/net/netfilter` configures timeouts and `nf_conntrack_max` (default `262144`). Full tables evict expired entries before dropping flows. |

## 6. Troubleshooting

If a node stays `NotReady`, Calico pods crash, or ports conflict, consult [`../troubleshooting.md`](../troubleshooting.md#5-kubernetes-k3s-failures). Re-run `rungvx` with `GVX_DEBUG_LOG=1` to inspect Sentry kernel diagnostics alongside `k3s` logs.
