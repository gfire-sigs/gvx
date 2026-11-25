# Running Kubernetes (`k3s`) Inside gvx

This guide explains how to boot an unmodified `rancher/k3s` node inside a `gvx` sandbox, either as a standalone cluster or as a multi-node cluster with Flannel WireGuard or Calico VXLAN networking. `gvx` supplies the Linux kernel interfaces expected by `k3s`, `kubelet`, `containerd`, `runc`, `flannel`, and Calico without Kubernetes-specific flags. Consult [`../troubleshooting.md`](../troubleshooting.md#5-kubernetes-k3s-failures) if a node fails to reach `Ready`.

The commands below pin `rancher/k3s:v1.31.4-k3s1` and Calico `v3.28.2` because those exact artifacts are pinned and continuously verified by `e2e/k3s_e2e_test.go` and `internal/acceptprog/k8stools.go`. Newer `k3s` or Calico releases that honor `IPTABLES_MODE=legacy` and `FELIX_IPTABLESBACKEND=Legacy` may also run, though CI pins the versions shown here.

---

## 1. Architecture of a Node

`rungv` executes the official `rancher/k3s` image. The table below summarizes the key arguments.

| Argument | Purpose |
| :--- | :--- |
| `-e IPTABLES_MODE=legacy` | Selects legacy `iptables`, because the Sentry guest kernel omits `nftables`. |
| `-v k3s:/var/lib/rancher` | Stores cluster state, images, and container layers in `k3s.ext4`, where `containerd`'s `overlayfs` snapshotter runs natively. |
| `-p 127.0.0.1:6443:6443` | Exposes the Kubernetes API server on host loopback. |
| `--write-kubeconfig` | Writes the cluster kubeconfig into a bind-mounted host directory for the host `kubectl`. |
| `--hostname` | Sets a unique Kubernetes node name. |
| `-m` and `--cpus` | Set reported node capacity (`MemTotal` and online CPU count). |

Because host self-lockdown seals socket binds at startup, publish static ports such as `6443`, UDP `51820`, or a NodePort range with `-p`. For dynamic local TCP NodePorts, you may also pass `--auto-publish`.

---

## 2. Starting a Single-Node Cluster

These steps start a single-node `k3s` server and connect the host `kubectl` on macOS, Windows, or Linux.

> [!IMPORTANT]
> Confirm that host ports `6443` and `30000` through `30019` are unused. `rungv` exits with `address already in use` if any static `-p` port is occupied.

1. Create a host directory to receive `kubeconfig.yaml`.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the `k3s` server in the foreground.

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

3. Wait for `k3s is up and running` in the terminal log.

4. Point `kubectl` at the generated kubeconfig in a second terminal.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   ```

5. Verify that the node reaches `Ready`.

   ```sh
   kubectl get nodes
   ```

   Expected status: `Ready`. Any `NodePort` Service on ports `30000` to `30019` is now reachable on host `127.0.0.1:<port>`.

---

## 3. Starting a Two-Node Cluster

These steps run a `k3s` server and a `k3s` agent in two separate sandboxes on one host. The agent connects to the server via the host gateway (`10.0.2.2`), and `flannel` transports cross-node pod traffic over WireGuard on UDP port `51820`.

> [!IMPORTANT]
> Stop the single-node server from Section 2 before starting the two-node server, as both bind host port `6443`.

1. Create the host directory for `kubeconfig.yaml`.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the server sandbox (replace `my-token` with a chosen secret).

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

4. Start the agent sandbox in a second terminal using the same token.

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

5. Point `kubectl` at the kubeconfig in a third terminal and verify both nodes.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   kubectl get nodes
   ```

   Expected output: both `server` and `agent` report `Ready`.

The agent publishes no host ports; it initiates the WireGuard handshake so the server learns its endpoint automatically. Because `k3s agent` rejects `--flannel-external-ip`, `--node-external-ip 192.0.2.1` supplies a placeholder. `kubectl logs` and `kubectl exec` reach the agent through the `k3s` tunnel.

---

## 4. Using Calico VXLAN Instead of Flannel

Calico replaces Flannel and enforces Kubernetes `NetworkPolicy` using VXLAN encapsulation and legacy `iptables`. The guest kernel supplies the policy routing tables, route types, proxy ARP, `rpfilter` match, and `ipset` support required by Felix.

> [!IMPORTANT]
> Run `mount --make-rshared /` before launching `k3s`. `calico-node` requires a recursively shared `/sys/fs` mount; because the sandbox boots without systemd, this matches the startup sequence used by `kind`.

1. Download the pinned Calico `v3.28.2` VXLAN manifest and apply the two `k3s` adjustments (`CALICO_IPV4POOL_CIDR=10.42.0.0/16` and `FELIX_IPTABLESBACKEND=Legacy`).

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

2. Verify that both entries appear in `~/.gvx/k3s/calico.yaml`.

   ```sh
   grep -n -A1 -E 'CALICO_IPV4POOL_CIDR|FELIX_IPTABLESBACKEND' ~/.gvx/k3s/calico.yaml
   ```

3. Start the server; the shell wrapper marks `/` recursively shared and installs `calico.yaml` into `k3s`'s auto-deploy manifest directory.

   ```sh
   rungv run \
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

4. Wait until Calico pods reach `Ready`.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   kubectl -n kube-system get pods
   ```

`TestE2EK3sCalico` automates this sequence and verifies pod readiness, `coredns`, pod IP assignment, pod-to-pod and ClusterIP traffic, deny-all `NetworkPolicy`, and label-scoped allow rules.

---

## 5. Reference: Verified Behavior and Known Limits

The tables below summarize automated test coverage and architectural limits for Kubernetes nodes on `gvx`.

### 5.1 Verified Single-Node Behavior

`TestE2EK3sSingleNode` verifies the following behaviors across backends:

| Check | Verified Outcome |
| :--- | :--- |
| Node startup | Reaches `Ready` within 120 seconds. |
| System pods | `coredns`, `local-path-provisioner`, and `metrics-server` run. |
| Services | Multi-endpoint Services answer, hairpin pod-to-self calls succeed, and NodePorts answer from host and pods. |
| DNS recovery | Resolution recovers cleanly after restarting `coredns`. |
| Pod operations | `kubectl logs`, `kubectl exec`, and `kubectl port-forward` succeed. |
| Pod sysctls | `securityContext.sysctls` apply inside pods. |
| Resource limits | A `500m` CPU cap throttles a busy pod near 0.5 CPU; exceeding memory triggers `OOMKilled`. |
| Metrics | `kubectl top node` and `kubectl top pod` report live figures. |
| Restart persistence | The node resumes with the same name and restarts its pods from the `ext4lite` volume. |

`TestE2EK3sNetworkPolicy` verifies `k3s`'s built-in `kube-router` controller using guest `ipset` and `-m set`:

| Check | Verified Outcome |
| :--- | :--- |
| Controller startup | Starts cleanly without `ipset save failed` warnings. |
| Deny-all policy | Ingress deny-all `NetworkPolicy` blocks client pods from reaching the selected server pod. |
| Label allow policy | Adding an allow rule for a labeled client unblocks only that client. |
| Kernel state | Guest kernel holds `KUBE-*` IP sets and `-m set --match-set` rules; deleting policies restores traffic. |

`TestE2EK3sCalico` verifies Calico `v3.28.2` VXLAN mode (Section 4):

| Check | Verified Outcome |
| :--- | :--- |
| Pod readiness | `calico-node`, `calico-kube-controllers`, and `coredns` reach `Ready`. |
| Addressing and traffic | Pods receive `10.42.0.0/16` addresses and communicate directly and via ClusterIP and DNS. |
| `NetworkPolicy` | Deny-all blocks direct and ClusterIP traffic; label-scoped allow permits only matching clients; deletion restores traffic. |

### 5.2 Verified Multi-Node Behavior

`e2e/k3s_multinode_e2e_test.go`, `e2e/k3s_wgmesh_e2e_test.go`, and `e2e/k3s_conformance_e2e_test.go` exercise unmodified images on one host (supplying Alpine's `wg`, `etcdctl`, and `sonobuoy` binaries where needed):

| Suite | Topology | Verified Outcome |
| :--- | :--- | :--- |
| C1 | Section 3: agent joins through published API port with `flannel` `wireguard-native` | Both nodes reach `Ready`; cross-node pod traffic, multi-endpoint Services, DNS, `kubectl logs`, and `kubectl exec` pass. |
| C2 | Direct `wg0` WireGuard mesh (`--flannel-iface wg0`, `--egress-selector-mode disabled`) | All C1 checks pass; API server reaches agent kubelet directly over `wg0`. |
| C3 | `gvx` agent joins a native Linux `k3s` server | All C1 checks pass. |
| C4 | Three-server HA cluster with embedded `etcd` over `wg0` mesh | Cluster survives `etcd` leader loss and accepts writes within 30 s (measured 5 to 9 s). |
| C5 | `sonobuoy` with the `e2e` plugin | `Quick` mode and `[sig-network] Services` pass. |

### 5.3 Known Limits

| Limit | Practical Effect |
| :--- | :--- |
| `nftables` | Set `IPTABLES_MODE=legacy`; components requiring `iptables-nft` fail. |
| Calico modes | Verified only with VXLAN and legacy `iptables` (`FELIX_IPTABLESBACKEND=Legacy`). eBPF and BIRD BGP are untested; Felix emits non-fatal XDP/BPF warnings and continues. |
| `NFLOG` | `-j NFLOG` rules are accepted and saved, but no listener receives logged packets. |
| IPVS, eBPF, and kernel modules | `kube-proxy` must run in `iptables` mode; eBPF-based CNIs such as Cilium cannot run. |
| Memory limits | Enforced by Sentry polling, so sub-interval spikes can escape detection (see [`docker-engine.md`](docker-engine.md#74-memory-limits-of-containers)). |
| Windows `systrap` | Supported; stub working-set queries report pod memory metrics and enforce `memory.max`. |
| Link MTU | `eth0` starts at `1500` (`flannel` derives `1450` for VXLAN and `1420` for WireGuard). Adjust via `--tune net.nat.mtu=N` or `ip link set dev eth0 mtu N` (`68` to `65535`). |
| WireGuard reply address | A guest `wireguard` interface replies from the route-selected source IP rather than the destination IP the peer addressed. |
| WireGuard link-local IPv6 | IPv6 endpoints drop `sin6_scope_id`; use global addresses. |
| Neighbor and VXLAN tables | Static neighbors and VXLAN FDB entries are unbounded by default (set `maxaddr` on untrusted VXLAN links). Dynamic neighbors obey per-namespace `gc_thresh1..3` (`128`, `512`, `1024`; `gc_thresh1` is stored only). |
| `xt_recent` module parameters | Root may write `ip_list_tot` and `ip_pkt_list_tot` only before any `recent` rule exists; later writes fail with `EINVAL`. |
| Connection tracking | `/proc/sys/net/netfilter` controls protocol timeouts and `nf_conntrack_max` (default `262144`, writable in root netns only; `nf_conntrack_buckets` is read-only `16384`). When full, expired or unassured entries evict first before new flows drop. |

---

## 6. Troubleshooting

If a node remains `NotReady`, Calico pods crash, or ports conflict, consult [`../troubleshooting.md`](../troubleshooting.md#5-kubernetes-k3s-failures). Re-run `rungv` with `GVX_DEBUG_LOG=1` to inspect Sentry kernel diagnostics alongside `k3s` logs.
