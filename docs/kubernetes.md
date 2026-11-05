# Run a Kubernetes Node with `gvx`

This guide shows how to run an unmodified `k3s` node in a `gvx` sandbox: as a single-node cluster, or as a node of a cluster with several nodes. The sandbox provides the Linux kernel behavior that `k3s`, the `kubelet`, `containerd`, `runc`, and `flannel` use. `gvx` has no Kubernetes-specific option. [`gvxip/gvxip-005-kubernetes-node-compatibility.md`](gvxip/gvxip-005-kubernetes-node-compatibility.md) defines the behavior and its tests.

## 1. How It Works (Descriptive Module)

`rungv` runs the official `rancher/k3s` image. The guest kernel gives the node agent what it needs. The table lists the parts of a node and the settings that each part uses.

| Part | What it does |
| :--- | :--- |
| `IPTABLES_MODE=legacy` | Makes the `k3s` image use the legacy iptables. The guest has no `nftables`. |
| `-v k3s:/var/lib/rancher` | Stores the cluster state, the images, and the containers in the `ext4lite` image `k3s.ext4`. The `overlayfs` snapshotter of `containerd` works on it. |
| `-p 127.0.0.1:6443:6443` | Publishes the API server to the host. |
| `--write-kubeconfig` | Writes the kubeconfig of the cluster to a host directory, so `kubectl` on the host reaches the API server. |
| `--hostname` | Sets the node name. Each node of a cluster needs its own name. |
| `-m` and `--cpus` | Set the capacity that the node reports. `MemTotal` and the online CPUs follow these limits. |

The sandbox locks itself down before the guest starts. Publish every host port that the cluster needs, such as NodePorts and the WireGuard port, when you start the node.

## 2. Start a Single-Node Cluster (Procedural Module)

These steps start a `k3s` server and connect `kubectl` on the host to it. You need `rungv` and a `kubectl` command on the host. The steps work on macOS, Windows, and Linux.

> [!IMPORTANT]
> Use host ports that no other program uses. `rungv` stops with `address already in use` when a port is busy.

1. Create a directory for the kubeconfig.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the server in a terminal. It runs in the foreground.

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

3. Wait for the line `k3s is up and running`.

4. Point `kubectl` at the cluster in a second terminal.

   ```sh
   export KUBECONFIG=$HOME/.gvx/k3s/kubeconfig.yaml
   ```

5. Verify the node.

   ```sh
   kubectl get nodes
   ```

   The node shows the status `Ready`.

A Service of the type `NodePort` with a port from 30000 to 30019 is then reachable at `127.0.0.1:<port>` on the host.

## 3. Start a Cluster with Two Nodes (Procedural Module)

These steps start a server and an agent in two sandboxes on one host. The agent reaches the server through the published port on the host, which a guest sees at `10.0.2.2`. `flannel` carries the pod traffic between the nodes in WireGuard over the published UDP port 51820.

> [!IMPORTANT]
> Stop the single-node server of section 2 first. Both setups publish the host port 6443.

1. Create a directory for the kubeconfig.

   ```sh
   mkdir -p ~/.gvx/k3s
   ```

2. Start the server in a terminal. Replace `my-token` with a secret of your choice.

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

3. Wait for the line `k3s is up and running`.

4. Start the agent in a second terminal. Use the same token.

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

6. Verify the nodes.

   ```sh
   kubectl get nodes
   ```

   Both nodes show the status `Ready`.

The agent publishes no port. It starts the WireGuard handshake, so the server learns the endpoint of the agent. The agent needs `--node-external-ip` because `k3s agent` refuses `--flannel-external-ip`, and the address `192.0.2.1` is a placeholder. Both nodes show the internal address `10.0.2.15`. `kubectl logs` and `kubectl exec` reach the agent through the tunnel of `k3s`.

## 4. Reference

The tables below list the behavior that the tests prove and the limits of a `gvx` node.

### 4.1 Verified Behavior of a Single Node

The test `TestE2EK3sSingleNode` runs these checks on each backend.

| Check | Result |
| :--- | :--- |
| Node start | `Ready` within 120 seconds |
| System pods | `coredns`, `local-path-provisioner`, and `metrics-server` run |
| Services | Both endpoints of a service answer, a pod reaches a service whose only endpoint is that pod, and NodePorts answer from the host and from pods |
| DNS | Name resolution works again after a restart of `coredns` |
| Pod access | `kubectl logs`, `kubectl exec`, and `kubectl port-forward` work |
| Pod sysctls | `securityContext.sysctls` reach the container |
| Limits | A CPU limit of 500m holds a busy pod near 0.5 CPU; a pod above its memory limit ends with `OOMKilled` |
| Metrics | `kubectl top node` and `kubectl top pod` print values |
| Restart | The node returns with the same name after a restart, and its pods start again |

The test `TestE2EK3sNetworkPolicy` checks NetworkPolicy on each backend. The network policy controller of `k3s` (`kube-router`) needs the `ipset` tool and the iptables match `set`, and the guest provides both.

| Check | Result |
| :--- | :--- |
| Controller start | `k3s` does not log `Skipping network policy controller start, ipset save failed` |
| Deny all | A NetworkPolicy that selects a server pod and allows no ingress stops a client pod from reaching the server pod |
| Allow by label | A second policy that names the client label lets that client reach the server pod, and another client stays blocked |
| Sets and rules | The kernel of the guest holds the `KUBE-*` IP sets and a rule with `-m set --match-set` |
| Policy removal | Traffic returns after the policies end |

### 4.2 Verified Behavior of a Cluster

The tests in `e2e/k3s_multinode_e2e_test.go`, `e2e/k3s_wgmesh_e2e_test.go`, and `e2e/k3s_conformance_e2e_test.go` run their sandboxes on one host. The tests change no image and use no `gvx`-specific option. C2 and C4 copy the `wg` tool of Alpine into the guests, C4 copies `etcdctl`, and C5 copies `sonobuoy`.

| Test | Topology | Result |
| :--- | :--- | :--- |
| C1 | Section 3: the agent joins through the published API port, and `flannel` uses `wireguard-native` | Both nodes are `Ready`. Pods on the two nodes reach each other, a service with an endpoint on each node, and the DNS name of that service. `kubectl logs` and `kubectl exec` reach the agent. |
| C2 | A WireGuard mesh `wg0` between the guests, set up with `ip` and `wg`. `k3s` uses the `wg0` addresses with `--flannel-iface wg0` and `--egress-selector-mode disabled` | The C1 checks pass, and the API server connects to the kubelet of the agent directly over `wg0`. |
| C3 | A `gvx` agent joins a server that runs natively on a Linux host | The C1 checks pass. |
| C4 | Three servers with embedded `etcd` over the WireGuard mesh, joined one at a time | The cluster keeps working when the `etcd` leader stops. A surviving server accepts a write within 30 seconds. The tests measured 5 to 9 seconds. |
| C5 | `sonobuoy` with the `e2e` plugin | The quick mode passes. The `[sig-network] Services` tests pass. |

### 4.3 Known Limits

These limits come from the guest kernel. GVXIP-005, section 3.5, gives the reasons.

| Limit | Effect |
| :--- | :--- |
| `nftables` | Set `IPTABLES_MODE=legacy`. A component that needs `iptables-nft` fails. |
| Calico | The tests run `kube-router`, the controller of `k3s`. The guest has the IP sets, the match `set`, and the target `SET` that the iptables mode of Calico uses. No test runs Calico itself, so other matches of Felix can still fail. |
| NFLOG | `-j NFLOG` accepts a rule, but no group receives a packet, because the guest has no `nflog` listener. |
| IPVS, eBPF, and kernel modules | `kube-proxy` must use the iptables mode. CNIs that need eBPF, such as Cilium, do not run. |
| Memory limits | The Sentry checks `memory.max` by polling. A process that allocates and frees more than its limit between two checks is not ended. [`docker-engine.md`](docker-engine.md), section 6.4, gives the intervals. |
| Windows `systrap` | `memory.max` is stored and not enforced, so memory limits of pods do not hold. Taint such a node, or use `whpx`. |
| MTU | `eth0` has the MTU 1500 at the start, as on a Linux node. `flannel` derives 1450 for VXLAN and 1420 for WireGuard. Set `--tune net.nat.mtu=N` to start with another value. A node can change it later with `ip link set dev eth0 mtu N` from 68 to 65535, and `flannel` follows the new value at the next start. |
| WireGuard policy routing | The guest has no `ip rule` and no routing table besides the main one. `wg-quick up` with `AllowedIPs = 0.0.0.0/0` fails at `ip route add ... table`. Set `Table = off` and add the routes with `ip route`. The mark of the link (`fwmark`) reaches iptables, but it cannot choose a table. |
| WireGuard reply address | A `wireguard` link answers from the address that the route picks, and not from the address that the peer used. The two differ on an interface with several addresses. |
| WireGuard link-local endpoints | An IPv6 endpoint loses its `sin6_scope_id`. Use a global address. |
