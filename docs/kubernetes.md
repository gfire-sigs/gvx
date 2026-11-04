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

## 3. Reference

The tables below list the behavior that the tests prove and the limits of a `gvx` node.

### 3.1 Verified Behavior

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

### 3.2 Known Limits

These limits come from the guest kernel. GVXIP-005, section 3.5, gives the reasons.

| Limit | Effect |
| :--- | :--- |
| `nftables` | Set `IPTABLES_MODE=legacy`. A component that needs `iptables-nft` fails. |
| NetworkPolicy | The guest has no `ipset`. `k3s` logs `Skipping network policy controller start, ipset save failed` and continues. The API server accepts a NetworkPolicy, but the policy does not block traffic. |
| IPVS, eBPF, and kernel modules | `kube-proxy` must use the iptables mode. CNIs that need eBPF, such as Cilium, do not run. |
| Memory limits | The Sentry checks `memory.max` by polling. A process that allocates and frees more than its limit between two checks is not ended. [`docker-engine.md`](docker-engine.md), section 6.4, gives the intervals. |
| Windows `systrap` | `memory.max` is stored and not enforced, so memory limits of pods do not hold. Taint such a node, or use `whpx`. |
| MTU | `eth0` has the MTU 1500, as on a Linux node. `flannel` derives 1450 for VXLAN and 1420 for WireGuard. |
