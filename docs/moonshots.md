# Moonshot: GPU Acceleration for Browser and GUI Guests

This document outlines a future moonshot architecture for giving Linux browser and GUI guests access to the host GPU on macOS and Windows. The design has three layers: the Mesa driver in the guest, a virtual DRM device in the Sentry, and a renderer process on the host. The document assesses an earlier draft, states the constraints of `gvx`, and defines the security model and a phased plan with exit criteria. The repository implements the Phase 0 baseline gates and the headless macOS paths of Phase 2 (`rungv run -gpu=venus` and `rungv run -gpu=virgl`). The Windows path and Phase 3 are proposals.

| Field | Value |
| :--- | :--- |
| **Title** | GPU Acceleration for Browser and GUI Guests |
| **Status** | Moonshot. Phase 0: in progress. Phase 2 on macOS (headless): implemented behind `-gpu=venus` and `-gpu=virgl`. Windows and Phase 3: proposed. |
| **Isolation Tier** | Tier 1: `pkg/sentry/devices/virtgpu`, `internal/gpurender`, `gpurenderer`, and `scripts/gpu`. The list `tier1Prefixes` (`tools/gostateify/stateify/tier.go`) and `tools/upstream/file_mask.txt` register them. Tier 2: `pkg/sentry/fsimpl/sys/virtgpu_xplat.go`. Tier 3: the `seam` entry for `pkg/sentry/fsimpl/sys/sys.go`, which existed before this work. |
| **Target Platforms** | `darwin/arm64`, `windows/amd64`, `windows/arm64`. `linux/amd64` and `linux/arm64` are optional. |
| **Companion Docs** | [`systrap-windows.md`](systrap-windows.md), [`architecture.md`](architecture.md) |

The phases below have a fixed order. A phase starts only when the phase before it meets its exit criterion. Section 9.2 records one deviation from this rule for macOS.

| Phase | Content | State |
| :--- | :--- | :--- |
| Phase 0 | Baseline gates for Chromium, Playwright, and Electron with software rendering | In progress: the gates pass on `hvf`; no run covers `whpx`, Windows `systrap`, or Linux `systrap` yet |
| Phase 1 (macOS) | Renderer bring-up with no Sentry change | Done (section 9.2.2) |
| Phase 1 (Windows) | Prototype over the `vtest` socket protocol, with no Sentry change | Not started |
| Phase 2 (macOS, Vulkan) | Virtual render node for the `venus` stream and a confined renderer process (headless) | Implemented; gates G1 and G2 `venus` pass on `hvf` (section 9.3.1) |
| Phase 2 (macOS, OpenGL) | Virtual render node for the `virgl` stream on Apple OpenGL 4.1 (D13) | Implemented; gates G3 and G2 `virgl` pass on `hvf` (section 9.3.1) |
| Phase 2 (Windows) | Virtual render node and a confined renderer process (headless) | Not started |
| Phase 3 | Display output to the host desktop | Not started |

---

## 1. Scope and Goals (Descriptive Module)

The primary workloads are Chromium-based browsers, browser automation (Playwright and Puppeteer), and Electron applications. These programs use the GPU for WebGL, for compositing, and for rasterization when a usable GPU exists. Chromium deprecates the automatic WebGL fallback to SwiftShader, a CPU implementation of Vulkan and OpenGL ES. Without a GPU, WebGL context creation then fails unless the command line sets `--enable-unsafe-swiftshader`.

| Goal | Description |
| :--- | :--- |
| G1 | A headless Chromium guest renders WebGL and compositing on the host GPU on macOS and Windows. |
| G2 | The `rungv` binary stays pure Go (`CGO_ENABLED=0`) and keeps its size. |
| G3 | The GPU path is opt-in. A sandbox without the option keeps the current security model. |
| G4 | The guest uses unmodified distribution packages (Mesa, Chromium, Electron). |
| G5 | A later phase shows a guest window on the host desktop. |

These items are out of scope:

- GPU compute for machine learning (CUDA, ROCm, or Metal compute from the guest).
- Video decode and encode acceleration.
- Native Windows or macOS applications inside the guest.
- A display server for full Linux desktop sessions.

---

## 2. Background (Descriptive Module)

A browser in a `gvx` guest is a Linux ELF program, and the Sentry serves its system calls. The host GPU APIs are native libraries of the host: `Metal.framework` (Mach-O) on macOS and `d3d11.dll` (PE) on Windows. A Linux process cannot load them with `dlopen`, and the Sentry cannot hand them to the guest.

The standard solution serializes the guest graphics calls into a command stream. A driver in the guest encodes the stream, and a renderer on the host decodes it and calls the host API. Linux virtual machines use this model through the `virtio-gpu` device and the `virglrenderer` library.

### 2.1 State of Browser Support in `gvx`

The `e2e` browser gates run Chromium, Playwright, and Electron with software rendering. They run only with `GVX_E2E_BROWSER=1`, because the image is about 1 GB. Section 9.1.1 records the results on `hvf`. A GPU path cannot show a gain before software rendering works.

| Item | State in the current tree |
| :--- | :--- |
| Browser or Electron gate in `e2e/` | `e2e/gate_browser_test.go` (on request: `GVX_E2E_BROWSER=1`), with the benchmark `TestE2EBrowserBench` (`GVX_E2E_BROWSER_BENCH=1`) |
| `/dev/shm` | A `tmpfs` mount without a size option (`pkg/gvx/kernel_runner.go`), so the `tmpfs` default of 50% of host RAM applies |
| Guest devices | `pkg/gvx` registers `memdev`, `/dev/kmsg`, `ttydev`, `/dev/fuse`, and `tundev` (when the stack supports TUN). With `-gpu=venus` or `-gpu=virgl` it also registers `virtgpu`. `pkg/sentry/devices` also holds `nvproxy`, `rdmaproxy`, and `tpuproxy`, which `pkg/gvx` does not register. |
| DRM device (`/dev/dri/*`) | `/dev/dri/renderD128` (character device 226:128) with `-gpu=venus` or `-gpu=virgl` on `darwin/arm64`. None without the option. |
| Cost of `fork` and `exec` on Windows `systrap` | 6.4 ms on `amd64` and 22 ms on `arm64` (hosted runners; `systrap-windows.md`, section 3.9) |

Chromium starts a process for each renderer and for the GPU service. The `fork` and `exec` cost of Windows `systrap` therefore affects the start time of each tab [inference]. Phase 0 measures this cost.

---

## 3. Prior Art (Reference Module)

Four projects run a Linux guest with GPU access on a host that is not Linux, or isolate the renderer on Linux. This table lists the stack of each project and the result that matters for `gvx`.

| Project | Host | Guest driver | Host renderer | Result for `gvx` |
| :--- | :--- | :--- | :--- | :--- |
| UTM | macOS | Mesa `virgl` (OpenGL), Mesa `venus` (Vulkan) | `virglrenderer` with ANGLE on Metal, or MoltenVK | Proves `virgl` over ANGLE on Metal. UTM turned GPU acceleration off by default in v4.1.6 because of guest Mesa defects. The UTM manual states that a Linux desktop does not render through `venus`. `gvx` uses CGL in place of ANGLE, so the bundle gains no ANGLE binary. |
| libkrun and `krunkit` | macOS | Mesa `venus` | `virglrenderer` (`venus`) with MoltenVK | Proves Vulkan from Linux containers on Apple GPUs. Podman machine uses it. |
| `crosvm` (ChromeOS) | Linux | Mesa `virgl`, `venus`, and the cross-domain context | `virglrenderer` in a separate, confined GPU process | Proves the confinement model and the Wayland bridge (`sommelier`). |
| WSLg | Windows | Mesa `d3d12` driver | DirectX 12 through the `dxgkrnl` paravirtual device (`/dev/dxg`) | Proves a Windows path for a guest kernel that has the `dxgkrnl` driver. A Sentry emulation of `/dev/dxg` would call host `D3DKMT` functions, which use win32k system calls and conflict with the `gvx` lockdown [inference]. |

No project runs `virglrenderer` with ANGLE on Direct3D 11 as a supported Windows product. The authors did not find one. Phase 1 must measure this path before Phase 2 depends on it.

---

## 4. Constraints of `gvx` (Descriptive Module)

The design must satisfy the rules of [`AGENTS.md`](../AGENTS.md) and of the backends. These constraints change the design of the earlier draft. Each row names the rule and its effect on this proposal.

| Constraint | Source | Effect on the design |
| :--- | :--- | :--- |
| No new host process after the lockdown | `hostlockdown.Apply` (Job object with one process on Windows, Seatbelt `deny process-fork` on macOS) | The renderer is a separate process that starts before the lockdown, like the `systrap` stub host. |
| No win32k call after the lockdown | `AGENTS.md`, section 3.2 | Direct3D runs in the renderer process, never in the Sentry. |
| Pure Go build | `release.yml` sets `CGO_ENABLED=0`, so the binary needs no C library on the host | `virglrenderer` and ANGLE live in the renderer binary. The Sentry talks to it through IPC. |
| Sockets of `hostfs` live in Sentry memory | `docs/architecture.md`, "Special Files and Extended Attributes"; `pkg/sentry/fsimpl/hostfs/host.go` (`hostKindOther`) | A guest cannot connect to a host Unix socket through a bind mount. A display bridge needs a new socket bridge or TCP. |
| Guest memory differs on each backend | `hvf` (`hv_vm_map`, 16 KiB blocks), `whpx` (`WHvMapGpaRange`), Windows `systrap` (section views), Linux `systrap` (memory file) | A shared buffer of the renderer needs a new `memmap.File` for each backend. |
| Hosted CI runners have no GPU | GitHub-hosted runners | CI runs function tests on WARP for Windows only. The hosted macOS runner cannot run `hvf` (`docs/architecture.md`, section 4.2), so macOS tests run by hand on an Apple Silicon host. The renderer tests need Metal and no hypervisor. `ci.yml` builds the renderer on `macos-26` and runs those tests only when the repository variable `GVX_CI_METAL` is `1`. No run has measured Metal on a hosted macOS runner. CI cannot detect a performance regression. |
| Upstream diff budget below 5.0% (4.2% CI gate) | `tools/upstream -mode=audit` | Add each new package to `tier1Prefixes` first. Otherwise the audit charges each added file against the ceiling. The `sysfs` change needs a `seam` line in `buildtag_allowlist.txt`. The audit counts 105 of 2550 upstream files (4.12%). Neither the `venus` path nor D13 (`virgl`) adds an upstream file. |

---

## 5. Target Architecture (Descriptive Module)

The architecture keeps the guest unmodified and moves every host API call into one confined process. The Sentry implements the Linux DRM interface of a `virtio-gpu` render node and forwards command streams to the renderer. The renderer runs `virglrenderer` and passes the decoded calls to ANGLE or to a Vulkan driver.

![Moonshot GPU Acceleration Architecture](assets/moonshot-gpu.svg)

### 5.1 Components

Each component has one owner and one boundary. The renderer is the only component that calls a host graphics API.

| Component | Location | Responsibility |
| :--- | :--- | :--- |
| Guest driver | Guest image (`mesa-vulkan-drivers` and `libvulkan1` for `venus`; `libgl1-mesa-dri` for `virgl`) | Encodes Vulkan calls into `venus` command streams, or OpenGL calls into `virgl` command streams. |
| Virtual render node | `pkg/sentry/devices/virtgpu` | Registers the DRM render node 226:128, serves the DRM and `virtio-gpu` ioctls, and owns the GEM handles of each guest file. |
| DRM file types | `pkg/sentry/devices/virtgpu` | Implements `sync_file` descriptions for fences. The dma-buf descriptions for PRIME are a later step. |
| Device enumeration | `pkg/sentry/fsimpl/sys/virtgpu_xplat.go`, `devtmpfs` | Exposes a virtio GPU on a PCI device (`0x1af4:0x1050`) under `/sys/devices`, `/sys/class/drm`, and `/sys/dev/char/226:128`. `FilesystemType.GetFilesystem` in `sys.go` adds the entries when `pkg/gvx` passes `InternalData.VirtGPU`. |
| Blob memory | `pkg/sentry/devices/virtgpu` (`blob.go`, `blob_darwin.go`) | Maps a shared-memory object of the renderer and exposes it as a `memmap.File`. On `hvf`, the existing region path maps it into the guest. Each other backend needs its own file. |
| Renderer | `gpurenderer` (C program `gvx-gpu-renderer`) | Runs `virglrenderer` (`venus` on KosmicKrisp and Metal; `vrend` on Apple OpenGL 4.1 via CGL), owns the GPU context, and serves one sandbox. |
| IPC | `pkg/sentry/devices/virtgpu/gpuproto`, `internal/gpurender` | Carries requests, replies, and events on one stream socketpair. Blob memory passes as shared-memory descriptors. The `venus` command ring is inside a blob, so the IPC has no ring of its own. |

### 5.2 Guest Interface

The Linux kernel driver `virtio_gpu` defines the interface that Mesa expects. The Sentry must serve the DRM core ioctls and the `virtio-gpu` ioctls of [`virtgpu_drm.h`](https://github.com/torvalds/linux/blob/master/include/uapi/drm/virtgpu_drm.h). The DRM major number is 226, and render nodes use minor numbers from 128.

| Group | Requests | Purpose |
| :--- | :--- | :--- |
| DRM core | `DRM_IOCTL_VERSION`, `DRM_IOCTL_GET_CAP` | Driver name (`virtio_gpu`) and capabilities. Mesa selects its driver by this name. A render node returns `EACCES` for `DRM_IOCTL_SET_CLIENT_CAP` and `DRM_IOCTL_GET_UNIQUE`. |
| GEM and PRIME | `DRM_IOCTL_GEM_CLOSE`, `DRM_IOCTL_PRIME_HANDLE_TO_FD`, `DRM_IOCTL_PRIME_FD_TO_HANDLE` | Buffer handles and their export to other processes as dma-buf descriptors. |
| Synchronization | `DRM_IOCTL_SYNCOBJ_*` and the `sync_file` descriptors of `EXECBUFFER` | Fences between submissions and between processes. |
| `virtio-gpu` | `DRM_IOCTL_VIRTGPU_` plus `GETPARAM`, `GET_CAPS`, `CONTEXT_INIT`, `RESOURCE_CREATE`, `RESOURCE_CREATE_BLOB`, `RESOURCE_INFO`, `MAP`, `EXECBUFFER`, `TRANSFER_TO_HOST`, `TRANSFER_FROM_HOST`, `WAIT` | Contexts, resources, command submission, and data transfer. |
| File operations | `mmap` of a GEM object, `poll`, `read` of DRM events | Mapped buffers and completion events. |

The earlier draft estimated about 10 ioctls. The table lists 28 ioctls (2 core, 3 GEM and PRIME, 12 `SYNCOBJ`, 11 `virtio-gpu`). The full surface also adds two new file types and `sysfs` enumeration.

The first macOS step serves a subset of this table. Mesa `venus` and headless Chromium use only that subset. The device reports `DRM_CAP_SYNCOBJ` as 0, so Mesa uses its simulated sync objects, which need only `sync_file` descriptors and `poll`. With `GVX_DEBUG_LOG=2`, the device logs each refused request one time for each open file.

| Group | Served in the first macOS step | Refused, with the error |
| :--- | :--- | :--- |
| DRM core | `DRM_IOCTL_VERSION`, `DRM_IOCTL_GET_CAP` | Master, authentication, and mode-setting requests: `EACCES` |
| GEM and PRIME | `DRM_IOCTL_GEM_CLOSE` | `DRM_IOCTL_PRIME_HANDLE_TO_FD`, `DRM_IOCTL_PRIME_FD_TO_HANDLE`: `EOPNOTSUPP` |
| Synchronization | A `sync_file` descriptor from `EXECBUFFER` with `VIRTGPU_EXECBUF_FENCE_FD_OUT`; `poll` on it | `DRM_IOCTL_SYNCOBJ_*`: `EOPNOTSUPP`. `SYNC_IOC_MERGE`, `SYNC_IOC_FILE_INFO`: `ENOTTY`. `VIRTGPU_EXECBUF_FENCE_FD_IN`: `EINVAL` |
| `virtio-gpu` | `GETPARAM`, `GET_CAPS`, `CONTEXT_INIT`, `RESOURCE_CREATE_BLOB` (only `VIRTGPU_BLOB_MEM_HOST3D`), `RESOURCE_INFO`, `MAP`, `EXECBUFFER` | `RESOURCE_CREATE`, `TRANSFER_TO_HOST`, `TRANSFER_FROM_HOST`, `WAIT`: `EINVAL` |
| File operations | `mmap` of a blob (shared mappings only), `poll` | The node has no DRM events, so `read` returns no data |

### 5.3 Command Stream Choice

The renderer serves two command streams, one mode per process. On macOS, `gvx` implements both `venus` (Vulkan on KosmicKrisp and Metal) and `virgl` (OpenGL on Apple OpenGL 4.1 via CGL, D13). Windows keeps both candidates until its Phase 1 measures them.

| Property | `virgl` (OpenGL) | `venus` (Vulkan) |
| :--- | :--- | :--- |
| Guest API | OpenGL and OpenGL ES | Vulkan |
| Path of a Chromium WebGL call | Chromium ANGLE (GL back end), Mesa `virgl`, `virglrenderer`, host ANGLE, Metal or Direct3D 11 | Chromium ANGLE (Vulkan back end), Mesa `venus`, `virglrenderer`, KosmicKrisp (macOS) or the host Vulkan driver |
| Layers on the path | Chromium ANGLE, Mesa `virgl`, host ANGLE | Chromium ANGLE and a Vulkan driver on Metal (macOS only) |
| macOS prior art | UTM | UTM, `krunkit` (both on MoltenVK) |
| Windows prior art | None found | None found |
| Known limit | Host ANGLE on Direct3D 11 offers OpenGL ES 3.0 and parts of 3.1 [inference]. On macOS, `virgl` needs an ANGLE build and a patched `libepoxy`. | Chromium needs an OpenGL ES 3.0 context from ANGLE. ANGLE gives it only when the Vulkan device has `VK_EXT_provoking_vertex`. MoltenVK 1.4.2 lacks that extension (section 5.3.1). |

#### 5.3.1 Host Vulkan Driver on macOS (Reference Module)

Two Vulkan drivers run on Metal: MoltenVK and KosmicKrisp, which is part of Mesa. The renderer uses KosmicKrisp. The table gives the measured reasons on an Apple M1 Ultra with macOS 27.2.1.

| Property | MoltenVK 1.4.2 | KosmicKrisp (Mesa 26.3.0) |
| :--- | :--- | :--- |
| `VK_EXT_provoking_vertex` with `provokingVertexLast` | No | Yes |
| `nullDescriptor` of `VK_EXT_robustness2` (Mesa Zink needs it) | No | Yes |
| `SYNC_FD` descriptors for semaphores and fences | No | Yes |
| `VK_EXT_external_memory_host` (`virglrenderer` needs it on macOS) | Yes | Yes |
| Vulkan conformance | Portability subset | Conformant to Vulkan 1.4 |
| Host requirement | Metal | Metal 4: macOS 26 or later |
| Gate G2 with guest Mesa 25.2.8 | Fail: the guest device has no `VK_KHR_swapchain`, and ANGLE requires it | Pass |
| Chromium with guest Mesa 26.2.6 | Fail: `VK_KHR_swapchain` is present, but ANGLE offers only OpenGL ES 2.0 | Pass (WebGL 1 and WebGL 2) |

Mesa releases before 26.2 expose the `venus` swapchain extensions only when the host imports `SYNC_FD` semaphores. Mesa 26.2.0 removed that condition (merge request 42853). KosmicKrisp imports `SYNC_FD` semaphores, so both old and new guest Mesa releases work. The guest image therefore needs no patched driver.

### 5.4 Memory Model

A `virtio-gpu` resource has guest backing pages, host backing memory, or both. Without blob support, Mesa copies data with `TRANSFER_TO_HOST` and `TRANSFER_FROM_HOST`. Blob resources let the guest map renderer memory directly.

| Backend | Mapping of a renderer buffer into the guest | Expected work |
| :--- | :--- | :--- |
| `hvf` | `hv_vm_map` of a host pointer, aligned to 16 KiB | Done in `pkg/sentry/devices/virtgpu`. The Sentry maps the shared-memory object of the renderer one time. `hvcommon.RegionMap` maps that view with `hv_vm_map`. The platform package did not change. |
| `whpx` | `WHvMapGpaRange` of a host pointer | Import a section handle of the renderer. |
| Windows `systrap` | Map a view of a section into the stub | Extend `sectionCache` (`section_windows.go`) to accept an imported section handle. `get` accepts only file handles today. |
| Linux `systrap` | Map the descriptor of a memory file | Import a descriptor from the renderer (optional platform). |

On macOS, Phase 2 starts with `venus` and blob resources. The device accepts only `VIRTGPU_BLOB_MEM_HOST3D`. The renderer allocates every shared buffer as a POSIX shared-memory object, so the renderer never maps guest RAM. The device reports `VIRTGPU_PARAM_BLOB_ALIGNMENT` as 16 KiB, the page size of the host. A `virgl` path would need guest backing pages in the renderer, or a copy for each transfer.

### 5.5 Renderer Process

The Sentry starts one renderer for each sandbox before `hostlockdown.Apply`. The renderer receives its socket end and then confines itself, before it reads a guest byte. The Sentry keeps only its socket end and its views of the shared blob objects. It keeps no handle that can write other memory of the renderer.

| Host | Confinement of the renderer | GPU access that it keeps |
| :--- | :--- | :--- |
| Windows | Restricted token at low integrity, a job object without child processes, no file system access except its own binary | Direct3D 11 through `dxgi.dll` and `d3d11.dll`, which need win32k system calls [inference] |
| macOS | A Seatbelt profile with `deny default`. It denies `process-fork`, `process-exec`, file writes, and network access. It permits `file-read-metadata` and file reads only in system library paths and in the renderer bundle. | `iokit-open` for `IOAccelerator` and `IOSurfaceRootUserClient`; the Mach service `com.apple.MTLCompilerService`; POSIX shared memory with the name prefixes `/vkr-`, `/proxy-`, and `/gvx-r-` |
| Linux (optional) | seccomp and namespaces, as `crosvm` does | The render node of the host |

The renderer runs C code that parses guest-controlled input. Section 6 describes the consequences. The Sentry cannot start a process after the lockdown, so a renderer that exits does not restart. [`architecture.md`](architecture.md) section 3.15 gives the reason for each rule of the macOS profile.

### 5.6 Display Options

Phase 3 chooses one display path. The path decides the copy cost and the size of the host component. The earlier draft proposed an X11 bridge with zero-copy frames; the table shows why that combination does not hold.

| Option | Host component | Copy cost | Notes |
| :--- | :--- | :--- | :--- |
| X11 over TCP to XQuartz or VcXsrv | Third-party X server | Each frame crosses TCP; MIT-SHM does not cross the host boundary | Reaches a host X server on `127.0.0.1` through the `10.0.2.2` gateway of the NAT network [inference]. XQuartz accepts TCP clients only after the user enables network connections [inference]. A 4K frame at 60 Hz with 4 bytes for each pixel needs about 2 GB/s. |
| Frame streaming (VNC) | Viewer on the host | One encode and one decode for each frame | The viewer is an existing program, and it carries input. |
| Remote windows over RDP (WSLg model) | RDP client with remote application support | WSLg uses RDP with VAIL, which shares window memory across the VM boundary and skips frame encoding | `gvx` has no shared memory path to an RDP client yet. |
| Wayland cross-domain bridge | A host compositor that maps each guest surface to a native window | No copy for blob buffers | ChromeOS uses this model (`sommelier`). It needs a new host compositor for each host OS. |

---

## 6. Security Model (Descriptive Module)

`gvx` confines guest code to the Sentry, and the Sentry reaches the host only through a fixed set of host calls. A GPU path adds a renderer that parses guest-controlled command streams in C and calls the host GPU driver. The renderer therefore becomes part of the attack surface of the sandbox.

| Threat | Evidence | Mitigation |
| :--- | :--- | :--- |
| Memory corruption in `virglrenderer` | [CVE-2019-18389](https://access.redhat.com/security/cve/cve-2019-18389) is a heap overflow; Red Hat lists denial of service or a guest-to-host escape. [CVE-2022-0135](https://access.redhat.com/security/cve/cve-2022-0135) is an out-of-bounds write; Red Hat lists denial of service or code execution. | Run the renderer in its own confinement (section 5.5). Pin and update `virglrenderer` with each release. |
| Defects in the host GPU driver | The driver runs in the host kernel or in a privileged host service | Keep the GPU path opt-in. State the risk in the documentation of the option. |
| Resource exhaustion | A guest can allocate GPU memory and submit long command buffers | The Sentry caps contexts (64), one blob (1 GiB), one submission (16 MiB), and pending fences (4096 for each context). It caps blob bytes at the smaller of 4 GiB and 25% of host RAM by default. A fence that stays pending for 30 s ends its context. |
| Data leaks between sandboxes | A shared renderer could mix contexts | Start one renderer for each sandbox. Give the renderer no write access to the Metal shader cache, which all processes of one user share. |
| GPU memory that the Sentry cannot count | `venus` allocates device-local Vulkan memory through its ring, with no blob | A thread in the renderer samples the memory footprint every 250 ms. The renderer exits above the blob limit plus 512 MiB. The host kernel does not enforce this limit, so a corrupted renderer can pass it. |
| Loss of the renderer during a run | The renderer is one process, and it cannot restart after the lockdown | Guest mappings stay valid, because the Sentry holds its own view of each blob. Later GPU calls return `EIO`. The sandbox keeps running, and Chromium uses its own fallback. |

The option is off by default. A sandbox without the option registers no DRM device and starts no renderer. Its security model stays unchanged.

---

## 7. Assessment of the Earlier Draft (Reference Module)

An earlier draft proposed the same three layers. This table compares its claims with the facts that this proposal found. Each row gives the corrected statement and its basis.

| Claim of the draft | Finding | Basis |
| :--- | :--- | :--- |
| The Sentry intercepts about 10 ioctls | The surface also includes the DRM core, dma-buf and `sync_file` file types, and `sysfs` enumeration | Section 5.2 |
| Chromium enables acceleration without changes | Headless Chromium needs `--use-angle=vulkan` and `--ignore-gpu-blocklist`. The guest image needs `mesa-vulkan-drivers`. `gvx` adds no flag and no package to the guest. | Gate G2 (section 9.3.1) |
| WebGL becomes tens of times faster than SwiftShader | The gain applies to WebGL-heavy pages. Page rasterization, screenshots, and PDF output of automation depend on the CPU. Chromium deprecates the automatic WebGL fallback to SwiftShader, so WebGL on SwiftShader needs `--enable-unsafe-swiftshader` | Phase 0 measures the share of CPU rendering |
| Guest sockets connect to the host X11 or Wayland socket | `hostfs` keeps sockets in Sentry memory. A guest reaches a host display server only through TCP today | Section 4 |
| Shared memory gives zero-copy 4K at 60 Hz through the X11 bridge | X11 over TCP copies each frame. `virgl` transfers copy by default. Zero copy needs blob resources and a compositor bridge | Sections 5.4 and 5.6 |
| `/dev/shm` must grow from 64 MB | The 64 MB limit is a Docker default. `gvx` mounts `/dev/shm` as `tmpfs` without a size option, so the `tmpfs` default of 50% of host RAM applies | `pkg/gvx/kernel_runner.go` |
| The host renderer takes 15 MB to 20 MB | Plausible for ANGLE and `virglrenderer`. The ANGLE build needs `depot_tools` and `gn`, and `virglrenderer` has no supported `windows/arm64` build | [inference] Phase 1 measures it |
| Two licenses fit the project | `virglrenderer` is MIT and ANGLE is BSD-3-Clause. MoltenVK is Apache-2.0. Mesa, which holds KosmicKrisp, is MIT. | Upstream license files |
| Phase 1 can prototype every stream over `vtest` (first version of this document) | On macOS the `vtest` server falls back to protocol version 0, because it needs `memfd_create`. Version 0 has no blob resource, and `venus` needs blob resources and descriptor passing. | `vtest/vtest_shm.c` and `vtest/vtest_renderer.c` of `virglrenderer` |

---

## 8. Risks (Reference Module)

The risks below decide whether the project continues after each phase. The exit criterion of each phase in section 9 tests the risk in the same row.

| Risk | Effect | Mitigation | Tested in |
| :--- | :--- | :--- | :--- |
| Browsers do not run on a backend with software rendering | No baseline for a gain | Fix the defects first | Phase 0 |
| GPU rendering gives a gain below the Phase 0 minimum for the target workloads | The cost exceeds the value | Stop after Phase 0 or Phase 1 | Phase 0 and Phase 1 |
| `virglrenderer` with ANGLE on Direct3D 11 is incomplete or unstable | No Windows path | Measure `venus` with the host Vulkan driver; keep Windows on software rendering | Phase 1 and Phase 2 |
| Rendering defects from three translation layers | Wrong output in some pages | Keep a conformance subset of WebGL tests in the exit criteria | Phase 1 and Phase 2 |
| A renderer escape | Host compromise | Renderer confinement, opt-in, pinned versions | Phase 2 |
| Build and release cost of C dependencies | CI time and release size | Build the renderer in a separate job and ship it as a separate archive | Phase 2 |
| No GPU in CI | Regressions in performance stay unseen | Run function tests on WARP for Windows; run macOS and performance tests by hand on physical hosts | Phase 2 |
| KosmicKrisp is a young driver (first release in 2025) | Rendering or stability defects on some pages | Pin the Mesa version in `gpurenderer/third_party.lock`. Run gates G1 and G2 after each change of the pin. | Phase 2 |
| The renderer needs macOS 26 or later | No GPU option on older hosts | `gvx.New` returns an error that names the requirement. The sandbox does not fall back to software rendering silently. | Phase 2 |

---

## 9. Phased Plan (Procedural Modules)

Each phase ends with an exit criterion. A failed criterion stops the project or changes the next phase. Record each measurement with its host, its command, and its run ID.

### 9.1 Phase 0: Baseline Gates

Phase 0 needs no new device. It tells whether browsers run on each backend and how much time software rendering costs.

1. Add an `e2e` gate that runs headless Chromium on a static page and prints a value from the page.
2. Add a Playwright gate that takes a screenshot and saves a PDF.
3. Add an Electron gate that starts an application and exits with code 0.
4. Run each gate on `hvf`, `whpx`, Windows `systrap`, and Linux `systrap`.
5. Run the `hvf` gates on an Apple Silicon development host.
6. Measure the start time of the browser and of each new tab.
7. Record a minimum share of run time and a minimum speedup over SwiftShader.
8. Profile one WebGL page and one automation script with `--enable-unsafe-swiftshader` set.
9. Record the share of time in SwiftShader for each workload.

Exit criterion: the browsers pass on each backend, and SwiftShader takes at least the minimum share of run time.

#### 9.1.1 Phase 0 Results on `hvf` (Reference Module)

The tables below record the first `hvf` results on an Apple M1 Ultra with 64 GB running macOS 27.2.1. Other workloads loaded the host (load average 24 to 133), so the latency values are upper bounds. Each row of the command table names the suite that produced the measurements below.

| Suite | Command |
| :--- | :--- |
| Browser gates | `GVX_E2E_BROWSER=1 go test -count=1 -timeout 30m -exec "$PWD/scripts/codesign-exec.sh" ./e2e -run '^TestE2EGateBrowser' -v` |
| Browser benchmark (`hvf`) | `GVX_E2E_BROWSER=1 GVX_E2E_BROWSER_BENCH=1 go test -count=1 -timeout 60m -exec "$PWD/scripts/codesign-exec.sh" ./e2e -run '^TestE2EBrowserBench$' -v` |
| Native macOS Chromium 159 | `GVX_BENCH_PWCORE=<playwright-core-dir> GVX_BENCH_BASE="file://$PWD/e2e/testdata/browser/" GVX_BENCH_WEBGL="n=20000&size=0.05&iters=16;sync=1&n=20000&size=0.05&iters=16;sync=1&n=200&size=1.0&iters=64" node e2e/testdata/browser/browser-bench.js` (Playwright macOS Chromium 159 headless shell for SwiftShader; full Chromium for Metal) |
| Microbenchmarks (`hvf`) | `GVX_E2E_BENCH=1 go test -count=1 -exec "$PWD/scripts/codesign-exec.sh" ./e2e -run '^TestE2EMicroBench$' -v` |

| Gate | Result on `hvf` |
| :--- | :--- |
| Chromium 159 `--dump-dom` (`TestE2EGateBrowserChromiumDumpDOM`) | Pass |
| Chromium sandbox as `pwuser` (`TestE2EGateBrowserChromiumSandbox`) | Pass: each renderer runs in seccomp mode 2 in its own user and PID namespaces |
| WebGL on SwiftShader (`TestE2EGateBrowserWebGLSwiftShader`) | Pass with `--enable-unsafe-swiftshader` |
| Playwright 1.65.1 screenshot and PDF (`TestE2EGateBrowserPlaywright`) | Pass |
| Electron 45.4.1 (`TestE2EGateBrowserElectron`) | Pass with `--ozone-platform=headless` |

| Measurement (`TestE2EBrowserBench`) | `hvf` | Native macOS, same Chromium |
| :--- | ---: | ---: |
| Browser start (median of 5) | 280 ms to 302 ms | 128 ms to 131 ms |
| New tab (median of 10) | 190 ms to 202 ms | 46 ms to 47 ms |
| WebGL draw-call bound, 60 frames (`webgl-load.html?frames=60&sync=1&n=20000&size=0.05&iters=16`) | 5263 ms (SwiftShader share 95 %) | 1277 ms (SwiftShader), 512 ms (Metal) |
| WebGL fragment bound, 60 frames (`webgl-load.html?frames=60&sync=1&n=200&size=1.0&iters=64`) | 7577 ms (SwiftShader share 98 %) | 6948 ms (SwiftShader), 100 ms (Metal) |
| Automation script: 10 screenshots and 10 PDFs (`automation-doc.html`) | 36.8 s (SwiftShader share 0 %) | 18.8 s |

The first Phase 0 threshold is a SwiftShader share of at least 50 % of Chromium CPU time. The GPU path must run at least 3 times faster on the fragment-bound page. It must run at least 1.5 times faster on the draw-call-bound page. The automation script spends no time in SwiftShader, so a GPU path cannot shorten it. In `TestE2EMicroBench` on `hvf`, `futex_pingpong` takes 149 µs to 233 µs, and `getpid` takes 1.7 µs. This wake latency makes the draw-call page 4.1 times slower than native SwiftShader, and it also limits the GPU path.

### 9.2 Phase 1: Prototype without a Sentry Change

Phase 1 measures the rendering stack before the Sentry device exists. Windows uses the test server (`vtest`) of `virglrenderer`. macOS cannot use that server for `venus`, so macOS uses the checks of section 9.2.2.

#### 9.2.1 Windows: Prototype over `vtest` (Procedural Module)

`vtest` speaks a Unix socket protocol. Mesa can use that protocol without a DRM device, so the prototype needs no Sentry change. Upstream Meson builds the server only for hosts other than Windows, and the clients receive buffers as file descriptors.

> [!CAUTION]
> Run the prototype server only on a development host with test pages. The server parses guest commands in unconfined C code, so a malformed command can corrupt memory and run code on the host.

1. Port the `vtest` server to Windows.
2. Build `virglrenderer` and the server with ANGLE on Direct3D 11.
3. Relay the guest `vtest` Unix socket to the host over TCP on the NAT network.
4. Run Chromium with Mesa in `vtest` mode for `virgl`.
5. Run a WebGL conformance subset and the Phase 0 workloads.
6. Compare frame times and correctness with SwiftShader.

Exit criterion: `virgl` passes the conformance subset on Windows and meets the minimum speedup of Phase 0. The relay copies every buffer because it cannot pass file descriptors. The criterion therefore compares the rendering work, not the transport.

#### 9.2.2 macOS: Renderer Bring-Up (Reference Module)

On macOS, the `vtest` server negotiates protocol version 0, which has no blob resource. A TCP relay also cannot carry the shared memory of the `venus` ring. Phase 1 on macOS therefore proved each host mechanism alone, with no Sentry change. This is the deviation from the phase order: the browser measurement moved to gates G1 and G2 of Phase 2.

The checks ran on an Apple M1 Ultra with macOS 27.2.1. Each check now has a test in the repository.

| Check | Result | Test in the repository |
| :--- | :--- | :--- |
| `virglrenderer` with `venus` builds unpatched and serves a capset, a context, a blob as a shared-memory descriptor, and a fence through its public API | Pass | `internal/gpurender`: `TestHandshakeCachesVenusCapset`, `TestBlobDescriptorIsSharedMemory`, `TestFenceRetiresWithin100ms` |
| `hv_vm_map` accepts a shared view of POSIX shared memory, and the view stays valid after the creator exits | Pass | `pkg/sentry/devices/virtgpu`: `TestBlobFromRendererOnHVF`, `TestBlobFromRendererSurvivesRendererExit` |
| A process under the Sentry Seatbelt profile receives a shared-memory descriptor and maps it with no new rule | Pass | `pkg/gvx`: `TestGPUServesRenderNodeUnderLockdown` |
| A Vulkan driver on Metal runs under a `deny default` Seatbelt profile, and the profile refuses `fork`, `exec`, file access, and network access | Pass | `gvx-gpu-renderer --selftest`; `internal/gpurender`: `TestGPURendererConfinement` |

Exit criterion for macOS: all four checks pass on an Apple Silicon host. The four checks passed on 2026-11-20.

### 9.3 Phase 2: Virtual Render Node

Phase 2 builds the production path for headless guests. It adds the device, the renderer process, the IPC, and the confinement of section 5.5. Steps 1 to 9 are the smallest path to a measurement on macOS.

1. Add `pkg/sentry/devices/virtgpu` with the `venus` subset of section 5.2.
2. Add blob resources and the host-visible mapping in the same step.
3. Add the `sysfs` entries that `libdrm` reads.
4. Add the renderer command and its IPC package.
5. Start the renderer before `hostlockdown.Apply` when the sandbox enables the GPU option.
6. Confine the renderer as section 5.5 describes.
7. Add confinement tests that fail when the renderer starts a process, opens a file, or connects to a network.
8. Run gate G1: an unmodified guest Mesa runs a Vulkan compute probe.
9. Run gate G2: headless Chromium renders WebGL through `venus`.
10. Add the resource caps and the fence timeout of section 6.
11. Run the WebGL conformance subset with the GPU option on.
12. Build the renderer in a separate CI job and publish it as a separate archive.
13. Measure `venus` with the host Vulkan driver on Windows.
14. Add `e2e` gates that run on WARP in the Windows CI jobs.
15. Run the gates by hand on a physical Mac and a physical Windows host.

Exit criterion: the Phase 0 gates and the confinement tests pass with the GPU option on. The speedup over SwiftShader meets the minimum of Phase 0.

#### 9.3.1 Phase 2 Results on macOS (Reference Module)

The macOS path completed steps 1 to 11. Step 12 has its jobs: `ci.yml` builds the renderer bundle, and `release.yml` builds and packages the renderer archive. No hosted runner has run either job yet. Steps 13 and 14 belong to Windows. The tables below record the gates on an Apple M1 Ultra with 64 GB running macOS 27.2.1, with the host lockdown on.

Each gate writes its record to the directory in `GVX_E2E_ARTIFACT_DIR`: `result.json`, the Sentry log, the list of refused ioctls, and the screenshots.

| Gate | Command |
| :--- | :--- |
| Renderer build and self-test | `scripts/gpu/build-renderer.sh`, then `--selftest` and `--selftest --mode=virgl` |
| G1, guest Vulkan (record `g1/result.json`) | `GVX_E2E_GPU=1 GVX_GPU_RENDERER="$PWD/build/gpu/gvx-gpu-renderer/bin/gvx-gpu-renderer" go test -count=1 -exec "$PWD/scripts/codesign-exec.sh" ./e2e -run '^TestE2EGateGPUVulkan$' -v` |
| Venus guard, create info that the renderer must survive (record `venus-guard/result.json`) | The same variables, with `-run '^TestE2EGateGPUVenusGuard$'` |
| G3, guest OpenGL (record `g3/result.json`) | The same variables, with `-run '^TestE2EGateGPUOpenGL$'` |
| Renderer kill (record `g1-kill/<mode>/result.json`) | The same variables, with `-run '^TestE2EGPURendererKill$'` (`venus` and `virgl` subtests) |
| G2, Chromium WebGL (record `g2/result.json`) | The same variables, with `-timeout 60m -run '^TestE2EGateGPUChromium$'` (`venus` and `virgl` passes) |
| WebGL conformance subset (record `webgl-cts/result.json`) | The same variables and `GVX_E2E_WEBGL_CTS=subset`, with `-timeout 240m -run '^TestE2EGateGPUWebGLCTS$'` |

| Gate G1 (2026-11-20) | Result |
| :--- | :--- |
| Guest image and driver | `debian:trixie` with a digest pin, unmodified `mesa-vulkan-drivers`, Mesa 25.0.7-2+deb13u1 |
| Device that the guest sees | `Virtio-GPU Venus (Apple M1 Ultra)`, driver `venus`; PCI ID `0x1af4:0x1050` in `sysfs` |
| Compute probe | Pass: the GPU writes 1048576 words through a mapped blob, and the guest reads them with 0 mismatches |
| First dispatch | 21.350 ms on `venus`; 55.203 ms on lavapipe in the same guest with `-gpu=off` |
| Submit and wait, average of 50 rounds | 0.422 ms |
| `SYNC_FD` fence through a `sync_file` descriptor | PASS |
| Refused ioctls | None |
| Renderer kill during the probe (`venus`) | Pass: the guest probe stops, `rungv` exits 4344 ms after the kill, and no renderer process stays |

The first `virgl` gate run exposed two `vrend` defects on Apple OpenGL 4.1 core. `scripts/gpu/build-renderer.sh` now applies two pinned patches from `gpurenderer/patches/virglrenderer/` and records their SHA-256 digests in `BUILDINFO`. `0001-vrend-strip-core-desktop-extensions.patch` drops `#extension` lines for core ARB features that Apple OpenGL omits from its extension list, and raises `#version`. `0002-vrend-multisample-without-storage.patch` probes multisample formats with `glTexImage2DMultisample` when `glTexStorage2DMultisample` is absent, enabling `MaxSamples >= 4` and desktop OpenGL above 2.1. Guest OpenGL ES stays at 3.0 because Apple OpenGL 4.1 lacks compute shaders and `ARB_buffer_storage`, so OpenGL ES 3.1 and coherent mapping stay unavailable.

| Gate G3 (2026-11-20) | Control (`llvmpipe`, `-gpu=off`) | `virgl` (`-gpu=virgl`) |
| :--- | :--- | :--- |
| Guest image and driver | `debian:trixie` with a digest pin, unmodified `libgl1-mesa-dri` and `libegl-mesa0` (Mesa `25.0.7-2+deb13u1`), `mesa-utils` `9.0.0-2+b2` | The same image and packages |
| `GL_RENDERER` | `llvmpipe (LLVM 19.1.7, 128 bits)` | `virgl (Apple M1 Ultra)` |
| `GL_VERSION` (`glesprobe`) | `OpenGL ES 3.2 Mesa 25.0.7-2+deb13u1` | `OpenGL ES 3.0 Mesa 25.0.7-2+deb13u1` (GLSL ES 3.00) |
| `eglinfo -B -p surfaceless` | Not applicable | Renderer `virgl (Apple M1 Ultra)`: OpenGL 4.1 Core and Compatibility (GLSL 4.10), OpenGL ES 3.0 (GLSL ES 3.00) |
| Probe checks (`fbo`, `fill`, `scissor`, `texture`, `readback`, `glerror`) | 6 of 6 PASS (27.21 s) | 6 of 6 PASS (23.68 s) |
| Refused ioctls | None | None |
| KD-1 counters | All 0 | All 0 |
| Renderer kill during the probe (`virgl`) | Not applicable | Pass: `rungv` exits 1 in 191 ms, probe reports a GL error, `renderer_lost=1`, no restart, no orphan (`venus` subtest: exit 134 in 4093 ms) |

| Gate G2 `venus` (2026-11-20) | Headless shell | Full Chromium (new headless) |
| :--- | :--- | :--- |
| Guest image | `mcr.microsoft.com/playwright:v1.65.1-noble` with a digest pin, Chromium 159, plus `mesa-vulkan-drivers` 25.2.8 from Ubuntu 24.04 | The same image |
| Chromium flags | `--use-angle=vulkan --ignore-gpu-blocklist --disable-vulkan-surface` | The same flags |
| WebGL context | WebGL 1 and WebGL 2 | WebGL 1 and WebGL 2 |
| `UNMASKED_RENDERER_WEBGL` | `ANGLE (Apple, Vulkan 1.4.307 (Virtio-GPU Venus (Apple M1 Ultra) (0x00000064)), venus)` | The same string |
| Pixel checks of the scene page | 10 of 10 | 10 of 10 |
| First page after browser start | 1655 ms | 5119 ms |
| Load page (`webgl-load.html`, 60 frames), GPU | 177 ms | 235 ms |
| Load page, SwiftShader in the same guest with `-gpu=off` | 7584 ms | 8788 ms |
| Refused ioctls | None | None |

| Gate G2 `virgl` (2026-11-20) | Headless shell (`159.0.8154.6`) |
| :--- | :--- |
| Guest image and packages | `mcr.microsoft.com/playwright:v1.65.1-noble` with a digest pin, Chromium 159, built-in Mesa `25.2.8-0ubuntu0.24.04.4` (no extra EGL packages needed) |
| Chromium flags | `--use-gl=angle --use-angle=gl-egl --ignore-gpu-blocklist` (default; no fallback needed) |
| ANGLE display type | `ANGLE_OPENGL_EGL` |
| WebGL context | WebGL 1 and WebGL 2 |
| `UNMASKED_RENDERER_WEBGL` | `ANGLE (Mesa, virgl (Apple M1 Ultra), OpenGL ES 3.0)` |
| Pixel checks of the probe and scene pages | Probe PASS; scene 10 of 10 |
| Scene mismatch against SwiftShader | 0.0004 (one 1-pixel checker midpoint row) |
| Page timings after browser start | First page 851 ms, scene page 582 ms, second page 539 ms |
| Load page (`webgl-load.html`, 60 frames), GPU | 229 ms (33.73x over SwiftShader; an earlier run on the same host measured 547 ms vs 8872 ms, 16.22x) |
| Load page, SwiftShader in the same guest with `-gpu=off` | 7725 ms |
| Refused ioctls | None |

The `venus` pass of gate G2 takes 22.19 s for both browsers. The screenshots of the `venus` and `virgl` passes differ from the SwiftShader pass only in one pixel row on a texel boundary of the checker texture. The fragment-bound page meets the Phase 0 minimum of 3 times in both modes. No run has measured the draw-call-bound page.

| WebGL conformance subset (2026-11-22) | SwiftShader (`-gpu=off`) | `venus` | `virgl` |
| :--- | ---: | ---: | ---: |
| Pages that pass, of 1009 | 1003 | 996 | 1003 |
| Pages that fail, crash, or time out | 6 | 13 | 6 |
| Wall time | 46 min | 34 min | 24 min |
| Renderer losses, refused ioctls, KD-1 counts | 0 | 0 | 0 |

The gate runs the KhronosGroup/WebGL tests of commit `714857a2`, which Chromium 159 pins. A page that passes on SwiftShader and does not pass on a GPU mode is a regression. Each of the 13 regressions has a line with a reason in `e2e/testdata/gpu/webgl-cts-expectations.txt`, so the gate passes. The first run found two renderer crashes and twelve guest context losses. The pinned patches `0003` to `0013` and a flush in the CGL callbacks fix them. The remaining `venus` regressions are KosmicKrisp 26.3.0 defects. The remaining `virgl` regressions are an Apple OpenGL 4.1 limit and three known guest stack defects.

The first run of gate G2 used MoltenVK and failed. Section 5.3.1 gives the two causes and the change to KosmicKrisp.

| Known defect | State |
| :--- | :--- |
| KD-1: the first blob request on a new context can fail while other contexts start and stop at the same time. `sendmsg` with a descriptor returns `EINVAL` in `virglrenderer`. | Open. In a stress test of context churn, up to 3 of 800 requests failed in about half of the runs. Gates G1, G2, and G3 count the failure; all counts are 0. |
| KD-2: Metal compiled each shader slowly under the renderer Seatbelt profile. The first page of full Chromium took about 55 s. | Fixed. The renderer resolves the cache directory of the user one time before it confines itself. A start-time test fails when the delay returns. |
| `virgl` on Apple OpenGL 4.1: `vrend` emitted unadvertised core ARB `#extension` lines and required `glTexStorage2DMultisample`. | Fixed by pinned patches `0001-vrend-strip-core-desktop-extensions.patch` and `0002-vrend-multisample-without-storage.patch`. Gates G3, G2 `virgl`, and the kill test report zero open defects. |

### 9.4 Phase 3: Display Output

Phase 3 starts only with a confirmed need for guest windows on the host desktop. It chooses one option of section 5.6.

1. Select the display option with a written comparison of cost and copy count.
2. Record a minimum frame rate at 1080p and at 4K.
3. Build a socket bridge or a compositor for the selected option.
4. Remove frame copies from the display path where the option allows it.
5. Measure the frame time at 1080p and at 4K.

Exit criterion: an Electron application shows its window on macOS and on Windows at the minimum frame rate of step 2.

---

## 10. Open Questions (Reference Module)

These questions have no answer in this proposal. Each answer changes the scope or the order of the phases.

| Question | Phase that answers it |
| :--- | :--- |
| Does Chromium run its multi-process sandbox in a `gvx` guest, or does it need `--no-sandbox`? | Phase 0 (answered for `hvf`): the sandbox runs for a user that is not root. Chromium refuses to start as root without `--no-sandbox`. |
| What share of automation time does SwiftShader take for the target users? | Phase 0 (answered for `hvf`): 0 % for screenshots and PDF output, and 83 % to 98 % for WebGL pages. |
| Does `virglrenderer` with ANGLE on Direct3D 11 render the WebGL conformance subset? | Phase 1 |
| Does `venus` run on Windows hosts with vendor Vulkan drivers on `amd64` and `arm64`? | Phase 2 |
| Which renderer confinement on Windows keeps Direct3D 11 working? | Phase 2 |
| Do the users need headed windows, or is headless rendering enough? | Before Phase 3 |
| Does `venus` run on a macOS host? | Phase 2 (answered): yes, on KosmicKrisp with macOS 26 or later. On MoltenVK 1.4.2, Chromium gets no OpenGL ES 3.0 context. |
| Does Chromium ANGLE on Vulkan render correct WebGL through `venus` on macOS? | Phase 2 (answered for the probe pages of gate G2): yes. The WebGL conformance subset passes with 13 expected regressions in `venus` and `virgl` together. |
| Does Chromium use PRIME or `sync_file` import with `--enable-features=Vulkan`? | Phase 2 (open). The device refuses both today and logs the refusal. |
| Can the host kernel limit the memory of the renderer process? | Phase 2 (open). The limit is a watchdog inside the renderer today. |
| Does Metal work on a hosted macOS CI runner, so that the renderer tests can run in CI? | Phase 2 (open). `scripts/gpu/ci-metal-probe.sh` measures it on a runner through `diagnose.yml`. The repository variable `GVX_CI_METAL=1` then turns on the renderer tests of `ci.yml`. |

---

## 11. Sources (Reference Module)

The external facts of this proposal come from these sources. The facts about `gvx` come from the files that each section names.

| Source | Supports |
| :--- | :--- |
| [Linux `virtgpu_drm.h`](https://github.com/torvalds/linux/blob/master/include/uapi/drm/virtgpu_drm.h) | The `virtio-gpu` ioctls and parameters. |
| [`virglrenderer`](https://gitlab.freedesktop.org/virgl/virglrenderer) | The renderer library, the `vtest` server, and the MIT license. |
| [ANGLE](https://chromium.googlesource.com/angle/angle) | The OpenGL ES implementation on Metal and Direct3D 11, and the BSD-3-Clause license. |
| [UTM graphics architecture](https://github.com/utmapp/UTM/blob/main/Documentation/Graphics.md), [UTM Linux guide](https://docs.getutm.app/guest-support/linux/), [UTM v4.1.6 notes](https://github.com/utmapp/UTM/releases/tag/v4.1.6) | `virgl` over ANGLE on Metal, the `venus` desktop limit, and the default that UTM turned off. |
| [`krunkit`](https://github.com/containers/krunkit), [Red Hat measurement](https://developers.redhat.com/articles/2025/09/18/reach-native-speed-macos-llamacpp-container-inference) | `venus` with MoltenVK for Linux containers on macOS. |
| [WSLg](https://github.com/microsoft/wslg) | The Windows path through Mesa `d3d12` and RDP. |
| [CVE-2019-18389](https://access.redhat.com/security/cve/cve-2019-18389), [CVE-2022-0135](https://access.redhat.com/security/cve/cve-2022-0135) | Guest-triggered memory corruption in `virglrenderer`: heap overflow and out-of-bounds write. |
| [Chromium SwiftShader notes](https://chromium.googlesource.com/chromium/src/+/main/docs/gpu/swiftshader.md) | The deprecation of the automatic SwiftShader fallback for WebGL. |
| [KosmicKrisp](https://docs.mesa3d.org/drivers/kosmickrisp.html) | The Vulkan driver on Metal in Mesa, its conformance, and the macOS 26 requirement. |
| [Mesa merge request 42853](https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/42853) | The removal of the `SYNC_FD` condition on semaphore import for the `venus` swapchain extensions in Mesa 26.2.0. |
| [ANGLE `vk_renderer.cpp`](https://chromium.googlesource.com/angle/angle/+/refs/heads/main/src/libANGLE/renderer/vulkan/vk_renderer.cpp) | The rule that limits ANGLE to OpenGL ES 2.0 without `VK_EXT_provoking_vertex`. |
| [Using GPU Hardware in Headless Chrome](https://chromium.googlesource.com/chromium/src.git/+/main/docs/gpu/using-gpu-hardware-in-headless-chrome.md) | The `--use-angle=vulkan` flag for headless Chromium on Linux. |
