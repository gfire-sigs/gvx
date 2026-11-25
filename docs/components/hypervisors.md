# Hardware Hypervisor Backends: `whpx`, `hvf`, and `hvcommon`

This specification describes the two hardware-assisted execution backends of `gvx`: `platform/whpx` on Windows (`amd64` and `arm64`) and `platform/hvf` on macOS (`arm64`), together with their shared foundation `platform/hvcommon`. Both backends execute unmodified Linux ELF64 instructions at Ring-3 or EL0 inside an unprivileged hardware virtualization partition without booting a Linux kernel.

---

## 1. Purpose and Scope

Linux ELF64 binaries map code and data segments at 4 KiB (`0x1000`) boundaries, whereas Windows `VirtualAlloc` enforces 64 KiB allocation granularity and Apple Silicon XNU enforces 16 KiB host pages. Hardware virtualization resolves both mismatches cleanly. By placing guest code inside a virtual address space managed by 4 KiB guest page tables, `whpx` and `hvf` enforce exact 4 KiB read, write, and execute permissions while isolating guest memory from the host Go heap.

| Property | `platform/whpx` (Windows) | `platform/hvf` (macOS) |
| :--- | :--- | :--- |
| **Host targets** | `windows/amd64` (Windows 10 2004+ / Windows 11); `windows/arm64` (Windows 11 24H2, Build `26100.3915+`) | `darwin/arm64` (Apple Silicon M1 through M5) |
| **Host API** | `WinHvPlatform.dll` (`WHvCreatePartition`, `WHvRunVirtualProcessor`) | `Hypervisor.framework` (`hv_vm_create`, `hv_vcpu_run`) |
| **Privilege requirement** | Standard user account; Windows Hypervisor Platform optional feature enabled | Standard user account; binary signed with `com.apple.security.hypervisor` |
| **Guest paging** | 4 KiB guest page tables over Stage-2 GPA (`WHvMapGpaRange`) | 4 KiB Stage-1 (`TTBR0_EL1`, `TCR_EL1.TG0=0b00`) over 16 KiB Stage-2 (`hv_vm_map`) |
| **Shared VM model** | One partition per platform instance | Process-wide shared VM (`vmGlobal`, reference-counted) because XNU permits one VM per process |

---

## 2. Design and Invariants

Both backends avoid per-syscall host register API overhead by installing minimal Ring-0 (`amd64`) or EL1 (`arm64`) guest stubs that spill system-call registers into a shared 304-byte `CommHeader` page before exiting to the Sentry.

![Hypervisor Fast-Path Syscall and Fault Sequence](../assets/hypervisor-trap.svg)

### 2.1 Two-Stage 4 KiB Paging and Zero-Hypercall Faults

Both `whpx` and `hvf` register backing chunks of `pgalloc.MemoryFile` with the hypervisor once rather than on every guest page fault:

- On Windows, `whpx` maps each `MemoryFile` chunk into a dynamic 36-to-40-bit GPA window once via `WHvMapGpaRange` with writable permissions. Transient non-memory files track separate read-only and writable Stage-2 regions and unmap via `WHvUnmapGpaRange` once unreferenced. `MemoryManager.PinRange` (`mm/pinned_xplat.go`) keeps backing frames pinned while Stage-2 mappings exist.
- On macOS, `hvf` maps each 1 GiB `MemoryFile` chunk into Stage-2 IPA once with `HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC`. `MapFile` and `Unmap` mutate only 4 KiB Stage-1 `TTBR0_EL1` entries. Because the ARM64 MMU enforces the intersection of Stage-1 and Stage-2 permissions, permission violations trap at exact 4 KiB boundaries. Because `hv_vm_map` rejects read-only EROFS descriptors, `hvf` copies read-only file blocks into 64 KiB `MAP_ANON` buffers (`CopyReadOnly`) and releases them when unmapped. A 256-page (`4 MiB`) VM slab allocates Stage-1 tables, the EL1 vector page, and per-worker communication pages.

`Platform.MapUnit` returns 2 MiB on both backends, and `SupportsAddressSpaceIO` returns false so the Sentry reads and writes guest memory through its own host mapping. On `arm64`, mapping a page with execute permission flushes the guest instruction cache, preserving correctness for ELF loading, `mprotect`, and copy-on-write. During teardown, `Sandbox.Close` closes the platform before destroying `pgalloc.MemoryFile` chunks so GPA mappings never outlive their backing host views.

### 2.2 Syscall Traps, Thread Affinity, and Register State

- **`whpx` (`amd64`)**: Ring-3 `SYSCALL` enters Ring-0 `MSR_LSTAR`, writes syscall general-purpose registers to `CommPage`, and executes `HLT`. `whpx` writes `CR3` on the host before running a virtual processor whose recorded address space changed; kicks, cancellations, and `AddressSpace.Release` invalidate that record. Fast paths leave `YMM0..15` and AVX-512 state inside the vCPU; cold paths convert compacted XSAVE state through `fp.go` while preserving hypervisor supervisor components and `XCOMP_BV`.
- **`whpx` (`arm64`)**: Configures GICv3 before partition setup with one redistributor per vCPU and clears startup suspension. EL0 `SVC #0` enters EL1 vectors, spills registers to `CommPage`, and triggers a memory exit by loading from unbacked GPA zero (because WHP consumes `HVC #0` without exiting). Because a memory exit leaves PC on the load instruction, each stop advances PC once before resume.
- **`hvf` (`arm64`)**: Dedicated `vcpuWorker` OS threads (`runtime.LockOSThread`) own each `hv_vcpu_t`, because `Hypervisor.framework` binds each vCPU to its creating thread. EL0 `SVC #0` enters `VBAR_EL1`, spills `X0..X8`, `SP_EL0`, `ELR_EL1`, and `PSTATE` to `CommPage`, and executes `HVC #0`. On `HV_EXIT_REASON_UNKNOWN`, the worker resumes the vCPU up to 4,096 consecutive times before failing `Switch`. Because each vCPU is thread-bound, `hvf` synchronizes general and FP registers from `arch.Context64` on every `Switch`.

### 2.3 CPU Feature Exposure and `membarrier`

Guests must never observe CPU features they cannot execute. One `cpuid.FeatureSet` drives `/proc/cpuinfo`, `AT_HWCAP`, signal frames, and `sigreturn` validation:

| Backend | Guest CPUID or ID Registers | Sentry Feature Set |
| :--- | :--- | :--- |
| **`whpx` (`amd64`)** | `vector.go` configures `ProcessorXsaveFeatures` and XCR0, hiding MPX, AMX, XFD, XCR1, and AVX10 while keeping `XsaveComp` and `XsaveSupervisor`. `New` verifies compacted XSAVE layout against CPUID leaf `0xD` on a probe vCPU and fails on mismatch. | `Platform.GuestFeatureSet` strips hidden features and reports guest XCR0 in leaf `0xD`. |
| **`whpx` (`arm64`)** | `hvcommon.DefaultIDRegisters`. | `AT_HWCAP` retains only host features reported in those ID registers. |
| **`hvf` (`arm64`)** | Host ID registers with PAC, SVE, MTE, SME, and MPAM masked. | `AT_HWCAP` derived from `hw.optional` sysctl keys. |

For `membarrier(2)`, `whpx` cancels active virtual processors with `WHvCancelRunVirtualProcessor`, waits for their `Switch` returns, and calls `FlushProcessWriteBuffers` to order Sentry threads. `hvf` cancels active vCPUs with `hv_vcpus_exit` and awaits one exit from `hv_vcpu_run`.

---

## 3. Verified Measurements

The `TestE2EMicroBench` results below come from the [`bench-results`](https://github.com/gfire-sigs/gvx/tree/bench-results) branch (`darwin/arm64` physical Apple Silicon host at commit `ce792c97`; `windows/amd64` nested GitHub runner at commit `d77169d3`). Re-run locally with `GVX_E2E_BENCH=1 go test -count=1 -v -run TestE2EMicroBench ./e2e/`.

| Backend and Host | `host_new` | `getpid` | `open_close` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `hvf` (`darwin/arm64`, physical) | 11.39 ms | 1.3 us | 5.2 us | 15.1 us | 25.9 us | 0.94 ms | 0.23 ms |
| `whpx` (`windows/amd64`, nested CI VM) | 12.24 ms | 12.4 us | 29.0 us | 74.4 us | 69.6 us | 0.99 ms | 1.12 ms |

---

## 4. Known Limits

- **No nested virtualization on hosted macOS runners or Apple Silicon VMs**: `hvf` requires a physical Apple Silicon Mac.
- **macOS `membarrier` coverage**: Because macOS lacks an all-thread process memory-barrier primitive, `hvf` `GlobalMemoryBarrier` orders guest vCPU code only and does not order Sentry goroutines accessing guest memory during concurrent system calls.
- **`hvf` omitted registers**: `hvf` does not virtualize `TPIDRRO_EL0`, ARM64 PAC key registers, or hardware debug registers (`DBGBVR`/`DBGWVR`).
- **Sentry writes to active `arm64` code pages**: A Sentry write into a page already mapped executable does not flush the guest instruction cache until an executable mapping change occurs.
- **Same-architecture restriction**: Neither backend translates foreign instruction sets (`linux/amd64` on `amd64` only; `linux/arm64` on `arm64` only).

---

## 5. Implementation Map

| Package and Files | Role |
| :--- | :--- |
| `pkg/sentry/platform/hvcommon/` (`a64.go`, `x86.go`, `pagetables.go`, `regions.go`) | Shared Stage-2 `RegionTable`, Stage-1 `PageTablePool`, 304-byte `CommHeader`, AArch64/x86-64 encoders, `DefaultIDRegisters`, TSS/IDT templates. |
| `pkg/sentry/platform/whpx/` (`whpx.go`, `backend_windows.go`, `gpa.go`, `vcpu_*.go`, `stubgen_*.go`, `vector.go`, `fp.go`) | WHP partition lifecycle, dynamic GPA mapper, x86-64 and ARM64 vCPU loops, Ring-0/EL1 stub generators, compacted XSAVE conversion. |
| `pkg/sentry/platform/hvf/` (`hvf.go`, `vm_darwin.go`, `worker_darwin.go`, `stage1*.go`, `bluepill_arm64.go`, `vcpu_darwin_arm64.go`, `entitlement_darwin.go`) | Shared VM lifecycle, thread-locked vCPU workers, 4 KiB Stage-1 page tables, EL1 bluepill stub, entitlement verification. |
| Tests | `pkg/sentry/platform/whpx/*_test.go`, `pkg/sentry/platform/hvf/*_test.go`, `pkg/sentry/platform/hvcommon/*_test.go`, and `e2e/gate_m2_test.go` through `e2e/k3s_*.go`. |
