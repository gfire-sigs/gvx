# Windows `systrap` Engine: Measured Behavior and Design

This specification documents the Windows user-mode `systrap` engine (`winsystrap`) inside `pkg/sentry/platform/systrap`. The engine executes unmodified Linux ELF64 guests natively inside unprivileged stub processes without hardware virtualization. It records the empirical measurements gathered on Windows hosts, the resulting architecture, its security boundaries, its known limits, and the procedures to reproduce every probe. Consult [`architecture.md`](architecture.md#33-stub-process-execution-engine-platformsystrap) first for shared `systrap` principles.

| Topic | Summary |
| :--- | :--- |
| **Implementation status** | Complete for `windows/arm64` and `windows/amd64`; passes engine and `e2e/` suites on both hosted Windows runners. |
| **Debug-path stops** | Page faults, signals, and fallback traps route through one native debug object (~70 to 115 us on `arm64`; ~80 to 190 us on `amd64`). |
| **Fast path** | Enabled by default (`GVX_SYSTRAP_FASTPATH=0` disables; `1` makes failure fatal). Patched syscalls bypass the debugger via shared `winSysmsg` pages (Section 6.8). |
| **Security limit** | **Not a syscall sandbox on Windows.** Windows provides no unprivileged filter for NT syscalls; hostile guests can reach NT services under the stub token. Untrusted workloads require `whpx`. |
| **Primary role** | Hosts lacking the Windows Hypervisor Platform (WHP), including `windows-11-arm` runners and Windows-on-ARM VMs under Apple Silicon. |

---

## 1. Purpose and Scope

`platform/whpx` is the primary Windows backend, but several environments lack WHP: GitHub's `windows-11-arm` runner reports `WHvCapabilityCodeHypervisorPresent = 0`, and Apple Silicon virtualization products (such as Parallels, KB 116239) do not expose nested virtualization to Windows guests. `winsystrap` enables native Linux execution and CI testing on those hosts. All Windows files carry `_windows`, `_xplat`, `_windows_amd64`, or `_windows_arm64` suffixes under `pkg/sentry/platform/systrap` (Section 8).

---

## 2. Measurement Method

Every probe below ran as a standalone Go program using only `syscall` and runtime-emitted machine code (requiring no C toolchain) on throwaway orphan branches across GitHub-hosted `windows-latest` (`amd64`) and `windows-11-arm` (`arm64`) runners. Because each result reflects one OS build per architecture, repeat the probes (Section 11) before relying on a figure on a different Windows release.

---

## 3. Verified Findings

Every entry below is an empirical measurement (averages unless noted), with CI run IDs recorded in Section 10.

### 3.1 Virtual Memory and Placeholders

Linux requires 4 KiB mappings of shared memory inside a remote process. Probes confirmed that Windows placeholder APIs eliminate the legacy 64 KiB granularity constraint:

| Probe | `amd64` | `arm64` |
| :--- | :--- | :--- |
| Remote `VirtualAlloc2` placeholder split into 4 KiB placeholders | Works | Works |
| `MapViewOfFile3(MEM_REPLACE_PLACEHOLDER)` at non-64 KiB address and offset | Works | Works |
| Two remote views aliasing one 4 KiB section page | Coherent | Coherent |
| `VirtualProtectEx` on one 4 KiB page inside a 32-page view | Works | Works |
| `UnmapViewOfFile2(MEM_PRESERVE_PLACEHOLDER)` mid-view vs. view base | Fails mid-view; whole view becomes placeholder at base | Same |
| Promoting a `PAGE_READWRITE` view to execute | Fails (`ERROR_INVALID_PARAMETER`) | Fails |
| Reserve 122 TiB high window (`0x40000000000..0x7ee000000000`) pre-loader | `[3 TiB, 16 TiB)` free in 400/400 stubs | Same |
| Reserve low window (`0x10000..0x7ffe0000`) pre-loader | Free in 60/60 suspended stubs; loader stayed clear | Same |
| Reserve middle window + 29 HotSpot windows pre-loader | Occupied in 312/2,712 (11.5%) | Occupied in 318/2,718 (11.7%) |
| Remote 4 KiB split, map, protect, unmap | 4.0, 2.6, 2.0, 2.9 us | 1.7, 1.4, 1.8, 7.2 us |

`VirtualAlloc2`, `MapViewOfFile3`, and `WaitOnAddress` export from `kernelbase.dll` rather than `kernel32.dll`; `nt_windows.go` binds them directly.

### 3.2 Cross-Process Signaling and Process Creation

| Probe | `amd64` | `arm64` |
| :--- | :--- | :--- |
| Cross-process `WaitOnAddress` / `WakeByAddressSingle` over shared memory | No wake in 4,000 ms | No wake in 4,000 ms |
| Cross-process auto-reset event pair round trip | 19.5 to 27.4 us | 12.0 to 12.6 us |
| `CreateProcess(CREATE_SUSPENDED)`, terminate, wait | 1.2 to 2.6 ms | 2.7 to 3.0 ms |

Because `WaitOnAddress` maintains wait queues per process, cross-process fast-path blocking uses NT auto-reset events (Section 6.8).

### 3.3 System Call Behavior

| Probe | `amd64` | `arm64` |
| :--- | :--- | :--- |
| NT service number encoding | `EAX` | Immediate of `svc` (for example, `NtClose` is `svc #0xF`) |
| `syscall` / `svc` in private RWX memory | Executes as NT service | Executes as NT service |
| Linux syscall numbers `0..3` with zero args | Run as NT services `0..3`, return `NTSTATUS` | Same |
| `SetProcessMitigationPolicy(ProcessSystemCallFilterPolicy, FilterId=1)` | `ERROR_INVALID_PARAMETER` | Fails |
| Win32k disable via `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY` | Works | Works |

Windows offers no unprivileged kernel syscall trap: any unpatched `syscall` or `svc` executes as an NT kernel service.

### 3.4 CPU and Register State

| Probe | `amd64` | `arm64` |
| :--- | :--- | :--- |
| User-mode `RDFSBASE` / `WRFSBASE` | Execute | N/A |
| `FS` base after sleep, yield, or 300 ms contention | Reset to `0` | N/A |
| `TPIDR_EL0` across 200 x 5 ms kernel waits and debug stops | N/A | Preserved |
| `x18` across debug stops via `CONTEXT_X18` | N/A | Preserved |
| `mrs x0, ctr_el0`, `ic ivau`, unknown `brk #imm` | N/A | `STATUS_ILLEGAL_INSTRUCTION` |
| `dc cvau`, `dc zva`, `mrs x0, dczid_el0` | N/A | Execute |
| Single-step flag (`TF` / `PSTATE.SS`) | Raises single-step exception | Raises single-step exception |
| `SetThreadContext` with `SegCs = 0` | Truncates upper 32 bits of `RIP` and `RSP` | N/A |

Because Windows zeroes `FS` base on context switches, `winsystrap` reloads `FS` base via a trampoline and repairs mid-run faults (Section 6.6). Every `amd64` `CONTEXT` explicitly sets `SegCs = 0x33` and `SegSs = 0x2b`.

### 3.5 Debugger Path

| Probe | `amd64` | `arm64` |
| :--- | :--- | :--- |
| First-chance exception delivered to debug object before user dispatch | Yes | Yes |
| Park thread (`NtSuspendThread` + `NtDebugContinue`); resume (`SetThreadContext` + `NtResumeThread`) | Yes (peer threads keep running) | Yes |
| Multiple stub processes sharing one debug object | Yes | Yes |
| Full debug-stop round trip in probe | 113 to 132 us | 75 to 93 us |
| Kernel freezes whole stub while exception awaits reply | Yes | Yes |

Parking the faulting thread and replying immediately prevents a blocking Linux syscall from freezing sibling guest threads. On `amd64`, `CONTEXT.ContextFlags` resides at offset `48` behind six home slots.

### 3.6 Stub Process, `ntdll`, and Minimal 1 KiB PE Stub Image

| Probe | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `NtCreateThreadEx(SKIP_LOADER_INIT \| SKIP_THREAD_ATTACH)` in initialized stub | Works | Works |
| Same before loader init + `SetThreadContext` | Works | Kernel ignores context on `arm64` |
| Park initial thread at loader breakpoint (`ntdll!DbgBreakPoint`) | Works | Works |
| Marking `ntdll` `.text` read-only or patching its 524/1,444 syscall sites | Thread creation dies | Same |
| Minimal PE image lacking load-config directory | Exits `0xC000007B` | Same |
| Same with load-config directory (`IMAGE_GUARD_SECURITY_COOKIE_UNUSED`) and high-entropy ASLR | Runs cleanly above 4 GiB | Same |
| Low-integrity restricted token + 1-process job + Win32k block | Works | Works |

Because `NtCreateThreadEx` enters `ntdll!RtlUserThreadStart`, `ntdll` must remain executable and intact. To avoid copying the full Sentry binary per stub, `buildStubImage` emits a minimal 1 KiB high-entropy-ASLR PE image with a valid load-config directory.

> [!IMPORTANT]
> The stub image executes on the host; no peer process of the same user may swap the file between creation and execution.

The stub host creates the file with `CREATE_NEW` and exclusive sharing, writes it, reopens it with read-only sharing (`FILE_SHARE_READ`) kept open until exit, verifies bytes, file index, link count, and absence of reparse points, and launches stubs from its canonical handle path (falling back to the Sentry binary if policy refuses). Median timings across 8 runs on hosted runners:

| Metric | `amd64` (Sentry Copy) | `amd64` (1 KiB PE) | `arm64` (Sentry Copy) | `arm64` (1 KiB PE) |
| :--- | ---: | ---: | ---: | ---: |
| Stub creation time | 6.3 ms | 1.5 ms | 14.8 ms | 4.3 ms |
| Loader time | 16.8 ms | 9.9 ms | 20.0 ms | 21.0 ms |
| `fork` and `wait` | 14.9 ms | 7.1 ms | 24.0 ms | 14.0 ms |
| `fork` and `exec` (minimal ELF) | 12.9 ms | 6.4 ms | 23.7 ms | 21.8 ms |
| Self-test in `New` | 6 to 8 ms | 2 to 3.5 ms | 13 to 17 ms | 5.9 ms |

### 3.7 Instruction Scan of Real Binaries

Scanning 17 `x86-64` and 17 `aarch64` ELF files from Alpine 3.20.10 revealed:

| Measure | `x86-64` (4.42 MB) | `aarch64` (3.81 MB) |
| :--- | ---: | ---: |
| Raw syscall pattern occurrences | 539 (`0F 05`, 121.8/MB) | 478 (`svc`) |
| True syscall instructions (linear decode) | 505 | 478 |
| False positives inside other instructions | 34 (6.3%) | 0 |
| Disagreements across 16 sweep start offsets | 0 | N/A |
| Occurrences in non-executable data | 54 (27.6/MB) | 1 (0.43/MB) |

Blind byte replacement of `0F 05` on `x86-64` would corrupt 34 legitimate instructions; fixed-width `aarch64` exhibits zero false decoding ambiguity.

### 3.8 Engine Measurements

| Measurement (Hosted Runners) | `amd64` | `arm64` |
| :--- | :--- | :--- |
| Single debug-path syscall (`TestManySystemCalls`) | 80 to 190 us | 70 to 115 us |
| `Probe` round trip (2,000 calls) | 78 to 167 us | 68 to 91 us |
| 25 address-space create/release cycles (`TestAddressSpaceChurn`) | 0.4 to 0.5 s | 0.8 s |
| FS-base repairs across 1.5 billion loop iterations | 9 to 12 | N/A |
| Shell `fork` / `fork`+`exec /bin/true` (with stub pool) | 33 ms / 50 ms | 27 ms / 31 ms |
| Fast-path spin round trip (`vector/spin` vs. `always/spin` vs. `novector/spin`) | 0.50-0.56 / 0.67-0.73 / 0.46 us | 11-13 / 11-13 / 10-12 us |
| Fast-path sleep round trip (`vector/sleep`) | 33 us | 21 to 25 us |
| Debug-path trap stops in `e2e/` gates (before vs. after pre-window patching) | 22,819 reduced to 47 | Not measured |
| `git add` 200 small files (sparse vs. dense memory file) | 8-12 s vs. 1.3 s | 12-19 s vs. 0.8 s |

Marking the backing NTFS memory file sparse caused severe cluster-allocation stalls on first writes; `unix.Fallocate` therefore leaves the memory file dense.

### 3.9 Cross-Backend Micro-Benchmarks and Spin Windows

Median values across 3 runs of `TestE2EMicroBench` (`internal/acceptprog/microbench`; `whpx` runs nested on `windows-latest`; `hvf` ran on an 8-core Apple Silicon host):

| Operation | `hvf` | `whpx` (nested) | Win `systrap` `amd64` (before) | Win `systrap` `arm64` (before) | Linux `systrap` `amd64` / `arm64` |
| :--- | ---: | ---: | ---: | ---: | ---: |
| `getpid` | 1.2 us | 19 us | 0.48 us (0.46) | 0.99 us (12) | 4.3 / 3.0 us |
| `open` + `close` | 19 us | 58 us | 9.4 us (10) | 9.4 us (60) | 16 / 16 us |
| 64 B pipe round trip | 12.5 us | 174 us | 18 us (41) | 11 us (58) | 22 / 17 us |
| Futex round trip | 23 us | 159 us | 13 us (27) | 8.9 us (33) | 8.5 / 6.7 us |
| `fork` + `wait` | 0.95 ms | 0.84 ms | 7.1 ms (15) | 14 ms (23) | 2.0 / 1.7 ms |
| `fork` + `exec` minimal | 0.25 ms | 1.9 ms | 6.4 ms (12) | 22 ms (23) | 0.42 / 0.69 ms |
| `gvx.New` | 10 ms | 17 ms | 24-30 ms (65) | 63-73 ms (100) | 2.0 / 2.9 ms |
| `Close` | 0.08 ms | 1.2 ms | 3-4 ms (61-65) | 5.2-5.5 ms (68-76) | 0.005 / 0.012 ms |

Alertable waits (`NtAlertThread`) and parallel pool termination cut `Close` latency from 60-76 ms down to 3-5.5 ms. Fixed-time spin windows calibrated against TSC (`amd64`) and `CNTVCT_EL0` (`arm64`) replaced iteration counts (which gave up after 0.2 us on `arm64` `yield`, causing 92% event wakeups). Sweeping `(stub, sentry)` windows established **64 us stub / 8 us Sentry** (`GVX_SYSTRAP_SPIN_US=64,8`) as the optimal default, lowering event wakes to 0.4% (`amd64`) and 1.0% (`arm64`):

| Runner | Spin Window (us) | `getpid` | `open`+`close` | Pipe | Futex | Sentry Slept | Stub Woken |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| `amd64` | `0, 0` | 30.6 us | 89.1 us | 131.0 us | 72.4 us | 75.0% | 98.9% |
| `amd64` | `16, 1` | 0.50 us | 10.2 us | 61.9 us | 39.6 us | 4.5% | 5.2% |
| `amd64` | `64, 8` (default) | 0.33 us | 5.7 us | 10.4 us | 6.0 us | 0.2% | 0.4% |
| `amd64` | `256, 32` | 0.48 us | 10.0 us | 12.2 us | 9.2 us | 0.1% | 0.4% |
| `arm64` | `0, 0` | 12.9 us | 46.9 us | 64.8 us | 25.9 us | 70.4% | 99.9% |
| `arm64` | `16, 1` | 1.07 us | 13.4 us | 37.4 us | 20.1 us | 4.6% | 6.4% |
| `arm64` | `64, 8` (default) | 0.98 us | 10.6 us | 15.4 us | 11.9 us | 0.2% | 1.0% |
| `arm64` | `256, 32` | 1.06 us | 14.1 us | 11.6 us | 9.8 us | 0.1% | 0.6% |

A deadlock during `fork` (where `stopThread` waited for a thread blocked on a queued cold-resume or relocated-instruction fault event) was eliminated by returning immediately from `stopThread` when an event is already queued (`TestStopThreadReturnsWhenTheThreadWaitsAtAnEvent` and `TestStopThreadReturnsWhenTheThreadFaultsInASlot`; 0 hangs in 32 runs on both runners).

### 3.10 Stub Address Space Between 4 GiB and 16 TiB

`TestProbeStubLayout` (`GVX_PROBE_LAYOUT=N`, 460 stubs per runner) showed that the Windows kernel places two private regions (a 1 MiB initial stack and a non-freeable 2 MiB PEB/TEB region) at a uniform random address between 4 GiB and 1 TiB before user code runs, while `[0x7fff0000, 4 GiB)` and `[3 TiB, 16 TiB)` were free in 400/400 stubs (`KUSER_SHARED_DATA` occupies `[0x7ffe0000, 0x7fff0000)`). Disabling ASLR shifted stack/PEB below 18 MiB, colliding with fixed `ET_EXEC` binaries. Because ARM64 HotSpot 21 probes 38 fixed bases (multiples of 4 GiB up to 28 GiB, and multiples of 32 GiB up to 992 GiB) for single-`MOVK` compressed class pointers, Section 6.2 reserves dedicated windows covering all 38 locations.

---

## 4. Why `ProcessInstrumentationCallback` Is Not Installed

`ProcessInstrumentationCallback` (class 40) fires only after the NT kernel has already executed the system call, cannot prevent the first unintended NT service, and can likely be cleared by a hostile guest calling `NtSetInformationProcess` (inference). `winsystrap` therefore omits it and relies on static page scanning (Section 6.3) within the documented trust boundary (Section 7).

---

## 5. Variable-Length Instruction Patching on `amd64` vs. Fixed-Width `arm64`

On `amd64`, a 2-byte `syscall` (`0F 05`) always admits in-place `CC 90` (`int3; nop`) replacement without relocating neighbors. Five-byte `jmp rel32` fast-path patches require either a post-window or pre-window relocation proving no jump targets lie inside the overwritten bytes (Section 6.8).

To avoid corrupting embedded constants, the `amd64` scanner runs 16 linear `x86asm` sweeps starting 49 to 64 bytes before the page, takes a majority vote among minimum-skip sweeps, bounds scans with ELF section headers, decodes `vzeroupper`/`vzeroall` directly (`decodeX86`, working around an `x86asm` ModRM bug that broke Node 22), skips anonymous RWX pages lacking an ELF/PE backing (preserving V8 inline data), and places dual-`INT3` guards on any residual `0F 05`, `CD 2E`, or `0F 34` byte pairs inside scanned code so Sentry emulates or scratch-executes the enclosing instruction safely.

On `arm64`, every instruction is an aligned 4-byte word, allowing complete scanning of every executable page prior to execution.

---

## 6. Architecture and Design

The Windows engine separates guest address spaces into dedicated stub processes while dispatching faults over a single debug object and fast system calls over shared memory.

### 6.1 Process Topology and Pools

- **Sentry**: Owns backing `MemoryFile`, address-space maps, patcher, and one shared native debug object served by a single OS-locked event pump thread.
- **Stub host**: A pre-lockdown copy of the Sentry binary (`GVX_SYSTRAP_STUBHOST`) communicating over pipes with no arbitrary path/argv arguments. Once initialized, Sentry drops its full-access process handle to a wait-only handle. Keeps up to 12 prepared suspended stubs.
- **Stub processes**: Created from the 1 KiB PE image (Section 3.6) under Low-integrity restricted tokens, protected Process/Thread DACLs, one-process Job Objects, and full process mitigations. Sentry keeps up to 12 loader-initialized ready stubs in a pool (roughly 28 idle stubs total per platform: 12 prepared, 12 ready, 4 in bring-up) and caches up to 4 exited guest threads per live stub. `AddressSpace.Release` always terminates used stubs asynchronously via a reaper goroutine.

### 6.2 Guest Virtual Address Windows

`guestWindows` routes `MapFile`, `Unmap`, and `Protect` calls across 32 placeholder windows (31 holes exported via `UserAddressHoles`):

- **Low window**: `[0x10000, 0x7ffe0000)` for non-PIE `ET_EXEC` binaries (`0x10000` Go `arm64`, `0x400000` standard linkers).
- **Middle window**: `[0x7fff0000, 66 GiB)` holding 9 HotSpot bases and zero-based heaps.
- **29 HotSpot windows**: 2 GiB each from `96 GiB` through `992 GiB`.
- **High window**: `[4 TiB, 0x7ee000000000)`, whose top `0x2010000` bytes reserve engine pages (64 KiB) and 512 per-thread 64 KiB `winSysmsg`/stack areas (`MaxUserAddress = 0x7edffdff0000`).

Because the random PEB/stack pair hits the 120 GiB middle/HotSpot span in ~12% of stubs, bring-up retries up to `windowAttempts = 12` times (mean 1.13 attempts, < 10^-10 total failure rate, hidden by the pool). `sectionCache` backs host-handle files directly; `SetChunkMemory` shares the kernel memory file with `hostfs` and `ext4lite`.

### 6.3 Lazy Execute Page-Trap and Coherence

Pages map non-executable initially. An execute fault triggers private copy creation, instruction scanning/patching, `PAGE_EXECUTE_READ` mapping, and `FlushInstructionCache` (patching all pages touched by the next 15 bytes on `amd64` to handle page-crossing instructions; 3 unpatched retries yield `SIGSEGV`).

A platform-wide frame index (`alias_windows.go`) lowers all peer writable views of any frame holding an active patched copy to read-only so cross-view writes (such as dual-mapped JIT arenas) trap and invalidate stale copies. Sentry writes to guest memory (`read`, `write`, `process_vm_writev`, `MapInternal` writable) notify the platform via `hostwrite_windows.go` to drop stale copies. Repeated identical executable mappings preserve blocks and skip rescans via SHA-256 clean-page hashes.

### 6.4 Stops, Resumes, and Self-Modifying Store Steps

Non-syscall exceptions route through the debug object: patched traps park the thread; execute faults patch; lowered-view writes drop copies and restore write access; `Interrupt` arms `TF`/`PSTATE.SS` while stepping past engine code; `PullFullState`/`FullStateChanged` lazily transfer `CONTEXT_XSTATE` (AVX/AVX-512) or NEON state.

When a guest stores into the very page it executes (`storestep_windows.go`), the engine remaps the copy RWX for one single step (up to 64 steps for `rep` strings), writes only changed bytes back to the original frame, drops all copies, and repatches on the next fetch (cost: 3 debug stops). `arm64` store-exclusives (`stxr`/`stlxr`/`stxp`/`stlxp`) and stores from trampoline slots raise `SIGSEGV`.

### 6.5 `windows/arm64` Patching and TLS

The `arm64` patcher rewrites all 65,536 `svc #imm16` encodings (fast slots for `svc #0`, `brk` for non-zero immediates), 32 each of `mrs/msr tpidr_el0`, `mrs ctr_el0` (emulated as `0xb444c004` with `DIC`/`IDC` set), `ic ivau`, and 160 `dc` cache-maintenance ops (`nop`ed because copy mapping flushes I-cache). Because `CONTEXT` omits `TPIDR_EL0`, an engine-page stub writes it on debug mode; fast mode stores `winSysmsg` in hardware `TPIDR_EL0` and guest TLS in `winSysmsg.TLS`.

### 6.6 `windows/amd64` Patching and FS-Base Repair

Every `syscall` becomes `CC 90` (or fast `jmp rel32`), `RDFSBASE`/`RDGSBASE` and `%gs:` accesses patch or trap, and per-thread trampolines reload `FS` base (`wrfsbase rax`) on start. Mid-run faults caused by Windows resetting `FS` base are emulated directly by Sentry (`ReadProcessMemory` / writable-verified writes, excluding atomics) so heavy concurrency cannot exhaust the 8-retry identical-register fault guard (fixing Node.js issue #24).

### 6.7 Stub Confinement

Stubs run under Low integrity, zero privileges, deny-only logon/extra group SIDs, a per-stub random restricting SID (`S-1-9-...`), protected Process/Thread/default DACLs excluding Everyone, a one-process UI-restricted Job Object, and tiered process mitigations (Win32k, strict handles, extension points, fonts, remote/low-label images, child processes). Stubs hold zero file handles (and only two limited event handles per fast-path thread).

### 6.8 Shared-Memory Fast Path

Enabled by default after a 6-syscall self-test in `New`. Each thread owns a 4 KiB `winSysmsg` page and 4 KiB spill stack in the high-window arena, plus two auto-reset events created by the stub host. Sealed 4 KiB island pages (allocated preferentially below code to leave `brk` heap room) hold 64-byte trampoline slots within 120 MiB of patched code.

States transition from `Idle` to `Trapped`, then to either `RunHot` (unchanged PC/SP, returning through the slot tail) or `RunCold` (modified PC/SP/TLS, trapping into the debug path). Release and acquire atomics, calibrated spin windows (64 us / 8 us), and conditional event signaling (`StubWaiter`/`SentryWaiter`) synchronize the handoff. Vector state (`XSAVE64`/`XRSTOR64` mask `0xE7` at offset `0x100` on `amd64`; `V0..V31`/`FPSR`/`FPCR` on `arm64`) saves unconditionally on trap and reloads conditionally on `RunHot` only if `ntdll` was called (`R14`/`x21`) or Sentry set `FPDirty`.

- **`arm64` `svc` slot**: Temporarily spills guest `x18` to `sp - 64` (preserving the 32 bytes below `sp` used by Go `clone`), moves it to `winSysmsg.X18`, and restores it on return. Invalid/unaligned `sp` faults cleanly to the debug path.
- **`amd64` post-window and pre-window slots**: Post-window overwrites `syscall` plus >= 3 following bytes (relocating RIP-relative operands and `jcc`/`jmp`, avoiding non-returning calls and internal branch targets). When post-window fails (for example, musl `syscall; ret`, Go `osyield`, glibc `getpid`), pre-window overwrites 5 to 9 preceding bytes (12/16 sweep consensus) while keeping `CC 90` at `syscall`, translating faulting and stepping PCs back to original addresses.
- **Restart-PC invariant**: `continueAt` records in-place resume targets in `restartPC` and active slots record `islandSlot.resume` so `patchBlock` never overwrites an interior byte of any live resume address.

### 6.9 Epoch-Based Island Slot Reclamation

Slots progress in strict lifecycle order: `Free`, `Allocated`, `Live`, `Quarantined`, and back to `Free`. Retiring a block removes its executable page before stamping slots with an incremented epoch counter. Each guest thread maintains an online/offline epoch and a pinned slot address (offline while trapped or parked; pinned while resuming through a slot tail). `reclaim` frees a `Quarantined` slot only once every reader is offline or entered online after the stamp and holds no pin on it. If 4,096 allocation units (16 island pages) accumulate in quarantine, new sites stay on the debug path until active threads reach a quiescent point.

---

## 7. Security Model

| Backend | Kernel Syscall Filter | Guest Can Reach Host Services | Containment Basis |
| :--- | :--- | :--- | :--- |
| Linux `systrap` | `seccomp` trap | No | Host kernel filter |
| `whpx` and `hvf` | N/A | No | Hardware virtualization |
| Windows `arm64` `systrap` | None | Yes (via `ntdll` stubs) | Restricted token, Job, mitigations, full page scan |
| Windows `amd64` `systrap` | None | Yes (via `ntdll` stubs and anonymous RWX JIT pages) | Restricted token, Job, mitigations, ELF/PE page scan |

**Always state this boundary clearly**: Windows `systrap` is not a syscall sandbox. `--backend=auto` fails closed when `whpx` is unavailable unless `-allow-unconfined-systrap` opts in. Untrusted Windows workloads must run under `whpx`.

---

## 8. Implementation Map

| Files in `pkg/sentry/platform/systrap/` | Role |
| :--- | :--- |
| `nt_windows.go`, `stubhost_windows.go`, `debug_windows.go`, `stubproc_windows.go`, `thread_windows.go` | NT bindings, stub host, debug object pump, stub bring-up, thread park/resume. |
| `address_space_windows.go`, `section_windows.go`, `alias_windows.go`, `viewmap_xplat.go`, `windowlayout_xplat.go` | Placeholder window map, 32-window layout, lazy patching, frame alias coherence. |
| `context_windows.go`, `platform_windows.go`, `probe_windows.go`, `arch_windows_*.go`, `hostctx_*.go` | `Context.Switch`, signals, architecture patchers/TLS/FS repair, XSTATE context conversion. |
| `storestep_windows.go`, `hostwrite_windows.go`, `residency_windows.go` | Self-modifying store steps, Sentry write observer, `K32QueryWorkingSetEx` memory accounting. |
| `patcher_amd64_xplat.go`, `code_image_xplat.go`, `winsysmsg*_xplat.go`, `stubcode_*_xplat.go`, `islandslot_xplat.go`, `sites_amd64_xplat.go` | `x86asm` multi-sweep scanner, `winSysmsg` ABI, machine-code generators, slot records. |
| `fastpath_windows.go`, `fastisland_windows.go`, `fastselftest_windows.go` | Fast-path handoff, epoch-quarantined islands, 6-syscall startup self-test. |
| Unit tests | `engine_windows*_test.go`, `fastpath_windows_test.go`, `fastisland_windows_test.go`, `lockdown_windows_test.go`, `viewmap_xplat_test.go`, `patcher_amd64_xplat_test.go`, `hostctx_xplat_test.go`, `winsysmsg_xplat_test.go`, `stubcode_*_xplat_test.go`. |

---

## 9. Limits and Open Work

| Area | Current Behavior and Limit |
| :--- | :--- |
| Fast path | On by default; spin hits achieve 0.5 us (`amd64`) / 11-13 us (`arm64`), sleep path 21-33 us vs. 70-190 us debug stops. |
| Address-space holes | Mappings cannot occupy `< 0x10000`, `[0x7ffe0000, 0x7fff0000)`, or the 30 holes between 66 GiB and 4 TiB. All 38 ARM64 HotSpot bases are covered. |
| Fixed-range guests (ASan, Wine 64-bit) | AddressSanitizer (`amd64` ~14 TiB from 2 TiB; `arm64` 8 GiB from `0xffffff000`) and Wine 64-bit (`[0x110000, 8 GiB)`) fail at startup because reservations cross holes. Run on `whpx`. |
| Executing-page stores | Served via 3-stop store steps; `arm64` store-exclusives and trampoline-slot stores raise `SIGSEGV`; storing a byte matching a patch byte (`CC`/`90`) is not written back. |
| Sentry memory writes | `hostwrite_windows.go` drops stale copies on `MapInternal`/chunk-cache/MM writes. |
| `arm64` stack red zone & literal pools | Fast `svc` writes one word at `sp - 64`; `arm64` scans all executable pages so inline literal constants matching `svc` or patched system ops rewrite in the read copy. |
| `membarrier` | Expedited global/private commands work across all stubs via thread suspend + `GetThreadContext` + resume + `FlushProcessWriteBuffers` (relying on NT APC/context-switch barriers). |
| GS base & workspace files | `ARCH_SET_GS` virtualized via `%gs:`/`RDGSBASE`/`WRGSBASE` rewriting; `SetChunkMemory` supports writable shared `hostfs`/`ext4lite` mappings (handle-less `memmap.File` maps read-only). |
| Unpatched syscalls | Hostile branches to `ntdll` or anonymous `amd64` RWX JIT pages invoke NT services under the restricted stub token. |
| Verified JIT runtimes | Node 20/22/24 (`npm install`, `tsc`, esbuild, swc, Vite, `docker build`) and Temurin 21 (`TestE2EGateJVM`, HotSpot C2 + `membarrier`) pass on both Windows runners; Temurin 25 starts on `windows-11-arm`. Other JVMs untested. |
| Endpoint protection | Stub host, debug object, and executable views are untested under default Microsoft Defender settings. |
| Code self-reads & trap flag | Reading executing pages observes patched bytes; guests using the CPU trap flag directly may lose one step. |
| Island quarantine & memory accounting | Non-trapping threads hold quarantined slots up to 4,096 units (falling back to debug stops). `K32QueryWorkingSetEx` charges stub pages so `memory.max` operates on Windows `systrap`. |

---

## 10. Evidence Log (GitHub Actions Run IDs)

| CI Run IDs | Runners | Verified Behavior |
| :--- | :--- | :--- |
| `39790745508`, `39791228959`, `39791535847`, `39796084304` | Both | Exports, placeholders, remote 4 KiB cost, FS loss, events, `arm64` registers, debugger latency. |
| `39800771242`, `39802593217`, `39803097982`, `39803487649`, `39809735687`, `39811366093` | Both | `ntdll` patching limits, FS recovery, Low-integrity token/job/Win32k, multi-stub debug object. |
| `39864134146..39872813269`, `39870353585` | Both | Sparse vs. dense memory file `git add`, stub pool `fork`/`exec`, full registry gates (207 s / 281 s). |
| `39845577561`, `39846215053`, `39853085199..39855645886` | `arm64` / `amd64` | Node 22 `dc civac` fix; EPYC 9V74 page-crossing `call` fix (12/12 pass). |
| `39898594534..39905154834` | Both | Low window (`0x10000..0x7ffe0000`), `herdr` `ET_EXEC`, address-hole forwarding for Node/V8. |
| `41719899003..41751797551` | Both | Stub layout (460 stubs), HotSpot 21 38-location middle/HotSpot windows, `TestE2EGateJVM`, ASan probe. |

---

## 11. Reproduction Procedures

> [!CAUTION]
> Execute raw machine-code probes only on a throwaway branch and delete the branch afterward.

1. Run layout, bring-up, micro-benchmark, and fast-path benchmarks via the `diagnose` workflow on `windows-latest` and `windows-11-arm`:

```bash
# Stub address-space layout probe (emits PROBELAYOUT, PROBEREGION, PROBECAND, PROBEIDENT, PROBESUMMARY)
GVX_PROBE_LAYOUT=200 go test -count=1 -v -run TestProbeStubLayout ./pkg/sentry/platform/systrap/ | grep PROBE

# Production bring-up retry measurement (emits PROBEBRINGUP)
GVX_PROBE_BRINGUP=1200 go test -count=1 -v -timeout 28m -run TestProbeBringUp ./pkg/sentry/platform/systrap/ | grep PROBE

# Cross-backend micro-benchmarks (add GVX_E2E_BENCH_ONLY=fork_wait or GVX_E2E_BENCH_REPEAT=8)
GVX_E2E_BENCH=1 go test -count=1 -v -timeout 25m -run TestE2EMicroBench ./e2e/

# Fast-path round-trip and spin-sweep benchmarks
go test -run '^$' -bench BenchmarkFastPathRoundTrip -benchtime 2s -count 3 ./pkg/sentry/platform/systrap/
go test -run '^$' -bench BenchmarkFastPathSpinSweep ./pkg/sentry/platform/systrap/
```

For runtime diagnostics, set `GVX_SYSTRAP_TRACE=1` (guest exception signals), `2` (every stop plus 3 s stub dumps, capped at 200,000 lines), `3` (stop and `amd64` patch outcome summaries without timing distortion, capped at 400 lines), or `4` (5 ms hot-PC sampling).

---

## 12. External Sources

| Source | Relevance |
| :--- | :--- |
| [Pico Process Overview](https://learn.microsoft.com/en-us/archive/blogs/wsl/pico-process-overview) | Absence of third-party Windows pico-process APIs. |
| [MapViewOfFile3](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3) | `MEM_REPLACE_PLACEHOLDER` lifting 64 KiB alignment. |
| [WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress) | Same-process waking requirement. |
| [Windows ARM64 ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=msvc-170) | `x18` TEB convention and reserved `TPIDR_EL0`. |
| [ntdoc ProcessInfoClass](https://raw.githubusercontent.com/m417z/ntdoc/main/descriptions/processinfoclass.md) | Unprivileged `ProcessInstrumentationCallback` installation. |
| [Parallels KB 116239](https://kb.parallels.com/en/116239) | Absence of nested virtualization on Apple Silicon. |
| [ASC-Hook](https://arxiv.org/abs/2412.05784) | Prior art for ARM64 `svc` binary rewriting. |
| [gVisor `systrap` README](https://github.com/google/gvisor/blob/master/pkg/sentry/platform/systrap/README.md) | Upstream Linux `seccomp` trap architecture. |
