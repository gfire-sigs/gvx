# Windows `systrap` Engine: Measured Behavior and Design

This document describes the `systrap` engine for Windows. The engine runs a Linux guest natively inside a stub process, without a hypervisor. The document records what the project measured on Windows hosts, the design that those measurements allow, and the limits of the result. Read [`architecture.md`](architecture.md) section 3.3 first for the shared `systrap` concepts.

| Topic | Result |
| :--- | :--- |
| Status | Implemented for `windows/arm64` and `windows/amd64`. The engine runs the Sentry and its guests on both hosted runners. |
| Stops | Every system call, page fault, and signal reaches the Sentry through a debug object. One stop costs about 70 to 115 µs on `arm64` and about 80 to 190 µs on `amd64`, depending on the host. |
| Not implemented | A fast path that skips the debugger. Section 9 lists it as the main performance work. |
| Security | ARM64 seals native syscall instructions and uses separate AppContainers for Sentry and stubs. AMD64 requires trusted execution without host lockdown. |
| Value | Hosts without the Windows Hypervisor Platform (WHP): the `windows-11-arm` runner, and Windows on ARM virtual machines on Apple silicon. |

## 1. Purpose and Scope

The `whpx` backend is the primary Windows engine. It needs WHP. Some hosts have no WHP. The `windows-11-arm` hosted runner reports `WHvCapabilityCodeHypervisorPresent = 0`. Parallels states that Apple silicon hosts do not support nested virtualization (KB 116239, reviewed October 2024). Windows on ARM virtual machines there therefore probably lack WHP.

The `systrap` engine lets those hosts run guests. It also lets CI run real guests on `windows-11-arm`. The `windows-latest` runner has WHP (`present = 1`), so the `amd64` engine matters less than the `arm64` engine. Both engines pass the same tests.

The package `pkg/sentry/platform/systrap` holds the code. The files with the suffix `_windows`, `_xplat`, and `_windows_amd64` or `_windows_arm64` belong to `gvx`. Section 8 maps the files.

## 2. Measurement Method

The probes are Go programs in [`windows-systrap-probes/`](windows-systrap-probes/). They use only the `syscall` package and raw machine code that the probe generates at run time. They need no C toolchain.

Each probe ran on a throwaway orphan branch. A workflow with `on: push` built the probe and ran it on two GitHub-hosted runners. `windows-latest` is `amd64`. `windows-11-arm` is `arm64`. The engine tests ran on the same runners through the workflow that section 10 describes.

All results come from one image per architecture. Another Windows build can differ. Repeat the probes on the target build before you rely on a number. Section 11 gives the procedure.

## 3. Verified Findings

Every row below is a measurement unless the row says "documented". Times are averages. Run identifiers appear in section 10.

### 3.1 Memory

The engine needs 4KB mappings of a shared memory file in the address space of another process. The original SPEC assumed 64KB regions. The probes show that placeholders remove that limit.

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `VirtualAlloc2` placeholder in a remote process, split into 4KB placeholders | works | works |
| `MapViewOfFile3` with `MEM_REPLACE_PLACEHOLDER` at a non-64KB address and offset | works | works |
| Two remote addresses map the same 4KB section page | both read the same bytes | both read the same bytes |
| Protection change on one 4KB page inside a 32-page view | works | works |
| `UnmapViewOfFile2` with `MEM_PRESERVE_PLACEHOLDER` at the middle of a view | fails | fails |
| Same call at the base of a view | the whole view becomes a placeholder | same |
| A view that starts as `PAGE_READWRITE`, then changes to execute | fails with `ERROR_INVALID_PARAMETER` | fails |
| Reserve 110 TiB (`0x100000000000` to `0x7ee000000000`) as one placeholder before the loader runs | succeeds in every stub of the probe and of the engine tests | same |
| Reserve `0x10000` to `0x7ffe0000` as one placeholder before the loader runs | free in 60 of 60 suspended processes; the loader never used it; 64KB views mapped at `0x10000`, `0x400000`, and `0x7ffc0000` | same |
| Remote 4KB split, map, protect, unmap | 4.0, 2.6, 2.0, 2.9 µs | 1.7, 1.4, 1.8, 7.2 µs |

The window map in section 6.2 follows these rules. A mapping of arbitrary size becomes one view. A partial unmap unmaps the whole view and maps the surviving parts again.

The exports `VirtualAlloc2`, `MapViewOfFile3`, and `WaitOnAddress` live in `kernelbase.dll`. They are not exports of `kernel32.dll` on either runner. `pkg/memutil/memutil_windows.go` looks up `MapViewOfFile3` in `kernel32.dll`, so that path always falls back to `MapViewOfFile`. The fallback works for mappings in the current process. The engine binds its own calls in `nt_windows.go`.

### 3.2 Signaling and Process Cost

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `WaitOnAddress` woken by `WakeByAddressSingle` from another process over shared memory | no wake in 4000 ms | no wake in 4000 ms |
| Round trip of two auto-reset events between two processes | 19.5 to 27.4 µs | 12.0 to 12.6 µs |
| `CreateProcess(CREATE_SUSPENDED)`, terminate, wait | 1.2 to 2.6 ms | 2.7 to 3.0 ms |

`WaitOnAddress` keeps its wait list in the memory of one process, so it cannot signal across processes. The event round trip is the cost that a fast path would pay. The current engine does not use events.

### 3.3 System Call Behavior

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| Service number location | `EAX` | immediate of `svc` (`NtClose` is `svc #0xF`) |
| `syscall` or `svc` executed from private RWX memory | runs as an NT service | runs as an NT service |
| Linux numbers 0 to 3 with zero arguments | NT services 0 to 3 run and return `NTSTATUS` | same |
| `SetProcessMitigationPolicy(ProcessSystemCallFilterPolicy)` with `FilterId = 1` | fails with `ERROR_INVALID_PARAMETER` | fails |
| Win32k disable at process creation (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`) | works | works |

Windows traps no system call instruction. An unpatched Linux `syscall` or `svc` runs as the NT service with the same number. The call returns an `NTSTATUS` in the register where the guest expects a Linux result. Windows offers no per-process filter to an unprivileged process.

### 3.4 CPU State

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `RDFSBASE` and `WRFSBASE` in user mode | execute | not applicable |
| FS base after a sleep, a yield, or 300 ms of contention | reset to 0 | not applicable |
| `TPIDR_EL0` with a junk value across 200 real 5 ms kernel waits, and across a debug stop | kept | kept |
| `x18` with a junk value across a debug stop, set and read with `CONTEXT_X18` | not applicable | kept |
| `mrs x0, ctr_el0` | not applicable | `STATUS_ILLEGAL_INSTRUCTION` |
| `ic ivau` | not applicable | `STATUS_ILLEGAL_INSTRUCTION` |
| `brk #imm` with an unknown immediate | not applicable | `STATUS_ILLEGAL_INSTRUCTION` |
| `dc cvau`, `dc zva`, `mrs x0, dczid_el0` | not applicable | execute |
| Single-step flag in `CONTEXT` (`TF`, or `PSTATE.SS`) | raises a single-step exception | raises a single-step exception |
| `SetThreadContext` with `SegCs = 0` | the thread loses the upper 32 bits of `RIP` and `RSP` | not applicable |

Windows resets the FS base of a thread when it switches contexts. A Linux `amd64` guest keeps its thread pointer there. Section 6.6 describes the repair. On `arm64`, Windows uses `x18` for the TEB and treats `TPIDR_EL0` as reserved. Neither register changed across real waits or debug stops.

The last row is a trap for any code that builds a `CONTEXT` from zero. A zero `SegCs` puts the thread in 32-bit compatibility mode. The engine sets `SegCs = 0x33` and `SegSs = 0x2b` in every record.

### 3.5 Debugger Path

A debugger process receives a guest fault before Windows runs any user-mode dispatch code in the stub. This is the Windows analog of `ptrace`.

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| First-chance exception reaches the debug object with the faulting address | yes | yes |
| `GetThreadContext` and `SetThreadContext` change registers and resume | yes | yes |
| Park a thread: `NtSuspendThread`, then `NtDebugContinue`. Other threads of the process run on. | yes | yes |
| Resume a parked thread: `SetThreadContext`, then `NtResumeThread` | yes | yes |
| Two stub processes on one debug object, events carry the right process ID | yes | yes |
| Time per stop (event, read context, park, set context, resume) in the probe | 113 to 132 µs | 75 to 93 µs |
| Process-wide freeze while one exception waits for a reply | yes | yes |

The kernel freezes every thread of the process while an exception waits for a reply. A blocking Linux system call in the Sentry would then freeze the guest threads that could unblock it. The engine parks the thread and replies at once. The cost is one suspend and one resume for each stop.

Caution for `amd64`: the `CONTEXT` structure starts with six home slots, so `ContextFlags` sits at offset 48. A wrong offset returns an all-zero context and no error.

### 3.6 Stub Process and `ntdll`

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `NtCreateThreadEx` with `SKIP_LOADER_INIT` and `SKIP_THREAD_ATTACH` runs code in a running or an initialized process | yes | yes |
| Same call in a process that never ran its loader, then `SetThreadContext` before the first run | the context applies | the thread ignores the context and runs `ntdll` start code |
| Let the loader finish with a debug object attached, then park the initial thread at the initial breakpoint | yes | yes |
| Thread start at `ntdll!DbgBreakPoint`, then `SetThreadContext` while the thread is parked | yes | yes |
| Same call after `ntdll` `.text` becomes read-only | the thread did not run and the process died | same |
| Same call after every syscall instruction in `ntdll` `.text` becomes an undefined instruction (524 and 1444 sites) | the thread did not run and the process died | same |
| A generated minimal PE image with no imports | starts, then exits with `0xC000007B` | same |
| Low-integrity restricted token, one-process job, Win32k disable, all at creation | works with the whole flow | works with the whole flow |

A new thread starts in `ntdll!RtlUserThreadStart`. The engine keeps its executable bootstrap code and replaces native ARM64 syscall instructions after loader initialization. `NtCreateThreadEx` skips loader initialization for guest threads. The engine generates a minimal PE image without imports or a Go runtime. It parks the initial thread before the entry point runs.

### 3.7 Instruction Scan of Real Binaries

The scan in [`windows-systrap-probes/x86scan/`](windows-systrap-probes/x86scan/) read the Alpine 3.20.10 root filesystems. It covered 17 `x86-64` ELF files and 17 `aarch64` ELF files.

| Measure | `x86-64` | `aarch64` |
| :--- | :--- | :--- |
| Executable bytes scanned | 4.42 MB | 3.81 MB |
| Syscall pattern in executable bytes | 539 pairs of `0F 05` (121.8 per MB) | 478 words of `svc` |
| Real syscall instructions by linear decode | 505 | 478 |
| Pattern inside another instruction | 34 (6.3% of the pairs) | 0 |
| Labels that changed between 16 sweep start offsets | 0 | not applicable |
| Pattern in non-executable data | 54 pairs (27.6 per MB) | 1 word (0.43 per MB) |

A blind byte replacement of `0F 05` would corrupt 34 instructions in 4.42 MB of `x86-64` code. On `aarch64`, every aligned word is an instruction, and the pattern is a 32-bit value. The decode was stable on this compiler output. The sample is small and it holds no JIT code.

### 3.8 Engine Measurements

These numbers come from the engine tests and the stub probe on the hosted runners.

| Measure | `amd64` | `arm64` |
| :--- | :--- | :--- |
| One guest system call, `TestManySystemCalls` | 80 to 190 µs | 70 to 115 µs |
| `Probe` round trip (2000 calls) | 78 to 167 µs | 68 to 91 µs |
| Create and release 25 address spaces (`TestAddressSpaceChurn`) | 0.4 to 0.5 s | 0.8 s |
| FS base repairs during 1.5 billion loop iterations | 9 to 12 | not applicable |
| One `fork` in a shell loop | 33 ms | 27 ms |
| One `fork` and `exec` of `/bin/true`, without the pool | 89 ms | 58 ms |
| One `fork` and `exec` of `/bin/true`, with the pool | 50 ms | 31 ms |
| One system call in a `dd` loop | 141 µs | 80 µs |
| `git add` of 200 small files, sparse memory file | 8 to 12 s | 12 to 19 s |
| `git add` of 200 small files, dense memory file | 1.3 s | 0.8 s |

The cost of a system call is the cost of the debug path. A fast path would pay the event round trip of section 3.2 instead. A `fork` and an `exec` each need a stub process. A stub that starts on demand costs 10 to 20 ms, and the pool of section 6.1 hides it.

The memory file of the Sentry is a temporary NTFS file. An earlier version marked it sparse when it tried to release pages. The first write to each hole of a sparse file waits for NTFS to allocate a cluster. Samples of the guest program counter showed the guest blocked at store instructions, and the `git add` row above shows the cost. 

The `unix.Fallocate` shim now never sets the sparse flag. A dense memory file reserves its disk space when it grows. Twenty-four memory files of one gigabyte exhausted the disk of a hosted runner.

## 4. The Nirvana Hook Is a Recovery Net, Not a Security Layer

The SPEC lists `ProcessInstrumentationCallback` (information class 40) as the "Unpatched Syscall Safety Net". The kernel calls the callback when it returns to user mode. By then the kernel has already run the NT service. The callback sees the return address in `R10` and can detect a `0F 05` at `R10 - 2`.

This design has three consequences. First, the hook cannot stop the first NT service from running with Linux arguments. Second, a hostile guest can probably remove the hook with a hidden `syscall` that calls `NtSetInformationProcess`. This part is inference and no probe tested it. Third, installing the hook on the current process needs no privilege (ntdoc, `ProcessInstrumentationCallback`).

The engine does not install the hook. A missed site runs as an NT service and returns garbage. The scan in section 6.3 is the only protection, and it has the limits that section 5 lists.

## 5. Why Variable-Length Instructions Matter

The `x86-64` `syscall` instruction is two bytes. A same-size replacement fits every site. The engine writes `CC 90` (`int3` plus `nop`) over each SYSCALL. Every other byte stays in place, so nothing moves and nothing needs relocation. The debugger resolves the trap. Patching is therefore possible on `amd64`.

The 5-byte `jmp rel32` patterns of the SPEC are harder. They overwrite three bytes after the `syscall`. A patcher must move those instructions into a trampoline, fix any `RIP`-relative operand, and prove that no branch lands inside the window. That work needs exact instruction boundaries. The engine uses no such pattern.

Finding the sites is the main problem. A byte scan has false positives: 34 of 539 pairs were not syscalls. The engine decodes each page with `x86asm` in 16 linear sweeps. The sweeps start at different offsets. It patches a site only when more than half of them agree. The decoder gives no guarantee for four kinds of code:

- Data that sits inside executable sections, such as tables and padding.
- Hand-written assembly with computed jumps.
- Just-in-time compiled code with no symbols.
- Code that a guest writes after the scan.

The engine limits the first kind with the section headers of the backing ELF file. It scans a page again each time the page becomes executable, which covers the last kind.

An indirect jump into the middle of an instruction can run a hidden `0F 05`. A hostile guest plants such a jump on purpose. Linux uses `seccomp` to catch every such call. macOS uses a Seatbelt filter that kills the stub. Windows has no equivalent. The engine makes benign guests correct, but it cannot prove completeness for hostile `amd64` code.

`arm64` is different. Every instruction is four bytes and aligned. A scan of every aligned word in executable pages finds every `svc` that can run. The page trap keeps pages non-executable until the Sentry scans them, so no `svc` can run in a guest page without a scan. This holds for guest pages only. Section 7 explains the gap that remains.

## 6. Design

### 6.1 Processes

| Component | Role |
| :--- | :--- |
| Sentry | Owns the memory file, the guest address space maps, the patcher, and the debug object. |
| Stub host | A fixed request loop in the parent broker. Trusted direct execution uses a helper executable before lockdown. |
| Stub process | A generated PE image inside its own AppContainer. It holds the guest address space and one thread per guest thread. |
| Debug object | One native debug object, created by the Sentry, receives the exceptions of every stub. One goroutine on one OS thread waits for events and routes each to the guest thread. |

`gvx.NewProcess` supplies the stub service through two inherited pipes. The service duplicates handles only into its fixed Sentry worker. A request cannot select an executable, environment, inherited descriptor, or another worker. The service permits at most 256 active stubs.

The host creates each stub suspended inside a unique AppContainer without capabilities or inherited descriptors. It requires the Win32k mitigation and a job with one active process. It removes token privileges after loader initialization. It attaches the process to the debug object and supplies process and thread handles to Sentry. It retains the AppContainer and job until Sentry releases the stub.

A stub reaches the ready state in four steps. The Sentry reserves each guest window as one placeholder while the stub is suspended. It resumes the initial thread, and the loader runs. The loader raises the initial breakpoint of a debuggee. The Sentry suspends the initial thread there, replies, and never resumes it. The stub is then fully initialized and idle.

The platform keeps two ready stubs in a pool. One goroutine fills the pool while guests run. A fork or exec takes a ready stub, or starts another when the pool is empty. `Close` terminates active and pooled stubs before stopping the debugger.

### 6.2 Address Space

The guest window of a stub is `[0x100000000000, 0x7edfffff0000)`. It starts at 16 TiB, above the heaps and stacks that Windows places in the first few TiB, and it ends below the system DLLs. The top 64KB hold the engine pages: 16KB of code and 48KB of data. `MinUserAddress` and `MaxUserAddress` exclude them.

`windowMap` turns each `MapFile`, `Unmap`, and protection request into the five operations that Windows allows on placeholders. It keeps one extent for each placeholder or view. A mapping of any size becomes one view. A partial change unmaps the whole view and maps the surviving parts again. A randomized test checks the map against a reference model with a fake host that enforces the Windows rules. The code runs on macOS too, so the logic has a fast test on the development host.

The low window is `[0x10000, 0x7ffe0000)`. It holds a non-PIE `ET_EXEC` image at the address that it links to. Go links an `arm64` program at `0x10000`, and most other linkers use `0x400000`. `0x10000` is the lowest user address of Windows, and `0x7ffe0000` is the page of `KUSER_SHARED_DATA`. The range between the two windows belongs to the stub. The platform reports it through `platform.AddressHolePlatform`, the kernel forwards it, and the memory manager never maps there.

`windowMap` stays the same. `guestWindows` routes each call to the window that owns the address. An unmap that crosses the hole clears both windows.

`New` decides once whether the platform uses the low window. It brings up one stub with both windows. If that fails, the platform keeps only the high window, and `MinUserAddress` stays at 16 TiB. The decision cannot change later, because the memory manager reads the guest range when a process starts.

The repair of a lost FS base treats a small positive offset from zero as a candidate. With the low window, that offset stops at `0x10000`, the lowest guest address. An access above it is a real guest access, for example to the TLS block of a static executable at `0x400000`.

The memory file is a temporary file. `sectionCache` creates a section of that file for the file handle that `memmap.File.FD` returns, and it creates a new section when the file grows. A host file that the Sentry opened read-only, such as an erofs layer, maps through a read-only section. A file without a host handle, such as a workspace file of `hostfs`, maps through a copy of its bytes in an anonymous section. Such a mapping cannot be writable.

### 6.3 Page Trap and Patching

1. Map a guest page without execute permission. The view shows the original frame.
2. Receive the execute fault through the debug object.
3. Copy the frame, scan the copy, and replace the sites (section 6.5 and 6.6 list them).
4. Map the copy as execute-read from a private section, and call `FlushInstructionCache`.
5. Continue the thread.
6. After a write fault to a writable and executable page, map the original frame again.
7. Patch the page again at the next fetch.

An `amd64` instruction can cross into the next page. The fetch then faults in the next page, and the fault reports `RIP` in the first page, which is already executable. The engine therefore patches every page that the next 15 bytes from `RIP` touch. A fault that repeats three times without a patch becomes SIGSEGV. Without this rule, a guest that ran a shell pipeline hung on one `amd64` runner model.

The original frame can be shared between address spaces and mapped at different addresses. The stub therefore never executes the original frame. A guest that writes to the page that it executes would make the engine swap the two mappings forever. The engine reports SIGSEGV for that write.

### 6.4 Stops and Resumes

A guest thread is parked or running. A parked thread has a suspend count of one, and its registers live in the Sentry. A stop starts when the thread raises an exception. The kernel freezes the process and sends the event to the debug object. The pump routes the event to the thread, and `Switch` reads its context.

| Stop | Action |
| :--- | :--- |
| Trap at a patched site | The thread parks, and the Sentry runs the system call. |
| Execute fault in a code page | The engine patches the page and continues the thread. |
| Write fault in a writable and executable page | The engine maps the original frame again and continues the thread. |
| Single step after a forced stop | The thread parks, and `Switch` returns an interrupt. |
| Any other exception | The thread parks, and the Sentry gets a signal. |

To park a thread, the engine suspends it, replies to the event, and copies the registers into `arch.Context64`. The next `Switch` writes the registers with `SetThreadContext` and resumes the thread.

A new thread starts at `ntdll!DbgBreakPoint` through `NtCreateThreadEx` without loader initialization. It stops there once, and the engine parks it. This avoids the `arm64` problem of a context that the kernel ignores before the first run.

`Interrupt` stops a running thread with the single-step flag. The engine suspends the thread, sets `TF` or `PSTATE.SS`, and resumes it. The thread raises one single-step exception after one instruction, and the stop follows the normal path. A thread inside engine code steps on until it reaches guest code. This design has no race with an exception that the thread raised before the suspend.

A stop copies only the general-purpose registers. `PullFullState` reads the vector state from the parked thread when the Sentry asks for it, and `FullStateChanged` makes the next start write it. On `amd64` the engine allocates the record with `InitializeContext` and `CONTEXT_XSTATE`. The upper halves of the AVX and AVX-512 registers then travel between the Sentry and the thread. A signal handler of the guest can then use them without damage.

### 6.5 `windows/arm64`

The patcher replaces every `svc` immediate, `mrs xN, ctr_el0`, `msr tpidr_el0, xN`, and `ic ivau, xN` with `brk` instructions. Windows reports a `brk` with an unknown immediate as an illegal instruction. The Sentry finds the site in its table and emulates the instruction. It returns a system call, loads the constant `0x8444c004` for `CTR_EL0`, writes the TLS register, or calls `FlushInstructionCache` for the address in `xN`. A `brk` that the guest wrote becomes SIGTRAP, and any other illegal instruction becomes SIGILL.

Windows also raises an illegal instruction for `dc civac` in the cache flush loop of Node 22. The probe of section 3.4 ran `dc cvau` and it executed. The engine therefore replaces `dc cvac`, `dc cvau`, `dc cvap`, `dc cvadp`, and `dc civac` with `nop` in the patched copy. The guest memory is coherent, so the operation has no effect that a guest can see. The replacement costs no stop. The engine did not test which of the five instructions raise the exception.

`CONTEXT` has no field for `TPIDR_EL0`. A routine in the engine page (`msr tpidr_el0, x16; brk`) writes it. The Sentry runs the routine when the TLS value of the guest differs from the value in the thread. That happens at the start of a new thread and after a guest write of the register. The guest reads the register natively. Windows keeps `x18` and `TPIDR_EL0` across stops, and `CONTEXT_X18` makes the engine read and write `x18`.

### 6.6 `windows/amd64`

The patcher replaces each SYSCALL with `CC 90` and each `RDFSBASE` with `INT3` and `NOP` bytes. The trap raises `EXCEPTION_BREAKPOINT` with `RIP` one byte after the site. The Sentry sets `RCX` and `R11` as the hardware does, and it moves `RIP` two bytes ahead.

Windows resets the FS base of a thread at every context switch. Before it starts a thread with a nonzero FS base, the engine points `RIP` at a trampoline in the engine page. Each thread owns one trampoline and one data slot:

```
wrfsbase rax          ; rax holds the guest FS base
mov rax, [rip+d1]     ; load the guest rax from the slot
jmp [rip+d2]          ; jump to the guest rip from the slot
```

A guest access through `%fs` can still fault when Windows resets the base during a long run. The Sentry reads the instruction at the faulting address, and if it has an FS prefix, runs the trampoline again. Eight repairs in a row at one address with identical registers count as a real fault, because a repair that works changes the registers. A loop that waits in the kernel on each pass can need a repair on each pass. A wait on a page of a file view is an example. The engine allows 512 threads in one stub.

### 6.7 Confinement

Each stub has a separate AppContainer, no capabilities, no token privileges, and a job with one active process. The host requires the Win32k mitigation. It rejects initialization failures without reducing these restrictions. `Platform.Confinement` reports the applied restrictions.

## 7. Security Model

Windows ARM64 uses instruction scanning and immutable executable copies. Linux and macOS use kernel syscall filters. These mechanisms enforce different execution boundaries.

| Engine | Syscall restriction | Guest can invoke native services | Boundary |
| :--- | :--- | :--- | :--- |
| Linux `systrap` | Kernel trap and seccomp | No | Kernel filter |
| macOS `systrap` | Seatbelt syscall policy | No | Kernel filter |
| `whpx` and `hvf` | Hardware guest execution | No | Hardware virtualization |
| Windows ARM64 `systrap` | Complete aligned `svc` scan | Blocked while executable-page invariants hold | AppContainer, immutable code, debug object |
| Windows AMD64 `systrap` | Heuristic instruction scan | Yes, through hidden instructions or host DLLs | Trusted execution only |

Before guest entry, ARM64 replaces every aligned `svc` in executable host mappings with a trap. This includes `ntdll`. It freezes all stub threads during this scan. It removes write permission from executable host pages. It scans every guest executable copy before mapping it without write permission. It converts every `svc` immediate into Linux dispatch.

Writable aliases reference the original, non-executable backing pages. Execute mapping failures use a read-only fallback before granting execute permission. A failed protection change removes that fallback mapping.

The debugger terminates a sealed stub if another native image loads. It also terminates unregistered threads that raise exceptions. A new guest thread uses the existing bootstrap without loader initialization. Initialization fails if the engine cannot seal a host mapping.

`gvx.NewProcess` confines Sentry separately and restricts stub creation to its fixed worker. `rungv` uses this boundary by default. Windows AMD64 rejects confined systrap requests. Explicit `DisableHostLockdown` retains trusted execution for that architecture.

Windows supplies no kernel syscall filter to this engine. ARM64 confinement depends on the scanner, page permissions, debugger, and AppContainer boundaries. It does not provide the hardware execution boundary of WHPX. AppContainer still permits system resources and private profile storage.

The tests verify native syscall rejection, immutable host code, token restrictions, JIT writes, concurrent threads, process cancellation, and brokered network access. They do not establish a formal proof of confinement.

## 8. Implementation Map

| File | Content |
| :--- | :--- |
| `nt_windows.go` | Bindings of the NT and Win32 calls. |
| `stubhost_windows.go`, `stub_broker_windows.go` | The fixed stub service and its Sentry client. |
| `stub_image_windows.go` | A minimal PE image without imports or caller code. |
| `syscall_guard_windows_arm64.go` | Native syscall sealing before guest entry. |
| `debug_windows.go` | The debug object and the event pump. |
| `stubproc_windows.go` | Stub bring-up and guest thread creation. |
| `thread_windows.go` | Guest thread state, park and resume, and the forced stop. |
| `address_space_windows.go`, `section_windows.go` | The address space, lazy patching, sections, and the private page pool. |
| `viewmap_xplat.go` | The window map. |
| `context_windows.go` | `Context.Switch`, event classification, and signals. |
| `platform_windows.go`, `probe_windows.go` | `New`, `Close`, and `Probe`. |
| `arch_windows_arm64.go`, `arch_windows_amd64.go` | Patching, TLS or FS base, and site emulation for each architecture. |
| `hostctx_xplat_*.go`, `hostctx_windows_amd64.go` | `CONTEXT` record layout and conversion, including the XSTATE area. |
| `patcher_amd64_xplat.go` | The `x86asm` scanner and the in-page patch. |
| `code_image_xplat.go` | ELF section headers that limit the scan to code. |

The tests are `engine_windows_test.go`, `engine_windows_amd64_test.go`, `lockdown_windows_test.go`, `viewmap_xplat_test.go`, and `patcher_amd64_xplat_test.go`. They run guests that the tests assemble by hand, through the same `Context.Switch` that the Sentry calls.

## 9. Limits and Open Work

| Item | State |
| :--- | :--- |
| Fast path | Not implemented. A patched `svc` or `syscall` could branch to a trampoline that signals the Sentry with an event pair, and skip the debugger. The measured event round trip is 12 to 27 µs, against 70 to 190 µs for a stop. |
| Guest addresses outside the two windows | No guest mapping can use an address below `0x10000` or between `0x7ffe0000` and 16 TiB. The memory manager treats the second range as a hole. |
| Writing to the executing page | A guest that writes to the page that it executes gets SIGSEGV. |
| GS base | A guest cannot set it. `UserModifiedGS` reports an error on `amd64`. |
| Workspace files | A file without a host handle maps through a copy. A writable shared mapping of such a file fails with `ENODEV`. |
| AMD64 system calls | A hidden `syscall` can invoke NT services. Confined execution rejects this backend. |
| CPU quota | Windows systrap reports the guest CPU count limit. `Limits().CPUTime` remains false because stub execution uses separate jobs. |
| JIT engines | Node 22 (V8) passes its two gates on both runners. A JVM is untested. |
| Endpoint protection | The stub host, the debug object, and the executable views are untested with Microsoft Defender at its default settings. |
| Single-step interrupt | A guest that uses the trap flag itself can lose one of its own steps. |

## 10. Evidence

| Run | Runners | Content |
| :--- | :--- | :--- |
| `39790745508` | both | Exports, stub bytes, direct syscalls, mitigation policy, spawn time. |
| `39791228959` | both | Placeholders, executable views, remote 4KB cost, FS base loss, event round trip. |
| `39791535847` | both | `arm64` `x18`, `TPIDR_EL0`, `ctr_el0`, `ic ivau`, WHP presence. |
| `39796084304` | both | Debugger event latency and register writes. |
| `39800771242`, `39802593217`, `39803097982` | both | `x18` across waits, policy flags, `ntdll` patching, loader-less threads. |
| `39803487649` | both | FS base recovery with the debugger. |
| `39809735687`, `39811366093` | both | Stub design: initialized stub, start trap, park and resume, `x18` and `TPIDR_EL0` across stops, Low-integrity token, job, Win32k, second stub on one debug object. |
| `39864134146`, `39864138530` | both | Cost of `fork`, `exec`, and system calls from the host side. |
| `39866441714`, `39866444969`, `39869493336`, `39869496938` | both | `git add` with the sparse and with the dense memory file. |
| `39872809703`, `39872813269` | both | Cost of `fork` and `exec` with the stub pool. |
| `39870353585` | both | The registry gates on the systrap engine: Alpine, nginx with port forwarding, Python, Node, the POSIX torture script, `git` workloads, and the Node modules torture. All pass in 207 s (`amd64`) and 281 s (`arm64`). |
| `39845577561`, `39846215053` | `arm64` | Node 22 gates: SIGILL at `dc civac`, then both gates pass with the `nop` replacement. |
| `39853085199`, `39854000516` | `amd64` | Shell pipeline hang on an AMD EPYC 9V74 runner: 12 of 12 runs. The state dump shows a `call` at the end of a page. |
| `39855645886` | `amd64` | The same loop on an EPYC 9V74 runner with the page-crossing fix: 12 of 12 runs pass. Seventeen runs on two other models (EPYC 7763 and 9V45) also pass. |
| `39898594534`, `39898597202` | `amd64`, `arm64` | The low window: 60 suspended processes on each runner. The range was free, one placeholder covered it, the loader stayed out of it, and 64KB views mapped in it. |
| `39899579241` | `arm64` | The `arm64` build of herdr links at `0x400000`. Before the low window it failed with `out of memory`. |
| `39903063365`, `39903065819` | `amd64`, `arm64` | The low window end to end. Executables at `0x10000` and `0x400000` run. The `amd64` build of herdr (static-PIE) and the `arm64` build (`ET_EXEC` at `0x400000`) print their version and their API schema. |
| `39903271799` | both | The registry gates fail in both Node gates. The kernel did not forward the address hole, and the address hints of V8 placed memory in it. |
| `39904398745`, `39905154834` | both, all platforms | The registry gates pass with the low window and the kernel forwarder. |

The scan of section 3.7 ran on a development host. Its output is in [`windows-systrap-probes/x86scan/RESULTS.txt`](windows-systrap-probes/x86scan/RESULTS.txt).

## 11. Reproduction Procedure

> [!CAUTION]
> Run the probes only from a throwaway branch. They execute raw machine code and raw NT system calls. Delete the branch after the run.

1. Create an orphan branch with the probe directory and a workflow.
2. Set the workflow trigger to `push` on that branch.
3. Use the runner labels `windows-latest` and `windows-11-arm`.
4. Run `go build` in the probe directory with Go 1.24 or newer.
5. Run the resulting executable and read lines that start with `PROBE`, `DBG`, `R2`, or `SP`.
6. Delete the branch and keep the logs.

To debug a guest stop in the engine, set `GVX_SYSTRAP_TRACE=1`. The engine then prints each signal that an illegal instruction, a breakpoint, or an arithmetic exception sends to the guest. A line has the exception code, the address, and the bytes at the program counter.

The value `2` also prints every stop and prints the state of each stub every three seconds. The value `3` prints only that state and the count of each kind of stop, which does not change the timing of the guest. The value `4` also samples the program counter every five milliseconds and prints the hottest addresses. The output has an upper bound of 400 lines, or 200000 lines for the value `2`.

## 12. Sources

| Source | Supports |
| :--- | :--- |
| [Pico Process Overview](https://learn.microsoft.com/en-us/archive/blogs/wsl/pico-process-overview) | No third-party API for pico processes. |
| [MapViewOfFile3](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile3) | The 64KB limit does not apply with `MEM_REPLACE_PLACEHOLDER`. |
| [WaitOnAddress](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitonaddress) | The waker is a thread of the same process. |
| [Windows ARM64 ABI](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions?view=msvc-170) | `x18` is the TEB. `TPIDR_EL0` is reserved. |
| [ProcessInfoClass notes (ntdoc)](https://raw.githubusercontent.com/m417z/ntdoc/main/descriptions/processinfoclass.md) | The instrumentation callback needs no privilege for the current process. |
| [Parallels KB 116239](https://kb.parallels.com/en/116239) | Nested virtualization is unsupported on Apple silicon. |
| [ASC-Hook](https://arxiv.org/abs/2412.05784) | Prior work on `svc` rewriting on `arm64`. |
| [gVisor `systrap` README](https://github.com/google/gvisor/blob/master/pkg/sentry/platform/systrap/README.md) | Linux uses `seccomp` traps for syscalls. |
