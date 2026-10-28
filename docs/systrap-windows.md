# Windows `systrap` Engine: Measured Behavior and Design

This document describes the `systrap` engine for Windows. The engine runs a Linux guest natively inside a stub process, without a hypervisor. The document records what the project measured on Windows hosts, the design that those measurements allow, and the limits of the result. Read [`architecture.md`](architecture.md) section 3.3 first for the shared `systrap` concepts.

| Topic | Result |
| :--- | :--- |
| Status | Implemented for `windows/arm64` and `windows/amd64`. The engine runs the Sentry and its guests on both hosted runners. |
| Stops | Every system call, page fault, and signal reaches the Sentry through a debug object. One stop costs about 70 to 115 µs on `arm64` and about 80 to 190 µs on `amd64`, depending on the host. |
| Fast path | On by default. `GVX_SYSTRAP_FASTPATH=0` turns it off, and `GVX_SYSTRAP_FASTPATH=1` makes a host that cannot run it an error. A patched system call skips the debugger. Section 6.8 describes it. |
| Security | The engine is not a syscall sandbox. Windows has no filter for NT system calls, so a hostile guest can reach the NT services of the stub token. |
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

The exports `VirtualAlloc2`, `MapViewOfFile3`, and `WaitOnAddress` live in `kernelbase.dll`. They are not exports of `kernel32.dll` on either runner. `pkg/memutil/memutil_windows.go` loads `MapViewOfFile3` from `kernelbase.dll` and keeps `MapViewOfFile` as a fallback. The engine binds its own calls in `nt_windows.go`.

### 3.2 Signaling and Process Cost

| Finding | `amd64` | `arm64` |
| :--- | :--- | :--- |
| `WaitOnAddress` woken by `WakeByAddressSingle` from another process over shared memory | no wake in 4000 ms | no wake in 4000 ms |
| Round trip of two auto-reset events between two processes | 19.5 to 27.4 µs | 12.0 to 12.6 µs |
| `CreateProcess(CREATE_SUSPENDED)`, terminate, wait | 1.2 to 2.6 ms | 2.7 to 3.0 ms |

`WaitOnAddress` keeps its wait list in the memory of one process, so it cannot signal across processes. The event round trip is the cost that the fast path of section 6.8 pays when spinning does not wake the peer.

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

A new thread starts in `ntdll!RtlUserThreadStart`. That path needs executable `ntdll` code and its syscall instructions. Removing the `ntdll` syscall gadgets therefore breaks thread creation, and the stub keeps `ntdll` executable. The engine does not generate a PE image. It starts a second copy of the Sentry executable as the stub image and parks it before the entry point runs.

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

The 5-byte `jmp rel32` patterns of the SPEC are harder. They overwrite three bytes after the `syscall`. A patcher must move those instructions into a trampoline, fix any `RIP`-relative operand, and prove that no branch lands inside the window. That work needs exact instruction boundaries. The default engine uses no such pattern. The optional fast path of section 6.8 uses it, and it keeps `CC 90` where it cannot prove the window.

Finding the sites is the main problem. A byte scan has false positives: 34 of 539 pairs were not syscalls. The engine decodes each page with `x86asm` in 16 linear sweeps. The sweeps start at different offsets. It patches a site only when more than half of them agree. The decoder gives no guarantee for four kinds of code:

- Data that sits inside executable sections, such as tables and padding.
- Hand-written assembly with computed jumps.
- Just-in-time compiled code with no symbols.
- Code that a guest writes after the scan.

The engine limits the first kind with the section headers of the backing ELF file. It scans a page again each time the page becomes executable, which covers the last kind.

The `x86asm` decoder has one more defect. It reads a ModRM byte for `vzeroupper` and `vzeroall`, which have none. The length that it returns is then 1 to 5 bytes too long. The engine decodes these two instructions itself, in `decodeX86`. Before this correction, the scan of Node 22 found a GS memory instruction inside a `lea`. The patch then made the `lea` an illegal instruction, and the guest received SIGILL.

An indirect jump into the middle of an instruction can run a hidden `0F 05`. A hostile guest plants such a jump on purpose. Linux uses `seccomp` to catch every such call. macOS uses a Seatbelt filter that kills the stub. Windows has no equivalent. The engine makes benign guests correct, but it cannot prove completeness for hostile `amd64` code.

`arm64` is different. Every instruction is four bytes and aligned. A scan of every aligned word in executable pages finds every `svc` that can run. The page trap keeps pages non-executable until the Sentry scans them, so no `svc` can run in a guest page without a scan. This holds for guest pages only. Section 7 explains the gap that remains.

## 6. Design

### 6.1 Processes

| Component | Role |
| :--- | :--- |
| Sentry | Owns the memory file, the guest address space maps, the patcher, and the debug object. |
| Stub host | A copy of the Sentry executable that runs only a request loop. It starts before `hostlockdown.Apply`, because the lockdown job allows one process. |
| Stub process | Another copy of the executable, created suspended, with the entry point never reached. It holds the guest address space and one thread for each guest thread. |
| Debug object | One native debug object, created by the Sentry, receives the exceptions of every stub. One goroutine on one OS thread waits for events and routes each to the guest thread. |

The `init` function of the package runs the host loop when the environment variable `GVX_SYSTRAP_STUBHOST` is set. The Sentry starts the host with that variable and talks to it over the standard pipes. A request names no path and no command line, so a compromised Sentry cannot start a program of its choice.

The host creates each stub with `CreateProcessAsUser`. It uses a copy of its own token without privileges at Low integrity, and it adds the Win32k and handle mitigations when Windows accepts them. It puts the stub in a job that allows one process, kills on close, and blocks all window operations. It attaches the stub to the debug object of the Sentry, because the lockdown can remove the right to debug a process from the Sentry. It duplicates the process and thread handles into the Sentry, and it keeps the job handle until the Sentry releases the stub.

A stub reaches the ready state in four steps. The Sentry reserves each guest window as one placeholder while the stub is suspended. It resumes the initial thread, and the loader runs. The loader raises the initial breakpoint of a debuggee. The Sentry suspends the initial thread there, replies, and never resumes it. The stub is then fully initialized and idle.

The platform keeps two ready stubs in a pool. One goroutine fills the pool while the guests run, and a fork or an exec takes a stub from it. A bring-up takes 20 ms on `arm64` and 10 ms on `amd64`, and the loader needs most of that time. The pool hides that time when the guest does other work between two forks. When the pool is empty, the call starts a stub itself. `Close` terminates the stubs that no guest took.

### 6.2 Address Space

The guest window of a stub is `[0x100000000000, 0x7ee000000000)`. It starts at 16 TiB, above the heaps and stacks that Windows places in the first few TiB, and it ends below the system DLLs. The top 0x2010000 bytes belong to the engine. The first 64KB hold the engine pages: 32KB of code and 32KB of data. The rest holds one 64KB area for each of the 512 possible threads, which only the fast path of section 6.8 maps. `MinUserAddress` and `MaxUserAddress` exclude all of it. `MaxUserAddress` is `0x7edffdff0000`.

`windowMap` turns each `MapFile`, `Unmap`, and protection request into the five operations that Windows allows on placeholders. It keeps one extent for each placeholder or view. A mapping of any size becomes one view. A partial change unmaps the whole view and maps the surviving parts again. A randomized test checks the map against a reference model with a fake host that enforces the Windows rules. The code runs on macOS too, so the logic has a fast test on the development host.

The low window is `[0x10000, 0x7ffe0000)`. It holds a non-PIE `ET_EXEC` image at the address that it links to. Go links an `arm64` program at `0x10000`, and most other linkers use `0x400000`. `0x10000` is the lowest user address of Windows, and `0x7ffe0000` is the page of `KUSER_SHARED_DATA`. The range between the two windows belongs to the stub. The platform reports it through `platform.AddressHolePlatform`, the kernel forwards it, and the memory manager never maps there.

`windowMap` stays the same. `guestWindows` routes each call to the window that owns the address. An unmap that crosses the hole clears both windows.

`New` decides once whether the platform uses the low window. It brings up one stub with both windows. If that fails, the platform keeps only the high window, and `MinUserAddress` stays at 16 TiB. The decision cannot change later, because the memory manager reads the guest range when a process starts.

The repair of a lost FS base treats a small positive offset from zero as a candidate. With the low window, that offset stops at `0x10000`, the lowest guest address. An access above it is a real guest access, for example to the TLS block of a static executable at `0x400000`.

The memory file is a temporary file. `sectionCache` creates a section of that file for the file handle that `memmap.File.FD` returns, and it creates a new section when the file grows. A host file that the Sentry opened read-only, such as an erofs layer, maps through a read-only section. `pkg/gvx` passes the kernel memory file to `hostfs` and `ext4lite` via `SetChunkMemory`, so their mapped chunks share a host handle and support writable mappings. A file without a host handle maps read-only through an anonymous section.

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

The memory manager maps a whole mapping at each page fault, so it maps pages again that the guest already runs. A repeated mapping with execute access keeps a block when its frame, its file offset, and its access do not change. The block then keeps its patched copy, its table of sites, and its island slots. A reset leaves a thread that already trapped at a patched site without its site. The guest then receives a SIGTRAP that it did not raise. A file without a host handle maps through a copy of its bytes, and such a mapping always gives new blocks.

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

A stop reads the context with the flags for the control and the integer registers only. The `arm64` flags also name `x18`. A stop that the engine resolves without a change to the registers skips `SetThreadContext`. The thread then costs one context read and one `NtDebugContinue`. This holds for the repair of an execute fault, the repair of a write fault, and the single steps through engine code. The engine never suspends the other threads of the process during a stop. A patch maps a copy with execute permission over a page without it. A restore removes the permission. A thread that fetches during the swap faults and retries. The saving per lazy fault is one NT call, and it is not measured.

### 6.5 `windows/arm64`

The patcher replaces `svc #0`, `mrs xN, ctr_el0`, `msr tpidr_el0, xN`, and `ic ivau, xN` with `brk` instructions. Windows reports a `brk` with an unknown immediate as an illegal instruction. The Sentry finds the site in its table and emulates the instruction. It returns a system call, loads the constant `0x8444c004` for `CTR_EL0`, writes the TLS register, or calls `FlushInstructionCache` for the address in `xN`. A `brk` that the guest wrote becomes SIGTRAP, and any other illegal instruction becomes SIGILL.

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

The stub runs with a token that has no privileges and Low integrity, in a job that allows one process. The host applies the Win32k, strict handle, and extension point mitigations when Windows accepts them, and it falls back to fewer mitigations otherwise. `Platform.Confinement` reports the result. The stub holds no handle. Most NT services therefore fail with `STATUS_INVALID_HANDLE`. With the fast path, the stub holds two event handles for each thread. Each handle carries only the rights to set and to wait.

### 6.8 Fast Path

The fast path is on by default. `New` falls back to the debug path when the host cannot run it. Set `GVX_SYSTRAP_FASTPATH=1` to turn a failed fast path into an error, and `GVX_SYSTRAP_FASTPATH=0` to turn the fast path off. It serves a patched system call without the debugger: no `NtSuspendThread`, no `NtResumeThread`, no `NtDebugContinue`, and no context call. The latency is a design target.

| Part | Content |
| :--- | :--- |
| Arena | The top of the guest window holds the engine pages (64KB) and then one 64KB area for each thread. `internalBase` is `winLimit - 0x2010000`, and `MaxUserAddress` stays below it. |
| Thread area | A 4KB `winSysmsg` page and a 4KB stack for the spill routine. The Sentry and the stub map both pages from one section. |
| Engine pages | The code pages hold the `amd64` FS base trampolines or the `arm64` TLS routine, and the spill routine at offset `0x4000`. A Go generator writes the machine code, because the engine has no C toolchain step. |
| Islands | One page of slots in the guest address space, within 120 MiB of the patched code. The engine reserves each island as a sealed mapping through `mm.MMap`, as the macOS engine does. |
| Events | Two auto-reset events for each thread. The stub host creates them with `NtCreateEvent` on request and duplicates them into the stub and into the Sentry. The host runs outside the lockdown job, so it can create events after the lockdown, as it creates stubs. |

A patched instruction jumps to a slot. The slot jumps to the spill routine. The routine saves the registers in the `winSysmsg`, stores the state `Trapped`, and waits for the Sentry. The Sentry reads the registers, serves the call, writes the registers back, and stores a resume state.

| State | Meaning |
| :--- | :--- |
| `Idle` | The thread runs guest code. |
| `Trapped` | The stub saved the registers and waits. |
| `RunHot` | The program counter is unchanged, and on `arm64` so is the stack pointer. The stub loads the registers and returns through the slot tail. |
| `RunCold` | The Sentry changed the program counter, the stack pointer, or the TLS value. The stub loads every register and executes a trap. The Sentry continues the thread at `Target` through the debug path, and loads the FS base or the TLS value. |

The stub stores `Trapped` with release semantics and sets the guest event only when `SentryWaiter` is set. It then polls the state word 1024 times. After that it sets `StubWaiter`, tests the state again, and sleeps on the host event. The Sentry polls 512 times, sets `SentryWaiter`, tests again, and sleeps on the guest event. Each flag has one writer. A fence separates the store of the state from the load of the other flag. A stale event signal does no harm, because both sides test the state after each wake.

On `arm64`, the patcher replaces `svc #0` with `B slot`. The slot saves `x16` and `x17` in the `Scratch` words of `winSysmsg` without touching the guest stack. It jumps to the spill routine with `x17` set to the slot tail. The routine writes the updated `x16` and `x17` values back to `Scratch` before it returns through the slot tail.

On `amd64`, the patcher replaces `syscall` and the three bytes after it with `jmp rel32`. The slot holds a copy of the instructions that those bytes belong to. The slot uses no guest stack, so it keeps the red zone. The patcher keeps `CC 90` in each of these cases:

- The instructions behind the `syscall`, at most three, cover fewer than three bytes or leave the page.
- One of them is a branch, a call, a return, a system call, an interrupt, or has a RIP-relative operand.
- A relative branch that decodes in the page or in the 15 bytes on each side lands in the overwritten bytes.
- A prefix byte stands in front of the `syscall`.
- The engine cannot allocate a slot.

A branch from a distant page and an indirect jump can still land in the overwritten bytes. The patcher cannot see them. The scan of section 5 accepts the same kind of risk for the bytes of the `syscall` itself. The common `syscall; ret` of musl keeps `CC 90`, because the byte after `ret` can start another function.

A thread can also start at the return address of a patched `syscall`. The new thread of `clone` does this. A `sigreturn` that restores the frame of an interrupted call does it too. The `jmp` overwrote the bytes at that address. The engine therefore starts such a thread at the tail of the slot. The tail runs the relocated instructions and jumps to the code behind them. The Sentry never writes the address of the tail into the registers of the guest. Without this rule, the child of `clone` in a Go guest ran the bytes of the `jmp` and crashed with SIGSEGV on `windows/amd64`.

On `amd64`, the spill routine finds the page of its thread through the TEB. The Sentry writes the address of the page into `NT_TIB.ArbitraryUserPointer` at offset `0x28` of each guest thread. `gs:[0x28]` names the word, and the slot also uses `SubSystemTib` and `FiberData` (offsets `0x18` and `0x20`) as scratch words.

On `arm64`, no register can name the TEB. The guest owns `x18`, and Windows keeps the CPU number in `TPIDRRO_EL0`. The engine therefore writes the address of the page into the real `TPIDR_EL0` of each fast thread. The guest thread pointer moves to the `TLS` word of the page. The patcher replaces each `mrs xN, tpidr_el0` with a branch to a 16-byte slot that loads the `TLS` word, or with a `brk` that the Sentry emulates. A `msr tpidr_el0, xN` trap stores the `TLS` word and runs no TLS routine. A page of guest code that the patcher did not scan would read the wrong value, but the page trap scans every page before it runs.

These stops keep the debug path: every fault, every execute fault that patches a page, every single step, every `CC 90` and `brk` site that stays trapped, `RDFSBASE`, and every signal. A thread can use both paths in turn. A thread that waits in the spill routine is not suspended, so the other threads of the stub run on.

`Interrupt` does not step a thread that runs the spill routine, a slot, or an ntdll stub that the routine calls, because the trap publishes its own stop. The call tries again until the thread leaves that code or publishes the trap. A thread that steps into the first instruction of a slot goes back to the patched instruction, because the slot has not run.

The spill routine saves the vector state of the guest in the `winSysmsg` before it makes any call, and loads it on every resume. The Sentry reads and writes the vector state of a trapped thread in that block. The live thread context does not hold the guest state, because the calls of the routine clobber the volatile vector registers. The first CI runs failed `TestFastPathVectorStateFollowsTheSentry` on `windows-11-arm` and on `windows-latest`: `PullFullState` read zero, and a value from the Sentry reached the guest as zero.

On `arm64`, the block holds V0 to V31, FPSR, and FPCR. The ABI lets a call clobber V0 to V7 and V16 to V31, and the guest expects a system call to keep them.

On `amd64`, the block is an XSAVE image at offset `0x100` of the `winSysmsg`. The routine writes it with `XSAVE64` and loads it with `XRSTOR64`. The feature mask is `0xE7`: x87, SSE, AVX, and the three AVX-512 components. The processor ignores the mask bits that XCR0 does not enable. The Sentry copies the image to and from the Linux XSAVE image of the guest. It sets only the XSTATE_BV bits of components that the operating system enabled, because `XRSTOR64` faults on any other bit.

By default, `New` runs a guest with six system calls in a new stub. All six must take the fast path. A failed run, or a run that exceeds 30 seconds, makes `New` fall back to the debug path. With `GVX_SYSTRAP_FASTPATH=1`, such a run makes `New` return `ErrUnavailable`. With `GVX_SYSTRAP_FASTPATH=0`, `New` skips the fast path.

The design rests on facts that no Windows document states:

- No code of the stub uses the three `NT_TIB` words.
- `ntdll` loads at the same address in the Sentry and in the stub.
- `TPIDR_EL0` keeps the value that the engine writes, across waits and stops, on `arm64`. Section 3.4 measured this for waits and stops, but not for the spill routine itself.
- On `amd64`, the stub process runs `XSAVE64` and `XRSTOR64`. Only a Windows run proves that the host accepts them. The macOS tests run the routine in an emulator.

| Piece | Verified by |
| :--- | :--- |
| Offsets and size of the `winSysmsg` | Unit tests and compile-time checks, also on macOS. |
| Handoff state machine | Unit tests with channel events and the race detector, also on macOS. |
| Generated machine code | Decoding with `x86asm` and `arm64asm`, and an emulator that runs the spin hit, the sleep, the races, and the cold resume, also on macOS. |
| `amd64` patch plan | Unit tests of the relocation and branch rules, also on macOS. |
| End to end | `fastpath_windows_test.go`, and the engine tests, which run with the fast path by default. `TestFastPathResumeBehindPatchedSyscall` covers a start behind a patched `syscall`. The e2e tests `TestE2EVolumePersistsAcrossSandboxes` and `TestE2EGateETExecGoStatic` run real Go guests. Both hosted Windows runners pass them. |
| Latency | Not measured. |

The engine reclaims island slots through a per-island bitmap when a code page unmaps or returns to data state. A thread count above 512 for one stub fails with an error.

## 7. Security Model

| Engine | Syscall filter | Guest can reach host NT services | Basis |
| :--- | :--- | :--- | :--- |
| Linux `systrap` | `seccomp` allowlist in the Sentry, trap for guests | no | kernel filter |
| macOS `systrap` | Seatbelt profile kills the stub | no | kernel filter |
| Windows `whpx` and `hvf` | none needed | no | hardware virtualization |
| Windows `arm64` `systrap` | none | yes, through `ntdll` stubs | token, job, mitigation policy, page scan |
| Windows `amd64` `systrap` | none | yes, through `ntdll` stubs and hidden `0F 05` | token, job, mitigation policy |

The Windows `arm64` engine blocks every `svc` in guest pages before it runs. A hostile guest can still jump to an `svc` inside `ntdll` and choose the registers. That call runs with the token of the stub.

The stub job blocks new processes. The stub holds no handle, so most NT services fail. This resembles the exposure of a sandboxed browser renderer. That comparison is inference. A guest could also attack the debug object through a hidden NT call, but it holds no handle to it.

State this limit in every user-facing document for the engine. Do not describe the engine as a syscall sandbox on Windows. A Windows host that needs that guarantee must use `whpx`.

## 8. Implementation Map

| File | Content |
| :--- | :--- |
| `nt_windows.go` | Bindings of the NT and Win32 calls. |
| `stubhost_windows.go` | The stub host loop, its token, job, and mitigation setup, and the Sentry-side client. |
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
| `winsysmsg_xplat.go`, `winsysmsg_*_xplat.go` | Layout of the arena and of the `winSysmsg` page, the handoff state machine, and the register blocks. |
| `stubcode_*_xplat.go` | Generators of the spill routine and the trampoline slots, and the `amd64` patch plan. |
| `fastpath_windows.go`, `fastisland_windows.go`, `fastselftest_windows.go` | Slots, events, the Sentry side of the handoff, the islands, and the self test of the fast path. |

The tests are `engine_windows_test.go`, `engine_windows_amd64_test.go`, `fastpath_windows_test.go`, `lockdown_windows_test.go`, `viewmap_xplat_test.go`, `patcher_amd64_xplat_test.go`, `hostctx_xplat_test.go`, `winsysmsg_xplat_test.go`, and `stubcode_*_xplat_test.go`. They run guests that the tests assemble by hand, through the same `Context.Switch` that the Sentry calls. The `xplat` tests also run on macOS.

## 9. Limits and Open Work

| Item | State |
| :--- | :--- |
| Fast path | Implemented and on by default (section 6.8). The fast path tests pass on `windows-latest` and `windows-11-arm`. The design target is an event round trip of 12 to 27 µs, against 70 to 190 µs for a stop. |
| Guest addresses outside the two windows | No guest mapping can use an address below `0x10000` or between `0x7ffe0000` and 16 TiB. The memory manager treats the second range as a hole. |
| Writing to the executing page | A guest that writes to the page that it executes gets SIGSEGV. |
| GS base | A guest cannot set it. `UserModifiedGS` reports an error on `amd64`. |
| Workspace files | `pkg/gvx` passes the kernel memory file to `hostfs` and `ext4lite` via `SetChunkMemory`, so writable shared mappings work. A custom `memmap.File` without a host handle maps read-only through a copy and rejects writable shared mappings with `ENODEV`. |
| Unpatched system calls | A hidden `syscall` that the scan misses runs as an NT service. |
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
