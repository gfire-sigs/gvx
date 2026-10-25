# ERRATA-003: Cross-Package Code Deduplication, Shared Subsystem Consolidation, and Divergence Fixes

This errata specification documents 11 architectural duplication clusters across Tier 1 and Tier 2 packages in `gvx`. Across hardware hypervisor backends, user-mode `systrap` engines, filesystem drivers, networking, OCI image tooling, and CLI entrypoints, the codebase contains over 5,000 lines of duplicated logic and five behavioral divergence bugs. Implementation agents must execute the remediation procedures in this document in priority order while keeping the Tier 3 upstream diff ratio below `1.0%`.

| Field | Value |
| :--- | :--- |
| **Document ID** | `ERRATA-003` |
| **Title** | Cross-Package Code Deduplication, Shared Subsystem Consolidation, and Divergence Fixes |
| **Status** | Active Errata and Remediation Work Order |
| **Upstream Baseline** | `0d2072ab24130458e928ea0a78b363a60705e433` (`upstream/go`) |
| **Isolation Tiers** | Tier 1 (`platform/whpx`, `platform/hvf`, `platform/hvcommon`, `platform/slimvm`, `fsimpl/hostfs`, `fsimpl/ext4lite`, `pkg/gvx`, `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `cmd/rungv`, `internal/gvxshim`), Tier 2 (`platform/systrap`) |
| **Companion Specs** | [`errata-001-upstream-reuse-and-efficiency.md`](errata-001-upstream-reuse-and-efficiency.md), [`errata-002-post-refactor-review-findings.md`](errata-002-post-refactor-review-findings.md), [`../architecture.md`](../architecture.md) |

---

## 1. Errata Matrix and Priority Classification (Reference Module)

The table below ranks all 11 deduplication and consolidation work items by correctness risk, maintenance cost, and removable line count.

| Errata ID | Priority | Target Packages | Duplicate Lines | Defect Summary | Remediation Gate |
| :--- | :---: | :--- | ---: | :--- | :--- |
| **ERRATA-003-E1** | **P0** | `platform/hvf`, `platform/whpx`, `platform/hvcommon`, `pkg/hostarch` | `~750` | `hvf` and `whpx` duplicate `CommPage` headers, ARM64 EL1 vector generators, and `ESR_EL1` fault decoders with four signal-delivery divergences (including missing `FAR_EL1` TBI untagging in `whpx`). | `hvcommon` owns one `CommHeader`, one ARM64 EL1 stub generator, and one `ESR_EL1` decoder shared by `hvf` and `whpx`. |
| **ERRATA-003-E2** | **P1** | `platform/hvf`, `platform/whpx`, `platform/hvcommon` | `~465` | `hvf` and `whpx` duplicate `pagetables.Allocator` (`tableAlloc` vs. `ptAllocator`), multi-page slab pools, Stage-1 `AddressSpace` lifecycle methods, and vCPU fault handlers. | `hvcommon` owns the shared Stage-1 `PTAllocator`, `SlabPool`, and `Stage1` address-space wrapper; `whpx` deduplicates `vcpu_arm64.go` and `vcpu_amd64.go`. |
| **ERRATA-003-E3** | **P1** | `fsimpl/hostfs`, `fsimpl/ext4lite`, `pkg/gvx` | `~520` | `hostfs/regular_file.go` and `ext4lite/mmap.go` duplicate the entire 64KB chunk page cache (`fileData`, `cacheChunk`, `dataMemmapFile`, `ChunkMemory`) and `safemem.Reader` block loops. | Both filesystems share one chunk-cache package (`pkg/sentry/fsimpl/chunkcache`) and one `ChunkMemory` registration hook. |
| **ERRATA-003-E4** | **P1** | `platform/systrap`, `platform/hvcommon` | `~450` | Seven files re-declare ARM64 instruction encoders (`MOVZ`, `MOVK`, `B`, `BR`, `BLR`, `LDR`, `STR`, `LDP`, `STP`, `MRS`, `MSR`, `BRK`, `DC`); `systrap` duplicates `MRS` ID emulation and trap-slot encoding. | `hvcommon/a64.go` exports parameterized AArch64 encoders; `systrap` reuses `hvcommon` for instruction encoding and `MRS` emulation. |
| **ERRATA-003-E5** | **P1** | `platform/systrap` (`darwin`, `windows`, `xplat`) | `~750` | `darwinsystrap` and `winsystrap` duplicate trampoline island bitmaps (`island`, `allocSlot`, `newIsland`), `addressSpace` helpers, `Platform`/`Context` boilerplate, FP/XSTATE copy loops, spin handoff, and `Probe` loops. | Shared `island_xplat.go`, `address_space_xplat.go`, `context_xplat.go`, and `probe_xplat.go` eliminate Darwin/Windows duplication. |
| **ERRATA-003-E6** | **P1** | `platform/slimvm`, `platform/kvm`, `platform/hvcommon` | `~2,050` | `slimvm` copies `platform/kvm` across 23 files with four changed ioctl numbers and introduces an `FPE_INTOVF` (`Code: 1` vs. `2`) bug in `slimvm/machine_amd64.go:337`. | `slimvm` fixes the `FPE_INTOVF` code, shares x86 exception vector classification via `hvcommon/x86.go`, or consolidates with `kvm` behind an ioctl dialect interface. |
| **ERRATA-003-E7** | **P2** | `fsimpl/hostfs`, `fsimpl/ext4lite`, `fsimpl/erofs` | `~550` | `hostfs` and `ext4lite` duplicate VFS xattr validation, host preallocation (`fallocate`/`F_PREALLOCATE`/`FileAllocationInfo`), Windows `NtQueryVolumeInformationFile`, disk-full error mapping, `PrependPath`/`IsDescendant`, and `openSpecial`. | Shared VFS helpers and `genericfstree` calls replace duplicated xattr, preallocation, `statfs`, error-mapping, and tree-walk code. |
| **ERRATA-003-E8** | **P2** | `fsimpl/hostfs` | `~220` | `watcher_linux.go` and `watcher_other.go` are 100% identical; `tmpfile_{darwin,windows,unix}.go` duplicate non-Linux stubs; Unix and Windows files repeat `SyscallConn`, two-parent walk, `FindFirstFile`, and `GetFinalPathNameByHandle` loops. | Redundant OS stub files are merged and shared Unix/Windows helpers remove repeated syscall boilerplate. |
| **ERRATA-003-E9** | **P2** | `pkg/netbackend`, `pkg/gvx` | `~210` | `dns_relay.go` duplicates 110 lines of DNS relay logic between `NATForwarder` and `WireGuardEndpoint`; `gvx` and `netbackend` duplicate port-forward parsing, loopback stack setup, and `spawn` helpers. | A single `dnsRelay` struct, unified `PortForwardRule` parser, `NewLoopbackStack()`, and shared `spawn` helper remove all duplication. |
| **ERRATA-003-E10** | **P2** | `pkg/oci`, `fsimpl/erofs`, `fsimpl/hostfs`, `internal/gvxshim`, `cmd/rungv` | `~320` | `pkg/oci` duplicates EROFS on-disk constants from `fsimpl/erofs`, repeats internal archive/digest/file-close helpers, and duplicates Windows NT file operations (`FILE_RENAME_INFORMATION_EX`, `FileIdInfo`, `FileDispositionInfo`, relative `NtCreateFile`). | `pkg/oci` imports EROFS constants, consolidates internal archive/cache helpers, and shares Windows NT file helpers. |
| **ERRATA-003-E11** | **P3** | `pkg/gvx`, `pkg/hostlockdown`, `platform/systrap`, `cmd/rungv`, `internal/gvxshim` | `~280` | ELF64 header parsing lives in four packages (`kernel_runner.go` reads the same 64KB ELF prefix twice); `hostlockdown` resolves mount paths three times on Windows; `rungv` and `gvxshim` duplicate flag and socket helpers. | Unified ELF probing, single-pass mount resolution in `hostlockdown`, `imagecmd.go` flag reuse in `rungv`, and shared Unix socket helpers in `gvxshim`. |

---

## 2. E1: Duplicate ARM64 Exception Decoder, `CommPage` Layout, and EL1 Stubs Across `hvf`, `whpx`, and `hvcommon`

`pkg/sentry/platform/hvf` and `pkg/sentry/platform/whpx` independently define the shared-memory `CommPage` header, the ARM64 EL1 exception vector table and register spill/reload stub, and the `ESR_EL1` syndrome decoder. Maintaining two copies has already introduced four signal-delivery bugs between macOS and Windows on `arm64`.

### 2.1 Root Cause Analysis and Fault-Decoding Divergences (Descriptive Module)

1. **Identical 304-Byte `CommPage` Header (`hvf/comm_arm64.go:21-36`, `hvf/bluepill_arm64.go:55-65` vs. `whpx/layout.go:120-175`)**:
   - The first eight fields (`0x000..0x130`, `304` bytes) of `hvf.CommPage` and `whpx.CommPage` have the exact same offsets and types: `Regs [31]uint64` (`0x000`), `SP uint64` (`0x0F8`), `PC uint64` (`0x100`), `Pstate` / `PstateOrRflags uint64` (`0x108`), `TLS uint64` (`0x110`), `FaultAddr uint64` (`0x118`), `ESR` / `FaultCode uint64` (`0x120`), and `Vector uint64` (`0x128`).
   - `whpx/layout.go:141-155` hardcodes raw hex constants (`commOffRegs = 0x000`, `commOffSP = 0x0F8`), whereas `hvf/bluepill_arm64.go:55-65` derives them at compile time via `unsafe.Offsetof(CommPage{}.Field)`.
2. **Duplicate ARM64 EL1 Stub Builders and System Register Constants (`hvf/bluepill_arm64.go:35-51,74-181`, `hvf/sysreg_arm64.go:24-50` vs. `whpx/stubgen_a64.go:35-270`)**:
   - `hvf` defines `stubBuilder` (`hvf/bluepill_arm64.go:74-103`) while `whpx` defines `a64Asm` (`whpx/stubgen_a64.go:184-270`), wrapping every `hvcommon` instruction encoder in duplicate one-line methods.
   - Both generators emit the same 16-slot vector table at `0x000..0x800` (`STP X0, X1, [SP, #0]`; `MOVZ X0, #slot`; `STR X0, [SP, #commOffVector]`; `B 0x800`), the same `X2..X30` and `SP_EL0`/`ELR_EL1`/`SPSR_EL1`/`TPIDR_EL0`/`FAR_EL1`/`ESR_EL1` spill sequence, and the same reload and `ERET` tail.
   - Only three behaviors differ between the stubs: `hvf` spills and reloads `Q0..Q31`, `FPSR`, and `FPCR` in the stub (`bluepill_arm64.go:135-143,161-169`); `whpx` writes `ExitException` to `commOffExitReason` before `HVC #0` (`stubgen_a64.go:134-135`); and `whpx` optionally reloads `TTBR0_EL1` from `commOffRoot` before `TLBI VMALLE1` (`stubgen_a64.go:149-151`).
   - Both packages also re-declare local aliases for `hvcommon.VectorSlots..SlotLowerSError`, `SCTLR_EL1` bits (`M`, `C`, `I`, `DZE`, `UCT`, `UCI`, `RES1`), `PSTATE` masks, and 4KB page constants (`pageSize = 4096`, `minUserAddr = 0x10000`, `maxUserAddrA64 = 1 << 48`).
3. **Duplicate `ESR_EL1` Exception Decoders and Four Signal Divergences (`hvf/exit.go:22-68`, `hvf/exit_arm64.go:28-113,154-168` vs. `whpx/fault.go:27-65,141-256` and `pkg/hostarch/hostarch_arm64.go:67-81`)**:
   - `decodeStubExit` (`hvf/exit_arm64.go:53-113`) and `classifyA64` (`whpx/fault.go:162-220`) decode the same vector slot, `ESR_EL1`, `FAR_EL1`, and `ELR_EL1` values into syscalls (`EC 0x15`), instruction skips (`EC 0x01` WFx), trapped `MRS` reads (`EC 0x18`), page faults, or Linux signals (`SIGSEGV`, `SIGBUS`, `SIGTRAP`, `SIGILL`, `SIGFPE`).
   - `a64AccessType` (`whpx/fault.go:245-256`) is a line-for-line copy of `hostarch.ESRAccessType` (`pkg/hostarch/hostarch_arm64.go:67-81`).
   - Maintaining separate decoders caused four behavioral bugs:
     1. **Missing TBI Untagging in `whpx`**: `hvf/exit_arm64.go:101` strips the ARM64 Top-Byte-Ignore tag via `UntaggedUserAddr(far)`, whereas `whpx/fault.go:184` passes the tagged `far` directly to the Sentry memory manager even though `whpx` enables `TBI0` in `TCR(1)`.
     2. **`SP` Alignment Fault (`EC 0x26`) `si_addr` Mismatch**: `hvf/exit_arm64.go:71` reports `sp` as the faulting address (`SIGBUS`/`BUS_ADRALN`), whereas `whpx/fault.go:200` reports `pc`.
     3. **Watchpoint (`EC 0x34`) `si_addr` Mismatch**: `hvf/exit_arm64.go:80` reports `far` as the watchpoint address (`SIGTRAP`/`TRAP_HWBKPT`), whereas `whpx/fault.go:212` reports `pc`.
     4. **Trapped FP Exception (`EC 0x2C`) Signal Mismatch**: `whpx/fault.go:203` delivers `SIGFPE` (`FPE_FLTINV`), whereas `hvf/exit_arm64.go:84` falls through to `SIGILL` (`ILL_ILLOPC`).

### 2.2 Remediation Procedure for E1 (Procedural Module)

> [!CAUTION]
> Always strip the top byte (`addr & 0x00ff_ffff_ffff_ffff`) from `FAR_EL1` on lower-EL data and instruction aborts before passing the address to `mm.HandleUserFault`. Passing a tagged address on an `arm64` partition with `TBI0` enabled causes `HandleUserFault` to reject valid heap pointers with `SIGSEGV`.

1. Open `pkg/sentry/platform/hvcommon/a64.go` and export the shared `SCTLR_EL1`, `PSTATE`, and 4KB layout constants.
2. Define a shared `CommHeader` struct (`0x000..0x130`) and `unsafe.Offsetof`-derived `CommOff*` constants in `pkg/sentry/platform/hvcommon`.
3. Embed `CommHeader` at offset `0` of `hvf.CommPage` and `whpx.CommPage`.
4. Extract `BuildA64VectorPage(dst []byte, opts A64StubOptions)` in `pkg/sentry/platform/hvcommon/a64.go` for `SpillFP`, `ReloadTTBR0`, and `WriteExitReason`.
5. Replace `buildVectorPage` in `pkg/sentry/platform/hvf/bluepill_arm64.go` and `buildA64Stubs` in `pkg/sentry/platform/whpx/stubgen_a64.go` with `hvcommon.BuildA64VectorPage`.
6. Move `ESRAccessType`, `UntaggedUserAddr`, trapped `EC 0x18` `MRS` emulation, and `DecodeA64Exception` into `pkg/sentry/platform/hvcommon/a64.go`.
7. Standardize `DecodeA64Exception` to untag `FAR_EL1`, report `sp` on `EC 0x26`, and deliver `SIGFPE` on `EC 0x2C`.
8. Replace `decodeStubExit` in `pkg/sentry/platform/hvf/exit_arm64.go` and `classifyA64` / `emulateA64SysReg` / `a64AccessType` in `pkg/sentry/platform/whpx/fault.go` with `hvcommon` calls.
9. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvcommon/... ./pkg/sentry/platform/hvf/... ./pkg/sentry/platform/whpx/...`.

---

## 3. E2: Duplicate Stage-1 Page-Table Allocator, Slab Pool, `AddressSpace`, and vCPU Fault Handlers in `hvf` and `whpx`

After `ERRATA-001-E3` migrated `platform/hvf` onto `pkg/ring0/pagetables`, both `hvf` and `whpx` implemented identical Stage-1 page-table allocators, multi-page slab pools, `AddressSpace` wrappers, and vCPU fault handlers in separate packages.

### 3.1 Root Cause Analysis (Descriptive Module)

1. **Cloned `pagetables.Allocator` Implementations (`hvf/stage1.go:33-167` vs. `whpx/ptalloc.go:182-285` and `whpx/kernel.go:53`)**:
   - `hvf.tableAlloc` (`hvf/stage1.go:42-150`) and `whpx.ptAllocator` (`whpx/ptalloc.go:182-253`) maintain identical `ready []*pagetables.PTEs`, `owned map[...]`, and `quarantine []*pagetables.PTEs` fields.
   - Their `reserve`, `NewPTEs`, `FreePTEs`, `Recycle`, `quarantined`, and `drain` methods are functionally identical (`Recycle` and `quarantined` are character-for-character identical).
   - `reserveForMap(n)` (`hvf/stage1.go:154-157`) and `ptReserveFor(n)` (`whpx/ptalloc.go:257-263`) compute the same three-level upper bound (`n/512 + 2 + n/512^2 + 2 + n/512^3 + 2`); `reserveForUnmap = 4` (`hvf/stage1.go:162`) equals `ptSplitReserve = 4` (`whpx/ptalloc.go:268`); and `kernelTablePages = 16` (`hvf/stage1.go:167`) equals `kernelPageCount = 16` (`whpx/kernel.go:53`).
2. **Duplicate Multi-Page Slab Pools (`hvf/vm_darwin.go:42-68,223-288` vs. `whpx/ptalloc.go:28-172` and `whpx/gpa.go:29-85`)**:
   - Both backends allocate host slabs containing multiple 4KB pages (`16 KiB` = 4 pages on `hvf`; `64 KiB` = 16 pages on `whpx`), bump-allocate a GPA range in the page-table window, map the slab into Stage-2 once, and dispense 4KB `*pagetables.PTEs` entries from a free list while tracking bidirectional host-to-GPA translations.
3. **Duplicate Stage-1 `AddressSpace` Lifecycle (`hvf/stage1.go:180-291`, `hvf/address_space.go:36-160`, `hvf/regions.go:61-71,277-281` vs. `whpx/address_space.go:41-285`, `whpx/gpa.go:98-111`)**:
   - Both backends define the same `chunkedFile` interface (`memmap.File; TotalSize() uint64`), coalesce contiguous physical ranges (`hvf.segment` vs. `whpx.gpaRun` / `appendRun`), track `tlbGen` (`gen`) and `icGen` (`execGen`) atomic counters, and run the same `MapFile`, `Unmap`, `Release`, `PreFork`, `PostFork`, and `UserModifiedGS` sequences.
4. **Internal Copy-Paste Between `whpx/vcpu_arm64.go` and `whpx/vcpu_amd64.go`**:
   - `func (t trap) result() runResult` is copy-pasted verbatim in `whpx/vcpu_arm64.go:235-241` and `whpx/vcpu_amd64.go:300-306`.
   - `func (c *Context) onMemoryFault(v *vcpu, ex exitInfo, ac *arch.Context64) runResult` is copy-pasted in `whpx/vcpu_arm64.go:308-324` and `whpx/vcpu_amd64.go:366-382`, differing only in the 1-line kernel-mode predicate (`ex.cpsr&a64PstateModeMask != 0` vs. `ex.cpl != 3`).
   - `func (s *vpState) invalidate()` is duplicated in `whpx/vcpu_arm64.go:58-59` and `whpx/vcpu_amd64.go:87-88`.

### 3.2 Remediation Procedure for E2 (Procedural Module)

1. Define a `PagePool` interface and a shared `PTAllocator` struct (with `ReserveForMap`, `SplitReserve = 4`, and `KernelTablePages = 16`) in `pkg/sentry/platform/hvcommon`.
2. Replace `tableAlloc` in `pkg/sentry/platform/hvf/stage1.go` and `ptAllocator` in `pkg/sentry/platform/whpx/ptalloc.go` with `hvcommon.PTAllocator`.
3. Move `GPARun`, `AppendGPARun`, and `IsChunkedFile` into `pkg/sentry/platform/hvcommon` and reuse them in `hvf` and `whpx`.
4. Move `func (t trap) result() runResult` into `pkg/sentry/platform/whpx/fault.go`.
5. Add `func (e exitInfo) inKernel(arm64 bool) bool` in `pkg/sentry/platform/whpx/exitctx.go` and move `(*Context).onMemoryFault` into `pkg/sentry/platform/whpx/context.go`.
6. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvcommon/... ./pkg/sentry/platform/hvf/... ./pkg/sentry/platform/whpx/...`.

---

## 4. E3: Duplicate 64KB Chunk Page Cache, `memmap.Mappable`, and `safemem.Reader` Adapter in `hostfs` and `ext4lite`

`pkg/sentry/fsimpl/hostfs` and `pkg/sentry/fsimpl/ext4lite` contain near-verbatim copies of a 500-line 64KB chunked page cache and `memmap.Mappable` / `memmap.File` implementation.

### 4.1 Root Cause Analysis (Descriptive Module)

1. **Cloned 64KB Chunk Cache and `memmap.File` (`hostfs/regular_file.go:447-1055`, `hostfs/allocate.go:175-202`, `hostfs/hostfs.go:274-297` vs. `ext4lite/mmap.go:33-564`, `ext4lite/filesystem.go:53-76`)**:
   - Both packages define identical constants (`chunkShift = 16`, `chunkSize = 1 << chunkShift`, `chunkMask = chunkSize - 1`, `chunkAlign = 16 << 10`, `maxReadahead = 64 << 10`).
   - Both packages define identical `ChunkMemory` interfaces, `chunkMemoryHolder` structs, and `SetChunkMemory` functions, forcing `pkg/gvx/chunkmemory.go:33-44` (`configureChunkMemory`) to register the same allocator twice.
   - `cacheChunk` (`release`, `newChunk`, `newChunkBuf`), `fileData` (`dropLocked`, `takeWritebackErr`, `syncData`, `flushRange`, `writeThrough`, `punched`, `truncated`, `AddMapping`, `RemoveMapping`, `CopyMapping`, `InvalidateUnsavable`, `maxFillRange`, `markDirtyLocked`, `Translate`, `translationsLocked`), and `dataMemmapFile` (`IncRef`, `DecRef`, `MapInternal`, `DataFD`, `FD`) are duplicated across `hostfs/regular_file.go` and `ext4lite/mmap.go`.
2. **Duplicate `safemem.Reader` Block Copy Loops (`hostfs/regular_file.go:173-247` vs. `ext4lite/regular_file.go:111-192`)**:
   - `hostFileReader.ReadToBlocks` (`hostfs/regular_file.go:208-247`) and `nodeReader.ReadToBlocks` (`ext4lite/regular_file.go:149-192`) implement the exact same `safemem.BlockSeq` iteration over an `io.ReaderAt`: reading directly into `dst.ToSlice()` when `!dst.NeedSafecopy()` and falling back to a reusable `scratch` buffer with `safemem.Copy`.

### 4.2 Remediation Procedure for E3 (Procedural Module)

1. Create `pkg/sentry/fsimpl/chunkcache` as a Tier 1 package in `tools/upstream/diff_audit.go` and `tools/upstream/boundaries.go`.
2. Move `ChunkMemory`, `SetChunkMemory`, `Cache`, `MemmapFile`, and the `safemem.Reader` adapter into `pkg/sentry/fsimpl/chunkcache`.
3. Replace the duplicated chunk-cache implementations in `pkg/sentry/fsimpl/hostfs/regular_file.go` and `pkg/sentry/fsimpl/ext4lite/mmap.go` with `chunkcache.Cache`.
4. Update `pkg/gvx/chunkmemory.go` to call `chunkcache.SetChunkMemory` once.
5. Merge `pkg/gvx/chunkmemory_linux.go` and `pkg/gvx/chunkmemory_other.go` directly into `pkg/gvx/chunkmemory.go`.
6. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/fsimpl/chunkcache/... ./pkg/sentry/fsimpl/hostfs/... ./pkg/sentry/fsimpl/ext4lite/... ./pkg/gvx/...`.

---

## 5. E4: Fragmented ARM64 and x86-64 Instruction Encoders, `MRS` Emulation, and Slot Builders in `platform/systrap`

Across `pkg/sentry/platform/systrap` and `pkg/sentry/platform/hvcommon`, seven files define private ARM64 instruction encoders and opcode constants under different names, and two separate decoders emulate user-mode `MRS` reads of ARM64 feature registers.

### 5.1 Root Cause Analysis (Descriptive Module)

1. **Seven Duplicate AArch64 Instruction Encoder Sets**:
   - **`MOVZ` / `MOVK`**: Defined in `hvcommon/a64.go:76-79` (`MOVZ`, `MOVZW`), `patcher_arm64_xplat.go:38-39,242-248` (`arm64MOVZ`, `arm64MOVKLSL16`, `ctrWords`), `patcher_darwin_arm64_x18.go:127-135` (`movConst`), `patcher_darwin_arm64_zone.go:60,243-246` (`zoneMOVK`, `encodeMovZ`, `encodeMovK`), `stubcode_arm64_xplat.go:106-107` (`a64movzX`, `a64movzW`), `arch_windows_arm64.go:414` (`movzImm`), and `probe_darwin.go:146` (`movzW`).
   - **Branches and Register Moves (`B`, `BR`, `BLR`, `CBZ`, `TBZ`, `TBNZ`, `MOV`)**: Split across `hvcommon/a64.go:82-93`, `patcher_arm64_xplat.go:45-46,60,146-164` (`encodeBranch`, `decodeBranch`), `patcher_darwin_arm64_zone.go:64-66,235-239` (`zoneMovX16`, `zoneMovX17`, `zoneBrReg`, `encodeTBNZ`), and `stubcode_arm64_xplat.go:97,113-114` (`a64movReg`, `a64blr`, `a64br`).
   - **Loads and Stores (`LDR`, `STR`, `LDP`, `STP`)**: `hvcommon/a64.go:100-146` hardcodes `rn = 31` (`SP`) in `STPXSP..LDRWSP`, while `stubcode_arm64_xplat.go:70-95` (`a64ldrX..a64stp`), `patcher_arm64_xplat.go:49-50`, and `patcher_darwin_arm64_x18.go:408-414` (`strFromSysmsg`, `ldrFromSysmsg`) re-encode the same opcodes with arbitrary base registers `rn`.
   - **System Registers, Barriers, `BRK`, and `DC` Cache Maintenance**: `patcher_arm64_xplat.go:36` defines `arm64MRSTPIDR = 0xd53bd040` while `stubcode_arm64_xplat.go:45` defines `a64TPIDR = 0xd53bd040` in the same package; `stubcode_arm64_xplat.go:54` defines `a64BRK = 0xd4200000` while `arch_windows_arm64.go:45` defines `arm64BRK = 0xd4200000`; and `patcher_darwin_arm64_zone.go:205-218` (`isCacheMaintenanceByAddress`) re-lists all five `DC` opcodes from `patcher_arm64_xplat.go:130-143` (`arm64DCOps` / `isDataCacheMaintenance`).
2. **Duplicate AArch64 `MRS` ID Register Decoding and Fault Emulation (`patcher_arm64_xplat.go:78,275-306` vs. `hvcommon/a64.go:254-348`; `context_darwin.go:761-783` vs. `arch_windows_arm64.go:251-265`)**:
   - `decodeARM64SysRegMRS` (`patcher_arm64_xplat.go:275-306`) and `hvcommon.DecodeMRSSysRegISS` + `IDRegisters.EmulateSysRegRead` (`hvcommon/a64.go:254-348`) decode the exact same `0xd5300000`-prefixed `MRS` instructions for `MIDR_EL1`, `REVIDR_EL1`, `ID_AA64PFR0_EL1`, `ID_AA64PFR1_EL1`, `ID_AA64ISAR0_EL1`, `ID_AA64ISAR1_EL1`, `ID_AA64MMFR0_EL1`, `ID_AA64MMFR1_EL1`, `ID_AA64MMFR2_EL1`, `CTR_EL0` (`0x8444c004`), and `DCZID_EL0`.
   - `emulateARM64MRS` in `context_darwin.go:761-783` and `(*thread).emulateARM64MRS` in `arch_windows_arm64.go:251-265` execute the same 4-byte instruction read, `decodeARM64SysRegMRS` call, `rt != 31` register write, and `pc += 4` advance.
3. **Duplicate ARM64 Trampoline Slot Encoders and Probe Program (`patcher_arm64_xplat.go:179-238` vs. `stubcode_arm64_xplat.go:360-411`; `arch_windows_arm64.go:414-436` vs. `probe_darwin.go:91-98,146-147`)**:
   - `encodeTrapSlot` (`patcher_arm64_xplat.go:179-212`) and `encodeWinSlot` (`stubcode_arm64_xplat.go:360-385`) emit the same ARM64 syscall trampoline slot (spilling `x16, x17`, setting `x17` to the slot tail via `ADR`, loading the 64-bit handler literal into `x16`, branching with `BR x16`, and reloading `x16, x17` before branching to `retPC`).
   - `encodeLoadSlot` (`patcher_arm64_xplat.go:218-238`) and `encodeWinTLSSlot` (`stubcode_arm64_xplat.go:394-411`) emit the same 16-byte `mrs xN, tpidr_el0` replacement slot.
   - `arch_windows_arm64.go:414-436` and `probe_darwin.go:91-98,146-147` construct the same 7-instruction ARM64 guest loop (`movz x1, #calls; movz x8, #5; svc #0; subs x1, x1, #1; b.ne -8; movz x8, #6; svc #0`).
4. **Duplicate x86-64 Encoders, Constants, and Prefix Switches (`hvcommon/x86.go` vs. `stubcode_amd64_xplat.go`, `hostctx_xplat_amd64.go`, `arch_windows_amd64.go`)**:
   - `AppendMovToGS` / `AppendMovFromGS` (`hvcommon/x86.go:101-117`) and `(*x86Asm).movLoadGS` / `movStoreGS` (`stubcode_amd64_xplat.go:203-211`) emit the same 9-byte `0x65, REX.W, 0x8B/0x89, modrm, 0x25, disp32` sequence.
   - `hostctx_xplat_amd64.go:64-65` redefines `userSegCs = 0x33` and `userSegSs = 0x2b` (`hvcommon.SelUserCS64` and `hvcommon.SelUserSS`).
   - `hasFSPrefix` (`arch_windows_amd64.go:445-457`) and `hasPrefixBefore` (`arch_windows_amd64.go:562-581`) duplicate the same x86 legacy and REX prefix byte switch (`0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65`, `0x40..0x4F`).

### 5.2 Remediation Procedure for E4 (Procedural Module)

1. Generalize `pkg/sentry/platform/hvcommon/a64.go` with base-register-parameterized `STPX..LDRW` functions and `MOVK`, `MovConst`, `MOVReg`, `BR`, `BLR`, `TBNZ`, `BRK`.
2. Replace private ARM64 instruction encoders and duplicate constants across all six `systrap` ARM64 files with `hvcommon` calls.
3. Update `decodeARM64SysRegMRS` in `pkg/sentry/platform/systrap/patcher_arm64_xplat.go` to call `hvcommon.DecodeMRSSysRegISS` and `hvcommon.IDRegisters.EmulateSysRegRead`.
4. Parameterize `encodeTrapSlot` and `encodeLoadSlot` in `patcher_arm64_xplat.go` by scratch/TLS offsets and delete `encodeWinSlot` and `encodeWinTLSSlot` from `stubcode_arm64_xplat.go`.
5. Reuse `hvcommon` GS-move encoders and segment selectors in `stubcode_amd64_xplat.go` and `hostctx_xplat_amd64.go`, and extract `isX86Prefix` in `arch_windows_amd64.go`.
6. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvcommon/... ./pkg/sentry/platform/systrap/...`.

---

## 6. E5: Duplicate Trampoline Island Allocator, `addressSpace` Helpers, `Context` State Sync, and Probe Harness in `platform/systrap`

The macOS (`*_darwin.go`) and Windows (`*_windows.go`) files in `pkg/sentry/platform/systrap` duplicate the trampoline island allocator, `addressSpace` block-state lifecycle, `Platform` and `Context` interface methods, floating-point and `XSTATE` copy loops, shared-memory spin handoff, and startup probe harness.

### 6.1 Root Cause Analysis (Descriptive Module)

1. **Duplicate Trampoline Island Allocator and VMA Reservation (`address_space_darwin.go:40,71-148,795-918` vs. `fastisland_windows.go:41,50-101,154-184,229-299`)**:
   - `islandReach = 120 << 20` (`address_space_darwin.go:40`) equals `winIslandReach = 120 << 20` (`fastisland_windows.go:41`); `slotRef` (`address_space_darwin.go:71-75`) equals `winSlotRef` (`fastisland_windows.go:50-54`).
   - `(*island).alloc`, `(*island).free`, `(*addressSpace).inIsland`, `absDiff`, `(*addressSpace).allocSlot` (3-attempt search and `newIsland` fallback), and `(*addressSpace).newIsland` (128-attempt random offset scan in `[2 MiB, islandReach - 2 MiB)` and `mm.MMap` with `memmap.MMapOpts{Name: "[systrap]", Sealed: true, Perms: Read|Execute}`) are duplicated across both files.
2. **Identical `addressSpace` Types, Errors, and Block Helpers (`address_space_darwin.go` vs. `address_space_windows.go`, `libsystem_darwin.go`, `section_windows.go`)**:
   - Both OS implementations define identical copies of `blockState` (`blockData`, `blockExec`), `errAddressSpaceReleased`, `errPatchRaced`, `AlignmentError`, `blockRound`, `checkAligned`, `addrPtr(addr uint64) unsafe.Pointer` (`libsystem_darwin.go:109-111` vs. `section_windows.go:37-39`), `PatchedBlocks()`, `PreFork()`, `PostFork()`, `blockStateOf(base uint64)`, `inPatchedCode(pc uint64)`, the 4-retry `patchBlock` loop (`address_space_darwin.go:523-537` vs. `address_space_windows.go:513-524`), and the `Unmap` block-cleanup loop (`address_space_darwin.go:445-455` vs. `address_space_windows.go:446-456`).
   - `putWord` (`address_space_darwin.go:787-789`) reimplements `binary.LittleEndian.PutUint32`.
3. **Identical `Platform` and `Context` Methods, Fault Constants, and `Probe()` Harness (`platform_*.go`, `context_*.go`, `probe_*.go`, `fastselftest_windows.go`)**:
   - Five `Platform` methods (`SupportsAddressSpaceIO`, `MaxUserAddress`, `NewContext`, `SeccompInfo`, `ConcurrencyCount`) are 100% identical in `platform_darwin.go:201-268` and `platform_windows.go:210-248`.
   - Nine `Context` methods (`FullStateChanged`, `Interrupt`, `Preempt`, `Release`, `PrepareSleep`, `PrepareUninterruptibleSleep`, `PrepareStop`, `PrepareExecve`, `PrepareExit`), `errNoAddressSpace`, and 11 Linux `si_code` constants (`segvMapErr..illIllOpc`) are 100% identical in `context_darwin.go:67,570-574,714-750,804-844` and `context_windows.go:294-308,442-444,506-536` (`platform_windows.go:267`).
   - `probeCalls = 2000`, `probeMM`, and the guest `c.Switch` timing loop between syscall `5` and syscall `6` are duplicated across `probe_darwin.go:35-60,115-143`, `probe_windows.go:34-55,122-155`, and `fastselftest_windows.go:71-96`.
4. **Duplicate FP/XSTATE Copy Loops, `hostContext` Alignment, `armThreadState` Indexing, and Spin Handoff**:
   - **ARM64 NEON State Copy**: `context_darwin.go:523-554` (`loadFP`, `storeFP`, plus custom `putUint32`/`getUint32`), `hostctx_xplat_arm64.go:121-177`, and `winsysmsg_arm64_xplat.go:115-135` (`storeVector`, `loadVector`) all copy 512 bytes of `V[0..31]` plus `FPSR` and `FPCR` to and from `ac.FloatingPointData()`.
   - **AMD64 `XSTATE` Component Copy**: `winsysmsg_amd64_xplat.go:145-199` (`loadXsave`, `storeXsave`) and `hostctx_windows_amd64.go:142-194` (`loadXState`, `storeXState`) repeat the same `xstateComponents` iteration and `XSTATE_BV` bitmask manipulation.
   - **16-Byte Aligned `hostContext` Allocation**: `newHostContext` is duplicated in `hostctx_xplat_arm64.go:63-67` and `hostctx_windows_amd64.go:71-73`.
   - **Darwin `armThreadState` Indexed Register Access**: Switching on `reg < 29` (`X[reg]`) vs. `29` (`FP`), `30` (`LR`), and `31` (`SP`/`XZR`) is repeated in `store_emulate_darwin.go:73-105`, `context_darwin.go:444-457,770-780`, and `zone_fault_darwin.go:144-153`.
   - **4-State Spin-Then-Wait Handoff**: `waitTrapped` / `resume` (`context_darwin.go:224-262`) and `await` / `release` (`winsysmsg_xplat.go:205-251`) implement the same 512-round spin, waiter-bit publication, and conditional wake protocol.

### 6.2 Remediation Procedure for E5 (Procedural Module)

1. Extract the shared `island` allocator and `addressSpace` block helpers into `pkg/sentry/platform/systrap/address_space_xplat.go` (`//go:build darwin || windows`).
2. Move the shared `Platform` methods, `Context` methods, `si_code` constants, `probeMM`, and `runProbeLoop` into `pkg/sentry/platform/systrap/systrap_xplat.go`.
3. Add `arm64LoadFP` and `arm64StoreFP` in `hostctx_xplat_arm64.go` and call them from `context_darwin.go`, `hostctx_xplat_arm64.go`, and `winsysmsg_arm64_xplat.go`.
4. Extract a shared `xstate` copy helper in `hostctx_xplat_amd64.go` for `winsysmsg_amd64_xplat.go` and `hostctx_windows_amd64.go`.
5. Add `(*armThreadState).getReg(reg uint8) uint64` and `(*armThreadState).setReg(reg uint8, val uint64)` in `sysmsg_darwin_arm64.go` and call them across Darwin fault paths.
6. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/systrap/...`.

---

## 7. E6: Duplicate Linux Ring-0 Hypervisor Backend in `pkg/sentry/platform/slimvm` vs. `pkg/sentry/platform/kvm`

`pkg/sentry/platform/slimvm` (`//go:build linux && amd64`, `2,450` lines across 23 non-generated files) is a copy-paste fork of `pkg/sentry/platform/kvm` that replaces `KVM_*` ioctl numbers with four custom `_SLIMVM_*` ioctl numbers (`slimvm_const_amd64.go:27-32`) and contains a copy-paste bug in its exception handler.

### 7.1 Root Cause Analysis and Divergence Bugs (Descriptive Module)

1. **Over 2,000 Lines of Copy-Pasted `kvm` Files**:
   - `slimvm/slimvm_amd64.go:28-206` and `kvm/kvm_amd64.go:25-197` (`170` lines) are 100% identical (`userRegs`, `systemRegs`, `segment`, `descriptor`, `modelControlRegisters`, `cpuidEntries`).
   - `slimvm/address_space.go` + `address_space_x86.go` (`210` lines), `slimvm/allocator.go` (`75` lines), `slimvm/physical_map.go` + `physical_map_amd64.go` + `bluepill_fault.go` (`265` lines), `slimvm/bluepill*.go` + `bluepill_amd64.s` (`350` lines), `slimvm/machine*.go` (`850` lines), and `slimvm/context.go` + `slimvm.go` (`270` lines) duplicate the corresponding `kvm` files.
2. **x86 Exception Vector Classification Duplicated Across `slimvm`, `kvm`, and `whpx`**:
   - `slimvm/machine_amd64.go:192-205,266-380`, `kvm/machine_amd64.go:316-328,392-500`, and `whpx/fault.go:68-139` (`classifyX86`) all map x86 exception vectors (`#DE`, `#DB`, `#BP`, `#OF`, `#BR`, `#UD`, `#NM`, `#TS`, `#NP`, `#SS`, `#GP`, `#PF`, `#MF`, `#AC`, `#XM`) and `#PF` error-code bits to `linux.SignalInfo` and `hostarch.AccessType`.
   - **Divergence Bug in `slimvm`**: `slimvm/machine_amd64.go:337` sets `Code: 1` (`FPE_INTDIV`) instead of `Code: 2` (`FPE_INTOVF`) on `ring0.Overflow`, whereas `kvm/machine_amd64.go:460` and `whpx/fault.go:124` correctly set `Code: 2`.

### 7.2 Remediation Procedure for E6 (Procedural Module)

1. Open `pkg/sentry/platform/slimvm/machine_amd64.go` and fix line 337 so `ring0.Overflow` sets `Code: 2` (`FPE_INTOVF`).
2. Extract a shared x86 exception vector classifier `ClassifyX86Exception` in `pkg/sentry/platform/hvcommon/x86.go` and reuse it in `pkg/sentry/platform/whpx/fault.go` and `pkg/sentry/platform/slimvm/machine_amd64.go`.
3. Cross-compile `GOOS=linux GOARCH=amd64 go build ./pkg/sentry/platform/slimvm/... ./pkg/sentry/platform/kvm/...` and run `go test ./pkg/sentry/platform/hvcommon/... ./pkg/sentry/platform/whpx/...`.

---

## 8. E7: Duplicate VFS Xattr Validation, Host Preallocation, `Statfs`, Error Mapping, and Tree Helpers Across `hostfs`, `ext4lite`, and `erofs`

`pkg/sentry/fsimpl/hostfs` and `pkg/sentry/fsimpl/ext4lite` duplicate VFS extended-attribute permission checks, host disk preallocation syscalls, Windows volume space queries, disk-full error classification, and VFS dentry tree traversal helpers.

### 8.1 Root Cause Analysis (Descriptive Module)

1. **Duplicate VFS Xattr Permission and Capability Logic (`hostfs/xattr.go:64-72,333-437,539-592`, `ext4lite/xattr_vfs.go:30-149,208-233`, `erofs/erofs.go:438-484`)**:
   - `checkXattrPrefix(name string) error` is 100% identical in `hostfs/xattr.go:64-72` and `ext4lite/xattr_vfs.go:30-37`.
   - `listXattr` (`CAP_SYS_ADMIN` filtering of `trusted.`, `checkXattrPrefix`, null-terminated size accounting, and `ERANGE` check), `getXattr` (`XattrReadNeedsFilePermission`, `GenericCheckPermissions`, `CheckXattrPermissions`, `ERANGE` check, and `auth.FixupVfsCapDataOnGet`), `setXattr` (`auth.FixupVfsCapDataOnSet`), and `removeXattr` are duplicated across `hostfs/xattr.go:333-437` and `ext4lite/xattr_vfs.go:42-149` (with read paths also duplicated in `erofs/erofs.go:438-484`).
   - Inside `hostfs/xattr.go:539-592`, `regularFD` and `dirFD` define eight duplicate `ListXattr`, `GetXattr`, `SetXattr`, and `RemoveXattr` methods instead of defining them once on embedded `fileDescription` as `ext4lite/xattr_vfs.go:208-233` does.
2. **Duplicate Host Space Preallocation, `Statfs`, and Disk-Full Error Mapping (`hostfs/allocate_*.go` & `statfs_*.go` & `errors_*.go` vs. `ext4lite/storage_*.go` & `errors_*.go`)**:
   - **Preallocation**: `hostfs/allocate_linux.go:30-45` vs. `ext4lite/storage_linux.go:29-38` (`unix.Fallocate` with `EINTR` retry); `hostfs/allocate_darwin.go:60-88` vs. `ext4lite/storage_darwin.go:36-75` (`F_PREALLOCATE` with `F_ALLOCATECONTIG|F_ALLOCATEALL` fallback and `unix.Ftruncate`); and `hostfs/allocate_windows.go:67-84` vs. `ext4lite/storage_windows.go:59-70` (`SetFileInformationByHandle` with `FileAllocationInfo` and `FileEndOfFileInfo`).
   - **`Statfs` Queries**: `hostfs/statfs_windows.go:29-42,77-97` and `ext4lite/storage_windows.go:33-54,103-124` both define the 32-byte `FILE_FS_FULL_SIZE_INFORMATION` struct (class `7`), lazy-load `ntdll.dll!NtQueryVolumeInformationFile`, and invoke it on a host handle. `hostfs/statfs_linux.go:28-45`, `hostfs/statfs_darwin.go:27-40`, and `ext4lite/storage_unix.go:59-74` all run `unix.Fstatfs` in an `EINTR` retry loop.
   - **Disk-Full Error Mapping**: `ext4lite/errors_windows.go:26-43` hardcodes raw numeric `syscall.Errno` values (`39`, `112`, `1816`, `665`, `1295`) that `hostfs/errors_windows.go:134-169` already translates to `linuxerr.ENOSPC`.
3. **Hand-Rolled `PrependPath`, `IsDescendant`, and `openSpecial` (`hostfs/vfs.go:1734-1791`, `hostfs/special_node.go:238-254` vs. `ext4lite/filesystem.go:468-524`, `ext4lite/special.go:32-48`)**:
   - While `erofs/filesystem.go:504-511` calls upstream `genericfstree.PrependPath` and `genericfstree.IsDescendant`, both `hostfs` and `ext4lite` hand-roll identical `PrependPath`, `IsDescendant`, and `isAncestorLocked` implementations.
   - `openSpecial` for named pipes (`pipefs.NewConnectedPipeFDs`) and Unix domain sockets (`unix.BoundEndpointFD`) is 100% identical in `hostfs/special_node.go:238-254` and `ext4lite/special.go:32-48`.

### 8.2 Remediation Procedure for E7 (Procedural Module)

1. Embed `fileDescription` in `hostfs.regularFD` (`pkg/sentry/fsimpl/hostfs/regular_file.go`) and define `ListXattr`, `GetXattr`, `SetXattr`, `RemoveXattr`, `SetStat`, and `StatFS` once on `fileDescription`.
2. Extract shared host preallocation (`PreallocateFile`), `StatfsFile`, and disk-full error classification helpers into `pkg/sentry/fsimpl/chunkcache` (or `pkg/sentry/fsimpl/hostfile`) and delete `ext4lite/errors_unix.go` and `ext4lite/errors_windows.go`.
3. Replace the custom `PrependPath`, `IsDescendant`, and `isAncestorLocked` methods in `pkg/sentry/fsimpl/hostfs/vfs.go` and `pkg/sentry/fsimpl/ext4lite/filesystem.go` with `genericfstree.PrependPath` and `genericfstree.IsDescendant`.
4. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/fsimpl/hostfs/... ./pkg/sentry/fsimpl/ext4lite/...`.

---

## 9. E8: Redundant Platform Files and Syscall Boilerplate Inside `pkg/sentry/fsimpl/hostfs`

Inside `pkg/sentry/fsimpl/hostfs`, several OS-tagged files are either character-for-character identical or repeat multi-step Unix and Windows syscall wrappers that already exist in sibling files.

### 9.1 Root Cause Analysis (Descriptive Module)

1. **100% Identical `watcher_linux.go` and `watcher_other.go`**:
   - `pkg/sentry/fsimpl/hostfs/watcher_linux.go:1-28` (`//go:build linux`) and `pkg/sentry/fsimpl/hostfs/watcher_other.go:1-24` (`//go:build !linux && !darwin && !windows`) contain the exact same 3-line `newWatchBackend` function returning `newPollBackend(hw), nil`.
2. **Three Redundant Non-Linux `tmpfile` Stub Files (`tmpfile_darwin.go`, `tmpfile_windows.go`, `tmpfile_unix.go`)**:
   - `tmpfile_darwin.go:1-34` and `tmpfile_windows.go:1-38` define identical stubs (`const tmpfileUnlinkAtOnce = false`, `anonUnsupported`, and `errHostUnsupported`). `tmpfile_unix.go:1-27` contains only a 3-line `(h *hostRoot) openAnonAt` wrapper used on Linux.
3. **Unshared `withFileFD` Helper Across Five Unix Files**:
   - `xattr_linux.go:114-124` defines `withFileFD(f *os.File, fn func(fd int) error) error`, whereas `inode_unix.go:328-343` (`syncFile`), `inode_darwin.go:36-47` (`utimensFile`), `allocate_linux.go:31-44`, and `allocate_darwin.go:37-53` each repeat the 12-line `f.SyscallConn()` + `rc.Control(...)` pattern inline.
4. **Duplicate Two-Parent Path Walks and Probe Helpers (`inode_unix.go`, `rename_flags_unix.go`, `caps_linux.go`, `caps_darwin.go`, `posix_rename_windows.go`)**:
   - `rename` (`inode_unix.go:383-402`), `link` (`inode_unix.go:404-422`), and `exchange` (`rename_flags_unix.go:28-46`) repeat the same 18-line double `walkParent` + `unix.Close` cleanup block.
   - `probeRenameSwap` in `caps_linux.go:43-53` and `caps_darwin.go:45-59` duplicates temporary probe file creation, `renameSwap(dir, nameA, dir, nameB)`, and `unix.Unlinkat` cleanup.
   - On Windows, `rename` (`posix_rename_windows.go:163-196`) and `link` (`posix_rename_windows.go:200-233`) repeat the same two-parent walk, source handle open, UTF-16 conversion, and `NtSetInformationFile` dispatch.
5. **Duplicate Windows `FindFirstFile` and `GetFinalPathNameByHandle` Loops (`inode_windows.go`, `watcher_windows.go`, `statfs_windows.go`)**:
   - `readDir` (`inode_windows.go:807-829`) and `listNames` (`watcher_windows.go:442-461`) duplicate the `windows.FindFirstFile` / `FindNextFile` / `FindClose` directory enumeration loop.
   - `finalPathLeaf` (`inode_windows.go:582-602`) and `finalDirPath` (`statfs_windows.go:101-114`) duplicate the `windows.GetFinalPathNameByHandle` buffer-growth loop.

### 9.2 Remediation Procedure for E8 (Procedural Module)

1. Delete `pkg/sentry/fsimpl/hostfs/watcher_linux.go` and update the build constraint in `pkg/sentry/fsimpl/hostfs/watcher_other.go` to `//go:build !darwin && !windows`.
2. Move `(h *hostRoot) openAnonAt` into `pkg/sentry/fsimpl/hostfs/tmpfile_linux.go`, delete `tmpfile_darwin.go` and `tmpfile_unix.go`, and rename `tmpfile_windows.go` to `tmpfile_other.go` with `//go:build !linux`.
3. Move `withFileFD` into `pkg/sentry/fsimpl/hostfs/inode_unix.go` and call it from `syncFile`, `utimensFile`, `allocateNative`, and `xattr_linux.go`.
4. Extract `(h *hostRoot) withTwoParents` in `inode_unix.go` for `rename`, `link`, and `exchange`, and unify `probeRenameSwap` in `rename_flags_unix.go`.
5. Extract shared `enumDirNames` and `finalPathByHandle` helpers in `pkg/sentry/fsimpl/hostfs/inode_windows.go` and call them from `watcher_windows.go` and `statfs_windows.go`.
6. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/fsimpl/hostfs/...`.

---

## 10. E9: Duplicate Virtual DNS Relay, Port-Forward Parser, Loopback Setup, and Goroutine Spawner in `pkg/netbackend` and `pkg/gvx`

`pkg/netbackend` and `pkg/gvx` duplicate virtual DNS query dispatch between the NAT and WireGuard backends, maintain two separate `-p` port-forward parsers and structs, and repeat netstack loopback initialization.

### 10.1 Root Cause Analysis (Descriptive Module)

1. **Duplicate Virtual DNS Relay Methods (`pkg/netbackend/dns_relay.go:143-246` vs. `424-533`)**:
   - Within `pkg/netbackend/dns_relay.go`, `NATForwarder.handleDNSQuery` (`143-179`), `NATForwarder.lookupLocalAddrs` (`184-216`), and `NATForwarder.forwardRawDNSUpstream` (`221-246`) are 98% identical to `WireGuardEndpoint.handleDNSQuery` (`424-461`), `WireGuardEndpoint.lookupLocalAddrs` (`463-492`), and `WireGuardEndpoint.forwardRawDNSUpstream` (`494-533`).
2. **Duplicate Port-Forward Rule Structs and Parsers (`pkg/gvx/config.go:25-39,83-143` vs. `pkg/netbackend/port_forwarder.go:26-44,63-112` and `pkg/gvx/netstack.go:88-100`)**:
   - `gvx.PortForward` / `gvx.ParsePortForward` and `netbackend.PortForwardRule` / `netbackend.ParsePortForwardRule` both parse `[ip:]hostPort:guestPort[/tcp|/udp]` specifications, and `pkg/gvx/netstack.go:88-100` copies each `gvx.PortForward` into a `netbackend.PortForwardRule`.
3. **Duplicate Loopback Stack Initialization and `spawn` Helpers (`pkg/gvx/netstack.go:39-70` vs. `pkg/netbackend/nat_forwarder.go:108-123,209-224,324-337` and `port_forwarder.go:275-288`)**:
   - `initNetstack` (`pkg/gvx/netstack.go:39-70`, `NetModeNone` branch) repeats the `stack.New` + `configureLoopbackNIC` sequence from `pkg/netbackend/nat_forwarder.go:108-123,209-224`.
   - `NATForwarder.spawn` (`nat_forwarder.go:324-337`) and `PortForwarder.spawn` (`port_forwarder.go:275-288`) are line-for-line identical.

### 10.2 Remediation Procedure for E9 (Procedural Module)

1. Extract a `dnsRelay` struct in `pkg/netbackend/dns_relay.go` and invoke it from both `NATForwarder` and `WireGuardEndpoint`.
2. Upgrade `netbackend.ParsePortForwardRule` in `pkg/netbackend/port_forwarder.go` with IPv6 bracket and single-port support.
3. Alias `gvx.PortForward = netbackend.PortForwardRule` in `pkg/gvx/config.go` and delete the conversion loop in `pkg/gvx/netstack.go:88-100`.
4. Export `NewLoopbackStack() (*stack.Stack, error)` from `pkg/netbackend` and call it in `pkg/gvx/netstack.go:39-70`.
5. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/netbackend/... ./pkg/gvx/...`.

---

## 11. E10: Duplicate EROFS Format Constants, Archive Loaders, Digest Helpers, and Windows NT File Operations Across `pkg/oci`, `erofs`, `hostfs`, and `internal/gvxshim`

`pkg/oci` duplicates every EROFS on-disk constant from `pkg/sentry/fsimpl/erofs`, contains multiple internal duplicate helpers across `cache.go`, `load.go`, `archive.go`, `store.go`, and `save.go`, and reimplements Windows NT file primitives that also appear in `hostfs` and `internal/gvxshim`.

### 11.1 Root Cause Analysis (Descriptive Module)

1. **Duplicate EROFS On-Disk Constants and Xattr Prefix Tables (`pkg/oci/tar2erofs.go:37-56`, `pkg/oci/erofs_layout.go:32-56,104-119` vs. `pkg/sentry/fsimpl/erofs/erofs.go:47-105`)**:
   - `pkg/oci` redefines `EROFSSuperBlockMagicV1 = 0xe0f5e1e2`, `EROFSSuperBlockOffset = 1024`, `EROFSInodeSlotBits = 5`, `EROFSInodeExtendedSize = 64`, `EROFSDirentSize = 12`, data layout constants, chunked-file feature flags, xattr header sizes, and xattr prefix indices already defined in `pkg/sentry/fsimpl/erofs/erofs.go:47-105`.
2. **Internal Duplications Within `pkg/oci` (`cache.go`, `load.go`, `archive.go`, `store.go`, `save.go`, `pull.go`, `registry.go`)**:
   - `closeAllFiles` (`pkg/oci/cache.go:428-434`) and `CloseLayerFiles` (`pkg/oci/cache.go:453-463`) sit 20 lines apart in the same file and close every non-nil `*os.File` in a slice.
   - `blobDigest(b []byte) string` is defined in `pkg/oci/load.go:50-53` and reimplemented inline in `pkg/oci/cache.go:621-622` and `pkg/oci/registry.go:285-286`.
   - `blobMemberName` (`pkg/oci/archive.go:180-185`) and `saveBlobPath` (`pkg/oci/save.go:50-52`) both format `"blobs/sha256/" + hex`.
   - `archive.load` / `loadOCILayout` (`pkg/oci/archive.go:216-273`) and `archive.register` / `registerOCILayout` (`pkg/oci/load.go:88-159`) duplicate archive indexing, `index.json`/`oci-layout`/`manifest.json` dispatch, manifest-chain resolution, config digest verification, and config parsing.
   - `ParseRuntimeConfig` (`pkg/oci/pull.go:207-238`) duplicates the JSON unmarshaling of `parseImageConfig` (`pkg/oci/pull.go:175-205`).
   - `LoadCachedImage` (`pkg/oci/cache.go:568-578`), `imageByReference` (`pkg/oci/store.go:324-337`), and `CachedDigest` (`pkg/oci/store.go:568-578`) repeat the same 11-line `tagRecord` read and `!isDigestRef(tr.Digest)` validation block.
   - `removeIfExists(path string) error` is duplicated in `pkg/oci/store.go:422-427` and `cmd/rungv/save.go:133-138`.
3. **Duplicate Windows NT File Primitives (`pkg/oci/fileops_windows.go`, `hostfs/posix_rename_windows.go`, `hostfs/inode_windows.go`, `internal/gvxshim/platform_windows.go`)**:
   - `FILE_RENAME_INFORMATION_EX` (`class 65`) with `NtSetInformationFile` is implemented in `pkg/oci/fileops_windows.go:38-46,106-122` and `pkg/sentry/fsimpl/hostfs/posix_rename_windows.go:30,46-51,90-105,182-187`.
   - `FileIdInfo` identity lookup (`GetFileInformationByHandleEx`), `FileDispositionInfo` delete-on-handle (`SetFileInformationByHandle`), and relative `NtCreateFile` with `OBJECT_ATTRIBUTES` are duplicated between `internal/gvxshim/platform_windows.go:18-21,79-107,144-166,319-320` and `pkg/sentry/fsimpl/hostfs/inode_windows.go:68-73,296-331,505-510` (`posix_rename_windows.go:142-151`).

### 11.2 Remediation Procedure for E10 (Procedural Module)

1. Import the EROFS on-disk constants in `pkg/oci` from `pkg/erofs` or `pkg/sentry/fsimpl/erofs`.
2. Delete the duplicate EROFS constant blocks in `pkg/oci/tar2erofs.go` and `pkg/oci/erofs_layout.go`.
3. Replace `closeAllFiles` in `pkg/oci/cache.go:428-434` with `_ = CloseLayerFiles(files)`, reuse `blobDigest` and `blobMemberName`, and extract `(*LayerCache).readTagDigest`.
4. Factor the shared archive manifest/config resolution step out of `pkg/oci/archive.go:216-273` and `pkg/oci/load.go:88-159`, and have `ParseRuntimeConfig` call `parseImageConfig` in `pkg/oci/pull.go`.
5. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/oci/... ./cmd/rungv/...`.

---

## 12. E11: Duplicate ELF Header Parsing, Config Helpers, Mount-Path Resolution, CLI Flags, and Shim Socket Helpers

Across `pkg/gvx`, `pkg/hostlockdown`, `pkg/sentry/platform/systrap`, `cmd/rungv`, and `internal/gvxshim`, several helper functions parse the same ELF headers, resolve the same host mount paths multiple times during startup, or bypass shared CLI and Unix socket helpers.

### 12.1 Root Cause Analysis (Descriptive Module)

1. **Duplicate ELF64 Header Parsing and Double 64KB VFS Reads (`pkg/gvx/elfheader.go:23-72`, `elflayout.go:64-67`, `nonpie.go:72-77`, `image.go:45-74`, `kernel_runner.go:434,498`, `systrap/code_image_xplat.go:44-92`, `cmd/rungv/run.go:431-444`)**:
   - `pkg/gvx/image.go:45-74` (`elfMachine`, `validateELF64Arch`) and `pkg/sentry/platform/systrap/code_image_xplat.go:59-72` (`parseCodeImage`) both open an ELF binary with `debug/elf`, map `"amd64"` to `elf.EM_X86_64` and `"arm64"` to `elf.EM_AARCH64`, and verify `ELFCLASS64`.
   - `pkg/gvx/elfheader.go:31-72` (`loadSegment`, `parseLoadSegments`) and `systrap/code_image_xplat.go:44-78` both extract `PT_LOAD` segments; `cmd/rungv/run.go:431-444` (`isHostELFFile`) manually checks the 5-byte ELF64 magic prefix (`0x7f, 'E', 'L', 'F', 2`).
   - During container startup in `pkg/gvx/kernel_runner.go:434,498`, `checkELFLayout` (`elflayout.go:64`) and `nonPIEHintForGuestFile` (`nonpie.go:72`) read the first `64 KiB` (`elfProbeBytes`) of the same guest executable from VFS twice.
2. **Duplicate Config, Size-Parsing, and Terminal Helpers in `pkg/gvx` (`mounts.go`, `resources.go`, `command.go`, `kernel_runner.go`, `image.go`)**:
   - `parseTmpfsSize` (`pkg/gvx/mounts.go:312-335`) and `ParseMemory` (`pkg/gvx/resources.go:39-81`) both parse byte quantities with `b`, `k`, `m`, and `g` suffixes.
   - `pkg/gvx/kernel_runner.go:880` re-hardcodes the `defaultPath` string already defined in `pkg/gvx/command.go:98`.
   - `isHostTerminalReader` (`pkg/gvx/kernel_runner.go:117-127`) checks `os.ModeCharDevice` (which also matches `/dev/null`) instead of calling `oci.IsTerminal` (`pkg/oci/terminal.go:26-29`).
   - `elfLayerTar` (`pkg/gvx/image.go:78-96`) and `writeTarFile` (`pkg/oci/save.go:210-219`) both construct single-entry tar archives in memory.
3. **Triplicated Mount-Path Resolution and Duplicate Token Probe Runner in `pkg/hostlockdown` (`lockdown.go:175-199`, `lockdown_darwin.go:105-122`, `lockdown_windows.go:218-231`, `workspace_windows.go:88-95`, `probe_windows.go:36-47,107-124`)**:
   - `validateMounts`, `resolveMounts` (Darwin), `resolveMount` (Windows), and `prepareWorkspace` (Windows) all execute `filepath.Abs` + `filepath.EvalSymlinks` + root-directory rejection (`filepath.Dir(r) == r`). On Windows, every mount path runs `Abs` + `EvalSymlinks` three times during lockdown.
   - `probeRestrictedOpenBlocked` (`probe_windows.go:36-47`) and `probeRestrictedSocketBlocked` (`probe_windows.go:107-124`) duplicate the goroutine spawn, `runtime.LockOSThread()`, and `windows.SetThreadToken(nil, token)` probe harness.
4. **Bypassed `imagecmd.go` Flag Helpers in `cmd/rungv/pull.go:45-71` and `cmd/rungv/stub.go:42-59`**:
   - Both files manually construct `flag.NewFlagSet`, check `errors.Is(err, flag.ErrHelp)`, and format usage errors instead of calling `newImageFlagSet`, `addImageCacheFlags`, `parseImageFlags`, `imageFail`, and `imageUsageError` from `cmd/rungv/imagecmd.go:29-81`.
5. **Duplicate Unix Socket Authorization, Pinned Bind, and Log FIFO Validation in `internal/gvxshim` (`platform_darwin.go:13-84`, `platform_linux.go:13-66`, `log_unix.go:26-49,84-92`, `log_windows.go:25-40`)**:
   - `authorizePeer` and `bindPinnedSocket` in `platform_darwin.go` and `platform_linux.go` are 85% identical, differing only in `GetsockoptXucred` vs. `GetsockoptUcred` and how the socket is bound in `dirFD`.
   - `openLog` is duplicated between `log_unix.go:26-49` and `log_windows.go:25-40`, and `log_unix.go` duplicates its 9-line FIFO `Stat_t` validation block between `openLog` (lines 37-45) and `Write` (lines 84-92).

### 12.2 Remediation Procedure for E11 (Procedural Module)

1. Combine the guest ELF header read in `pkg/gvx/kernel_runner.go` so `checkELFLayout` and `nonPIEHintForGuestFile` share one `64 KiB` buffer.
2. Reuse `defaultPath` (`command.go:98`), `ParseMemory` (`resources.go:39`), and `oci.IsTerminal` (`pkg/oci/terminal.go:26`) inside `pkg/gvx`.
3. Move `resolveMounts` into `pkg/hostlockdown/lockdown.go` and extract `runOnRestrictedThread` in `pkg/hostlockdown/probe_windows.go`.
4. Refactor `cmd/rungv/pull.go` and `cmd/rungv/stub.go` to call the flag helpers in `cmd/rungv/imagecmd.go`.
5. Move `authorizePeer` and `bindPinnedSocket` into `internal/gvxshim/platform_unix.go` and extract `validateFIFOInfo` in `internal/gvxshim/log_unix.go`.
6. Run `go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/gvx/... ./pkg/hostlockdown/... ./cmd/rungv/... ./internal/gvxshim/...`.

---

## 13. Verification and Audit Procedure (Procedural Module)

> [!IMPORTANT]
> Run `go test` through `scripts/codesign-exec.sh` on macOS. Always verify that the `1.0%` upstream diff budget (`-max-ratio=0.01`) and all five target platforms build cleanly after any file move or package extraction.

1. Format all modified Go files and run the native `-race` test suites on `darwin/arm64` via `scripts/codesign-exec.sh`.
2. Cross-compile all packages across `darwin/arm64`, `windows/amd64`, `windows/arm64`, `linux/amd64`, and `linux/arm64`.
3. Run the upstream diff audit tool to confirm that modified upstream files stay below `1.0%` (`-max-ratio=0.01`).
4. Run the mechanical ASD-STE100 and anti-slop `ripgrep` checks against `README.md`, `AGENTS.md`, and `docs/`.

```bash
# 1. Format and run native unit tests with -race on darwin/arm64
go fmt ./...
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvcommon/... ./pkg/sentry/platform/hvf/... ./pkg/sentry/platform/whpx/... ./pkg/sentry/platform/systrap/... ./pkg/sentry/fsimpl/hostfs/... ./pkg/sentry/fsimpl/ext4lite/... ./pkg/netbackend/... ./pkg/oci/... ./pkg/gvx/... ./pkg/hostlockdown/... ./cmd/rungv/... ./internal/gvxshim/...

# 2. Cross-compile all five official target platforms
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=arm64 go build ./...

# 3. Verify upstream diff budget (< 1.0%)
go run ./tools/upstream -mode=audit -offline -max-ratio=0.01

# 4. Verify zero em-dashes, spaced en-dashes, or prose arrows in documentation
rg -n "\x{2014}| \x{2013} |\x{2192}" README.md AGENTS.md docs/ 2>/dev/null
```
