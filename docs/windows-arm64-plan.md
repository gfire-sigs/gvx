# Windows ARM64 Implementation Assessment and Plan

This document compares the macOS ARM64 implementation with the Windows ARM64 implementation.
It proposes the work needed to verify native Linux ARM64 workloads on Windows through WHPX.

| Item | Scope |
| :--- | :--- |
| Status | Proposed implementation plan; current source assessment |
| Primary milestone | M2: WHPX initialization, guest entry, and static ELF execution |
| Related milestones | M1 host primitives; M3 dynamic workloads; M4 containment; M5 systrap |
| Architecture authority | [Architecture and milestone contracts](architecture.md) |
| Main owners | `pkg/sentry/platform/whpx`, `pkg/sentry/platform/hvcommon`, `pkg/gvx`, and `e2e` |
| Update trigger | Changes to ARM64 initialization, register transfer, containment, or native verification |

## 1. Recommendation (Descriptive Module)

Windows ARM64 already has WHPX and systrap implementations.
The next work should complete and verify the existing WHPX backend.
The macOS HVF backend supplies an architectural reference for guest execution, memory isolation, and cancellation.

The first blocking gap concerns interrupt controller configuration.
The Windows backend omits the ARM64 GIC configuration that Microsoft requires before partition setup.
Native tests reproduced a setup failure before any guest instruction executed.

The proposed sequence is: partition initialization, CPU state, memory lifetime, workload compatibility, containment, and sustained verification.
Cross-compilation and systrap results cannot establish WHPX execution support.
Each stage requires observable results from an explicitly selected backend.

## 2. Current Implementation (Reference Module)

The following inventory separates existing code from execution evidence.
The presence of a test does not establish a passing native result.

| Boundary | Existing implementation | Consequence for the plan |
| :--- | :--- | :--- |
| M1 host primitives | Windows siblings implement futex waits, mappings, descriptors, clocks, and memory allocation. | Reuse these packages; investigate only failing ARM64 contracts. |
| M2 Windows backend | `whpx` contains DLL calls, ARM64 registers, exception stubs, page tables, and cancellation. | Repair startup before changing guest execution. |
| M2 macOS backend | `hvf` implements EL1 entry, 4KB Stage-1 tables, communication pages, and worker threads. | Compare invariants; retain Windows API ownership in `whpx`. |
| Shared ARM64 logic | `hvcommon` contains instruction encoders, vector generation, exception decoding, and table allocation. | Extend shared pure logic only when both backends require the same contract. |
| M3 integration | `pkg/gvx` selects backends and coordinates OCI, Sentry, and networking. | Reuse the Linux ARM64 ABI and image pipeline. |
| M4 containment | Windows code configures restricted tokens, jobs, workspace access, and network restrictions. | Verify containment separately from guest execution. |
| M5 fallback | Windows systrap contains ARM64 patching, debug stops, TLS transfer, and shared communication. | Preserve this independent execution path. |
| macOS fallback | `platform_darwin.go` returns `ErrUnavailable`. | No active macOS systrap implementation exists to port. |

Sources: [Windows backend](../pkg/sentry/platform/whpx/backend_windows.go),
[ARM64 vCPU](../pkg/sentry/platform/whpx/vcpu_arm64.go),
[macOS vCPU](../pkg/sentry/platform/hvf/vcpu_darwin_arm64.go),
[shared ARM64 logic](../pkg/sentry/platform/hvcommon/a64.go),
and [Windows systrap](systrap-windows.md).

The [embedded unix package](x-sys-unix.md) supplies Linux-shaped types and host bindings inside this module.
Windows work must use this existing boundary where Sentry expects Linux interfaces.
An external `x/sys` replacement would not propagate to SDK consumers.

The Windows DLL adapter uses the `windows` build constraint.
The WHPX ARM64 vCPU file uses `arm64`, which also permits scripted backend tests on other ARM64 hosts.
HVF host bindings use Darwin constraints and ARM64 filenames.
Changes inside these additive platform packages require no upstream Sentry edits.

### CI Coverage

The current workflows compile all five supported targets.
The ARM64 Windows job executes the shim, systrap, and selected runtime suites.

| Workflow | ARM64 Windows coverage | Missing evidence |
| :--- | :--- | :--- |
| [CI build job](../.github/workflows/ci.yml) | Whole-root build and selected vet commands | Native hardware behavior |
| CI Windows ARM64 job | Shim controls, systrap platform tests, and selected offline suites | WHPX package tests and WHPX guests |
| [Weekly image gates](../.github/workflows/e2e-images.yml) | ARM64 image workloads through systrap | ARM64 image workloads through WHPX |
| CI macOS job | Signed tests on a hosted runner | Native HVF guests when the runner lacks a hypervisor |

The shim tests verify a control adapter without workload creation.
Their success supplies no evidence about either ARM64 execution backend.

## 3. Transfer from macOS (Descriptive Module)

HVF and WHPX share the Linux ARM64 execution model.
Their host APIs, initialization requirements, and state transfer mechanisms differ.

| Concern | macOS HVF implementation | Windows implementation or required action |
| :--- | :--- | :--- |
| Guest syscall | EL0 `SVC #0`, EL1 vectors, shared state, then `HVC #0` | Reuse the existing vector generator and WHPX hypercall exit. |
| Privilege separation | Immutable EL1 mappings through `TTBR1_EL1`; user mappings through `TTBR0_EL1` | Preserve the existing shared kernel tree and separate user roots. |
| Guest page size | 4KB Stage-1 entries over 16KB host mappings | Preserve 4KB entries over Windows mappings with 64KB allocation alignment. |
| Memory registration | HVF retains Stage-2 registrations for backing regions. | WHPX retains GPA registrations and updates guest page tables. |
| vCPU ownership | A dedicated locked thread creates, executes, and destroys each vCPU. | WHPX leases vCPUs and locks the calling thread during `Switch`. |
| GPR and TLS transfer | The communication page carries registers and `TPIDR_EL0`. | Keep the WHPX communication protocol and root reload flags. |
| FP transfer | The stub spills vectors into the HVF communication page. | WHPX retains FP state on a vCPU and synchronizes through register APIs. |
| Cancellation | HVF distinguishes EL0, partial spill, and partial reload. | Verify the equivalent WHPX branches against real cancellation exits. |
| Read-only backing | HVF can copy rejected host mappings into private backing. | Verify WHPX direct mappings before introducing any copy path. |
| Host containment | Seatbelt restricts host operations. | Restricted tokens and jobs retain Windows ownership. |

The existing [shared vector generator](../pkg/sentry/platform/hvcommon/a64.go) already supports both hardware backends.
HVF selects FP spill options; WHPX selects root reload and exit notification options.
Copying the complete HVF communication page would break the WHPX protocol.

The [HVF worker](../pkg/sentry/platform/hvf/worker_darwin.go) exists because Hypervisor.framework binds a vCPU to its creation thread.
The [WHPX context](../pkg/sentry/platform/whpx/context.go) instead binds the execution thread to the restricted token.
The port needs the same containment outcome without copying the macOS worker model.

## 4. Gaps and Risks (Reference Module)

The findings below distinguish source omissions, native failures, and unresolved compatibility risks.
Priority describes implementation order within this plan.

| Priority | Finding | Evidence | Required result |
| :--- | :--- | :--- | :--- |
| P0 | Partition setup omits ARM64 interrupt controller configuration. | `createPartition` sets processor count and hypercall exits, then calls setup without GIC parameters. | Native partition creation succeeds with valid GICv3 configuration. |
| P0 | vCPU initialization omits the redistributor base. | `archBringUp` writes EL1 registers without `WHvArm64RegisterGicrBaseGpa`. | Every vCPU receives a distinct valid redistributor region before execution. |
| P0 | ARM64 WHPX has no routine native execution gate. | CI selects systrap on the ARM64 hosted runner. | A capable ARM64 host executes explicit WHPX tests without skips. |
| P1 | FP converters use different byte layouts. | WHPX, HVF, and systrap read different offsets in `FloatingPointData`. | Guest vectors and control registers survive signals and context migration. |
| P1 | WHPX uses baseline ID registers. | `newVP` selects `DefaultIDRegisters`; HVF reads hardware ID registers. | Advertised features match the executable guest instruction set. |
| P1 | Cancellation and table retirement depend on precise ordering. | Both backends invalidate generations before recycling table pages. | Native concurrent unmap, release, and cancellation preserve isolation. |
| P1 | systrap provides a weaker NT boundary. | The Windows design documents executable NT syscall sites outside guest pages. | Backend selection exposes this distinction to callers. |

### Partition Initialization

Microsoft requires `WHvPartitionPropertyCodeArm64IcParameters` before `WHvSetupPartition` on ARM64.
The property selects GICv3 emulation and supplies its parameters.
The [setup contract](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvsetuppartition) documents failure when this configuration is absent.

The current [partition initialization](../pkg/sentry/platform/whpx/backend_windows.go) contains no call that sets this property.
A controlled native probe reproduced the failure without GIC configuration and succeeded after adding that configuration.
This confirms the setup prerequisite on the assessment host.
It does not justify classifying every setup failure as a missing host feature.

Microsoft also requires `WHvArm64RegisterGicrBaseGpa` before each vCPU runs.
The [register contract](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvsetvirtualprocessorregisters) defines this requirement.
The current [ARM64 initialization](../pkg/sentry/platform/whpx/vcpu_arm64.go) omits that register.

The [Microsoft ARM64 sample](https://github.com/MicrosoftDocs/Virtualization-Documentation/blob/main/virtualization/api/hypervisor-platform/samples/WinHvSampleArm64.cpp)
demonstrates both initialization operations.
The runtime needs valid controller configuration even though Sentry does not boot a Linux kernel.

The [WHPX layout](../pkg/sentry/platform/whpx/layout.go) reserves GPA space from 1GiB through 64GiB for tables and guest memory.
Some addresses in the Microsoft sample fall inside that window.
The proposed controller layout uses dedicated regions below `gpaWindowBase`, with validated alignment and separate redistributors for all vCPUs.
The RAM allocator must never allocate those regions.

### CPU State and Feature Reporting

The [WHPX FP converter](../pkg/sentry/platform/whpx/fp.go) stores FPSR at byte 0, FPCR at byte 8, and vectors at byte 16.
The [HVF converter](../pkg/sentry/platform/hvf/vcpu_darwin_arm64.go) stores vectors first and reads control fields after byte 512.
The [systrap converter](../pkg/sentry/platform/systrap/hostctx_xplat_arm64.go) reads FPSR at byte 8 and FPCR at byte 12.

These differences require an explicit interpretation of the Sentry state format before code reuse.
The [ring0 assembly](../pkg/ring0/lib_arm64.s), signal code, and platform adapters supply separate reference points.
A converter round trip alone cannot prove compatibility when both directions repeat the same layout error.

The WHPX backend uses a 36-bit physical window and baseline CPU identification.
HVF derives its physical width and ID values from the hypervisor.
This difference requires validation against WHP capabilities and the guest auxiliary vector.

The shared ID decoder masks selected unsupported features.
The plan retains those masks until the runtime preserves their associated architectural state.
It requires consistent counter behavior, cache geometry, and feature reporting before enabling additional instructions.

### Fallback and Containment

The [automatic selector](../pkg/gvx/sandbox.go) falls back to systrap after hardware initialization errors.
`PlatformName` identifies the selected backend, and `FallbackReason` preserves the hardware error.
An explicit WHPX request returns its initialization failure.

The [Windows systrap design](systrap-windows.md) states that the engine does not filter every NT system call.
Restricted tokens and jobs constrain the stub, but instruction patching does not remove every executable NT syscall site.
WHPX acceptance must therefore use an explicit platform selection.

The architecture overview states a stronger general syscall isolation goal.
The systrap design records a narrower implemented boundary.
Support documentation needs backend-specific wording before it makes a common security claim.

## 5. Implementation Sequence (Procedural Module)

Use this sequence for future implementation changes.
Complete each acceptance gate before starting work that depends on it.

> [!IMPORTANT]
> Verify shared ARM64 changes on macOS before adding Windows bindings.
> Reserve controller regions outside RAM allocations before creating a WHPX partition.

1. Reproduce the current failures with explicit native WHPX tests.
2. Add ARM64 controller configuration before partition setup.
3. Configure the redistributor base for every vCPU.
4. Verify EL1 initialization and the first syscall round trip.
5. Verify CPU state and memory lifetime under cancellation.
6. Execute dynamic workloads and containment gates.
7. Record native evidence before changing support claims.

| Slice | Milestone and owner | Planned change | Acceptance gate | Dependency |
| :--- | :--- | :--- | :--- | :--- |
| A | M2; `whpx` | Add GICv3 property encoding, capability queries, reserved GPA regions, and per-vCPU redistributors. | Real lifecycle, syscall, fault, and interruption tests pass. | Reproducible native host |
| B | M2 and M3; `whpx`, `hvcommon` | Validate register ABI, FP transfer, feature reporting, counters, and EL1 controls. | Guest state survives syscalls, signals, clone, and vCPU reassignment. | A |
| C | M2; `whpx` | Verify root reload, cache invalidation, page permissions, and retirement ordering. | Concurrent mapping changes cannot expose stale or recycled pages. | A and B |
| D | M3; `pkg/gvx`, `e2e` | Resolve failures in static executables, dynamic loaders, networking, and JIT workloads. | Existing M2 and M3 gates pass through explicit WHPX. | B and C |
| E | M4 and M5; containment owners, `e2e` | Verify mounts, volumes, restricted execution, fallback reporting, and systrap compatibility. | Workloads pass with default containment; denied operations remain denied. | D |
| F | Verification; existing workflows and documentation | Add focused native evidence and distinguish backend coverage. | Five target builds pass; native results identify executed backends and skipped prerequisites. | A through E |

### Slice A: Partition and vCPU Initialization

Use the documented WHP contract for controller parameters.
Keep configuration and rollback inside the existing Windows backend.

1. Query the GIC LPI capability through `WHvGetCapability`.
2. Encode `WHV_ARM64_IC_PARAMETERS` with zeroed reserved fields.
3. Select `WHvArm64IcEmulationModeGicV3` before calling `WHvSetupPartition`.
4. Assign nonoverlapping distributor, translator, and redistributor regions outside the RAM allocator.
5. Set `WHvArm64RegisterGicrBaseGpa` before each vCPU executes.
6. Mask unused virtual timer and performance monitor interrupts before guest entry.
7. Delete partial resources after any initialization failure.
8. Execute the existing real-platform tests on native ARM64 Windows.

The [property reference](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvpartitionpropertydatatypes)
defines GIC fields, reserved fields, and the controller mode.
The [capability reference](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability)
defines `WHvCapabilityCodeGicLpiIntIdBits`.

### Slices B and C: State and Memory

Use guest-visible results to verify the state transfer contract.
Retain the current table allocator and communication protocol until a failing contract requires changes.

1. Compare register names, widths, layouts, and alignment with the ARM64 SDK definitions.
2. Execute guest programs with distinct values in every GPR and vector register.
3. Verify TLS, condition flags, FPCR, and FPSR across syscall returns and signal delivery.
4. Compare guest auxiliary vectors with trapped ID reads and executable feature probes.
5. Verify 4KB permissions within one 64KB host allocation.
6. Verify executable remapping and instruction cache invalidation.
7. Interrupt guests during EL0 execution, vector spilling, and state reload.
8. Release and recreate address spaces while other vCPUs execute mapping changes.
9. Verify cleanup after partial mappings and failed register writes.

### Slices D through F: Integration and Delivery

Reuse the existing OS-agnostic guest suites.
Keep host-specific primitive tests in Windows test files.

1. Execute the M2 BusyBox and fixed-address executable gates through WHPX.
2. Execute Alpine, Python, Node, and nginx gates with Linux ARM64 images.
3. Verify clone, futex, signals, TLS, and generated executable code.
4. Execute workspace, volume, rename, unlink, and mount isolation gates under default containment.
5. Verify NAT, port forwarding, DNS, and WireGuard behavior.
6. Verify explicit WHPX failure and automatic fallback reporting.
7. Execute systrap regressions after any shared ARM64 change.
8. Extend the existing ARM64 CI job with pure WHPX contract tests.
9. Execute hardware tests on a WHP-capable ARM64 host before release.
10. Update backend-specific support and containment descriptions.

## 6. Verification Gates (Reference Module)

The plan uses three distinct evidence levels: compilation, host component tests, and actual guest execution.
A skipped hardware test supplies no guest execution evidence.

| Gate | Existing starting point | Required assertion |
| :--- | :--- | :--- |
| Host primitives | `pkg/sync`, `pkg/memutil`, `pkg/fd`, `pgalloc`, embedded unix tests | Mapping aliases, waits, closure, and reclamation obey host contracts. |
| Real WHPX startup | `TestRealPlatformLifecycle` | Partition and vCPU creation succeed on ARM64. |
| Guest transition | `TestRealSyscallRoundTrip`, `TestRealPageFault`, `TestRealInterruptStopsALoop` | Syscalls, faults, and interruption reach Sentry with correct state. |
| State preservation | ARM64 switch and FP tests; guest programs | Signals and vCPU sharing preserve independent register values. |
| Memory isolation | Root, address-space, and native guest tests | Guests cannot access EL1 pages or retired user mappings. |
| Static compatibility | `TestE2EGateM2BusyboxAshInteractive`, `TestE2EGateETExec*` | Static and fixed-address ARM64 executables run through WHPX. |
| Dynamic compatibility | `TestE2EGateM3*` | Dynamic loaders, networking, TLS, and JIT code run through WHPX. |
| Containment | `TestE2EHostLockdown*`, `TestE2EGateM4*` | Bound resources remain usable; denied host operations fail. |
| Fallback regression | Windows systrap platform tests and `TestE2ESystrap*` | ARM64 fallback retains its existing behavior and reports its backend. |
| Upstream isolation | `tools/upstream` audit | Charged upstream files remain below 1.0%, with no other audit violations. |

The hosted ARM64 Windows runner can execute WHPX tests that use the scripted backend.
Hardware tests need a separate capable execution environment, rather than another hosted job with the same limitation.
Registry gates remain weekly or explicitly requested to preserve the current CI cost policy.

## 7. Verification Procedure (Procedural Module)

Run these commands from the repository root on native ARM64 Windows.
Use the Go version declared in `go.mod`.
Run registry-dependent gates with network access and a timeout appropriate to the workload.

1. Run the platform suite to distinguish pure contract failures from hardware failures.

```powershell
go test -count=1 -timeout 4m -v ./pkg/sentry/platform/whpx ./pkg/sentry/platform/hvcommon ./pkg/sentry/platform/systrap
```

2. Run the host primitive and integration suites.

```powershell
go test -count=1 -timeout 8m ./pkg/sync ./pkg/memutil ./pkg/fd ./pkg/sentry/pgalloc ./pkg/hostlockdown ./internal/xsys/unix ./pkg/gvx ./cmd/rungv ./e2e
```

3. Run the existing WHPX guest gates with an explicit backend selection.

```powershell
go test -count=1 -v -timeout 15m -run '^TestE2EGateM2BusyboxAshInteractive$' ./e2e
go test -count=1 -v -timeout 40m -run '^(TestE2EGateETExec.*|TestE2EGateM3(Alpine|NginxPortForward|PythonAlpine|NodeAlpine)|TestE2EGateM4(PosixTortureBusybox|GitWorkloads|NodeModulesTorture|MetaSurvivesSigkill|LockdownDefaultBlocksSubprocess))$/^whpx$' ./e2e
```

The M2 shell gate selects WHPX directly on Windows through `autoPlatform`.
Its subtests name input modes, so a `/whpx` filter would exclude its guest executions.

4. Inspect verbose results for skipped prerequisites before declaring any gate complete.
5. Run signed native tests on macOS ARM64 for shared changes.

```sh
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/sentry/platform/hvcommon ./pkg/sentry/platform/hvf ./pkg/gvx ./e2e
```

6. Compile every package for all five supported targets.
7. Run the upstream audit with a quoted numeric flag in PowerShell.

```powershell
go run ./tools/upstream '-mode=audit' '-max-ratio=0.01' '-offline'
```

8. Run the documentation audits from the repository's deslop skill.
9. Read the existing CI results after pushing implementation changes.

## 8. Assessment Evidence (Reference Module)

The assessment uses source inspection and native execution on Windows ARM64.
External API references reflect the Microsoft documentation inspected on 2026-10-31.
The results below describe this assessment only.

| Item | Result | Limit |
| :--- | :--- | :--- |
| Host | Windows 11 Home, build 28000; native ARM64 Go 1.27.3; hypervisor present | Capability detection alone cannot prove partition readiness. |
| WHPX platform suite | Four real-platform tests failed at `WHvSetupPartition` with HRESULT `0x80370304`. | No WHPX guest executed. |
| Isolated partition probe | Setup returned `0x80370304` without GIC parameters and `S_OK` with GICv3 parameters. | No vCPU or guest execution; runtime code remained unchanged. |
| Shared hardware logic | `pkg/sentry/platform/hvcommon` passed. | Pure Go tests do not verify WHP. |
| Windows systrap | The platform package passed. | This result does not establish a complete NT syscall boundary. |
| Host primitives | Sync, memutil, fd, pgalloc, hostlockdown, and embedded unix packages passed. | Focused native suites only. |
| Five target builds | `go build ./...` passed for Darwin ARM64, Windows AMD64/ARM64, and Linux AMD64/ARM64. | Compilation only; cgo disabled. |
| SDK and CLI | `TestSandboxReportsPlatformName` and `TestRunELFReportsAutoBackend` failed with the same setup HRESULT. | Hardware initialization blocks those tests. |
| Combined e2e suite | WHPX cases failed during initialization; the suite reached its eight-minute timeout during `TestE2ESystrapBusyboxPipeline`. | The active stack awaited an OCI registry response; the complete suite has no passing result. |
| Race detector | Go rejected `-race` on `windows/arm64`. | No native race evidence from this host. |
| Upstream audit | Charged share: 18/2507 files, 0.72%; audit failed with 1427 findings. | Formatting and Linux-file findings prevent a clean audit result. |
| Documentation audits | Typography, banned vocabulary, and rhetorical scans returned zero matches across README, AGENTS, and docs. | Mechanical writing rules only. |

The temporary P/Invoke probe created two partitions with one processor and hypercall exits enabled.
Only the second partition received GIC parameters before setup; the probe deleted both partitions.
The capability query returned one LPI identifier bit.

| Probe parameter | Value |
| :--- | :--- |
| Controller mode | GICv3 |
| Distributor GPA | `0x08000000` |
| ITS translator GPA | `0x08080000` |
| LPI identifier bits | Capability result: `1` |
| Virtual timer PPI | `27` |
| Performance monitor PPI | `23` |

The checkout uses `core.autocrlf=true`.
Line-ending differences are a candidate explanation for the formatting findings, but this assessment did not establish their complete cause.
The proposed document adds no upstream Go or assembly edits.

### Not verified

This host cannot execute macOS HVF or signed macOS tests.
Windows AMD64 and both Linux targets received compilation evidence only.
The assessment does not prove that GIC configuration alone resolves every WHPX ARM64 failure.
Native WHPX workloads, FP correctness across backends, and release acceptance remain open until their gates pass.
The combined e2e timeout does not establish a systrap guest execution defect.
