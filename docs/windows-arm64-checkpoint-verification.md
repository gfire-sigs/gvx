# Windows ARM64 Checkpoint Verification

This report records native verification on 16 November 2026 against commit `a9bfd06c` and the backing-memory lifetime correction.
The correction fixes a resource-order defect, but the host still crashes during restored guest execution.

## Observed Execution (Descriptive Module)

The host runs Windows 11 ARM64 build `28000` on an ASUS Zenbook A16.
Both host crashes produced bugcheck `0x00020001`, which Microsoft names [HYPERVISOR_ERROR](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x20001--hypervisor-error).

| Evidence | Result | Limit |
| :--- | :--- | :--- |
| Initial platform suites | WHPX, systrap, and hvcommon passed | These suites did not prove checkpoint interoperability. |
| Initial buffered log | Last record started the systrap memory subtest at `21:43:18` KST | The log omitted later execution. |
| Initial surviving manifest | The WHPX ext4lite subtest wrote its manifest at `21:43:56` KST | The suite advanced beyond that last log record. |
| Corrected lifetime regression | The original ordering failed; the correction passed all four cases | The regression uses a real memory file and a platform double. |
| Corrected native rerun | The WHPX memory subtest saved state and closed its original sandbox | The correction did not remove the host crash. |
| Corrected restore | `gvx.Restore` returned at `22:09:12.644` KST | The subsequent `Run` did not return before the host crashed. |

The rerun synchronized each output record to disk before it continued reading.
Its last completed stage was `checkpoint: restored sandbox opened`.
No systrap subtest ran during that rerun.
The new crash dump is `111626-17000-01.dmp`; the current account cannot read it.

## Backing-Memory Lifetime (Descriptive Module)

The original kernel runners deferred `MemoryFile.Destroy` until `Run` returned.
WHPX retained persistent GPA mappings until the later platform closure, so memory destruction could precede hypervisor teardown.

The correction transfers consumed memory into `Sandbox.runMemFile` and preserves the existing refusal of a second `Run`.
`Sandbox.Close` closes the platform before mounts, layer descriptors, and backing memory.
A failed platform closure preserves those resources and returns the same error on repeated closure.
The invariant requires host backing memory to outlive every platform mapping that references it.

| Caller | Corrected ownership |
| :--- | :--- |
| `runWithKernel` | Transfers the pending file into `runMemFile`; `Close` destroys it after platform closure. |
| `runRestoredKernel` | Uses the same transfer for restored memory. |
| Constructor or restore failure | `Close` retains pending memory until platform closure. |
| Platform closure failure | `Close` retains backing resources instead of recycling potentially mapped pages. |

The regression uses `testing/synctest` to complete asynchronous destruction before the platform double inspects the backing file.
It covers pending and consumed memory, successful and failed platform closure, and repeated closure.

## Remaining Review Findings (Descriptive Module)

The lifetime correction has an independent review with no blocking finding.
The review identified additional defects that this correction does not address.

| Finding | Evidence | Assessment |
| :--- | :--- | :--- |
| ARM64 FP layout mismatch | `whpx/fp.go` uses offsets `0, 8, 16`; `arch/fpsimd_layout_xplat.go` defines `0, 4, 8`. | WHPX and the shared Sentry image disagree on control and vector fields. Existing local round-trip fixtures repeat the WHPX layout. |
| Shared HVF memory lifetime | `releaseVM` returns while another platform references the shared VM. Persistent regions can remain. | The corrected SDK order does not resolve that existing multi-sandbox case. |
| Concurrent `Run` and `Close` | `Close` does not coordinate the full active execution interval. | This change does not add concurrent-close support. |

The FP mismatch is a source-level interoperability defect, not a confirmed explanation for either host crash.
WHPX can preserve its own incorrect layout across a raw checkpoint round trip.
Further native reproduction requires a separate decision after offline register and mapping analysis.

## Verification Status (Reference Module)

Native guest verification remains unsuccessful because the corrected rerun crashed the host.
Build success and deterministic lifetime tests do not establish successful restored execution.

| Verification | Result |
| :--- | :--- |
| Original lifetime regression | Failed with an invalid backing-file handle before platform closure. |
| Corrected lifetime regression | Passed pending and consumed cases, including platform closure failure. |
| Native `go vet` for `pkg/gvx` and `e2e` | Passed. |
| Generated state files | Verified 53 files across 44 packages without drift. |
| Upstream audit with LF files | Passed: 106 of 2,551 files, or 4.16%, below the 4.20% CI gate. |
| Native checkpoint rerun | Host crash during `TestE2ECheckpointRestoreMemoryState/whpx`, after `Restore` returned. |
| Native macOS guests | Not executed on this Windows host. |

The durable local evidence directory is `%LOCALAPPDATA%\gvx\diagnostics\20261116-2144`.
It contains the synchronized rerun log, both phase inventories, the patch snapshot, and the second crash events.

The Windows checkout uses CRLF, which produces unrelated formatting findings in the raw upstream audit.
An isolated snapshot with LF files passed the audit without changing the checkout.
The first post-crash build encountered a Go linker panic in the existing cache.
A separate cache rebuilt the native Windows target successfully; this result does not identify the cache failure's cause.
