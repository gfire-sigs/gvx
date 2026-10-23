# Windows ARM64 Runtime Comparison

This benchmark compares confined Windows `systrap` and WHPX with an existing Debian distribution on WSL2.
Both runtimes execute the same static Linux ARM64 Go binary.
The driver preserves running WSL distributions and Docker workloads.

## Measured Systrap Results

The measurements used a Lenovo 83HL with a Snapdragon X Plus X1P42100 and eight logical processors.
The host ran Windows 11 Home build 26300 with 31.57 GiB RAM and the Balanced power plan.
Debian used Linux `6.6.87.2-microsoft-standard-WSL2`; Docker distributions remained active.
Go 1.27.3 built the workload and the runtime from production revision `bb58dce`, with benchmark additions.

| Metric | Confined gvx systrap | Existing WSL2 | Repetitions |
| :--- | ---: | ---: | ---: |
| Command startup, median | 796 ms | 143 ms | 30 each |
| Command startup, p95 | 843 ms | 150 ms | 30 each |
| Integer loop, median | 199 ms | 193 ms | 7 each |
| 10,000 `getpid` calls, median | 470 ms | 1.81 ms | 7 each |
| HTTP requests per second, median | 1,012 | 11,393 | 3 each |
| HTTP request latency, median | 0.958 ms | 0.291 ms | 6,000 requests each |
| HTTP request latency, p95 | 27.7 ms | 0.515 ms | 6,000 requests each |
| HTTP errors | 0 | 0 | 6,000 requests each |

The [recorded samples](../tools/bench/results/windows-arm64-20261023.json) include distributions, workload hashes, and the environment.
Startup and compute runs alternate runtime order.
Idle runs observe WSL first and gvx second at each instance count.
HTTP runs alternate runtime order and include twenty warm-up requests before each timed run.

| Idle instances | gvx private commit | Windows host physical increase with gvx | Windows host physical increase with WSL |
| ---: | ---: | ---: | ---: |
| 1 | 144 MiB | 29 MiB (8 to 186) | -29 MiB (-154 to 96) |
| 4 | 580 MiB | 294 MiB (288 to 432) | 22 MiB (-17 to 45) |
| 16 | 2,316 MiB | 1,023 MiB (962 to 1,142) | 246 MiB (228 to 402) |

Each physical increase uses the median across observation samples; parentheses show the observed range.
Private commit includes the broker, Sentry, guest stubs, and console hosts.
Private commit measures committed private memory, not resident physical RAM.
One gvx sandbox used twelve Windows processes and about 0.31 CPU seconds over sixty idle seconds.

Background activity and WSL reclamation changed total physical memory during the measurements.
Negative physical increases show this interference, so the single-instance observation does not establish the incremental RAM cost.
The existing WSL VM used about 735 MiB before the first idle run, including existing Debian and Docker workloads.
These measurements do not support a general claim that Windows systrap uses fewer resources than WSL2.

## Measured WHPX Results

The WHPX run reused both executable files from the systrap run; their SHA-256 hashes match.
The driver repeated the WSL baseline while Debian and Docker continued to run.
The [WHPX samples](../tools/bench/results/windows-arm64-whpx-20261023.json) record the confined run and a separate diagnostic without lockdown.
The hardware, workload, repetition counts, and power plan match the systrap comparison.

| Metric | Confined gvx WHPX | Existing WSL2 |
| :--- | ---: | ---: |
| Command startup, median | 972 ms | 145 ms |
| Command startup, p95 | 1,078 ms | 169 ms |
| Integer loop, median | 201 ms | 192 ms |
| 10,000 `getpid` calls, median | 1,175 ms | 1.83 ms |
| HTTP requests per second, median | 389 | 12,582 |
| HTTP request latency, median | 2.41 ms | 0.269 ms |
| HTTP request latency, p95 | 58.8 ms | 0.463 ms |
| HTTP errors | 0 | 0 |

| Idle instances | WHPX private commit | Windows host physical increase with WHPX | Windows host physical increase with WSL |
| ---: | ---: | ---: | ---: |
| 1 | 132 MiB | 9 MiB (-46 to 77) | 18 MiB (-26 to 126) |
| 4 | 524 MiB | 240 MiB (234 to 266) | 181 MiB (11 to 233) |
| 16 | 2,092 MiB | 1,161 MiB (1,112 to 1,180) | 180 MiB (164 to 241) |

One WHPX sandbox used four Windows processes and about 0.16 CPU seconds over sixty idle seconds.
The physical memory observations retain the background interference described below.
Private commit excludes shared mappings and resources that Windows charges outside these processes.

The diagnostic disabled lockdown only for the generated workload and repeated each compute measurement seven times.
Its median was 240 ms for 10,000 `getpid` calls, versus 1,175 ms with confinement.
The integer loop took 193 ms without confinement and 201 ms with confinement.
Removing confinement also removes the broker, so this diagnostic does not isolate every source of overhead.

The [WHPX broker](../pkg/sentry/platform/whpx/broker_windows.go) uses RPC for each run and each register operation.
The diagnostic indicates substantial overhead in the confined path and warrants profiling of those RPC calls.
It does not establish a performance advantage over WSL2 or an equivalent isolation boundary without lockdown.

## Measurement Boundary

The benchmark targets the M2 WHPX path and the M5 systrap path through `cmd/rungv`.
The workload belongs to `internal/benchguest`; the Windows driver belongs to `tools/bench`.
Neither component changes the Sentry or its platform bindings.

| Workload | Measured boundary | Validation |
| :--- | :--- | :--- |
| Startup | Windows command invocation through successful exit, after one warm-up per runtime | Exact JSON output and ARM64 architecture |
| CPU | 100 million dependent integer iterations inside the guest | Equal checksums across runtimes |
| Syscall | 10,000 direct Linux `getpid` calls inside the guest | Successful, positive results |
| Idle | One guest for 60 seconds; four and sixteen guests for ten seconds each | Explicit readiness and successful exit |
| HTTP | 2,000 requests per run, four clients, 1,024-byte responses, three runs | Status 200 and exact response bytes |

Startup includes sandbox initialization, image conversion, AppContainer creation, partition creation for WHPX, and shutdown.
It excludes compilation, registry access, and the initial warm-up.
WSL commands use `wsl.exe --exec` and a private directory on the Linux filesystem.
The driver verifies the installed binary with SHA-256.
The guest sets `GOMAXPROCS=1` for each workload.

The HTTP driver uses Windows loopback connections and persistent HTTP connections.
The gvx path includes `-net=nat -p`; the WSL path includes its existing localhost forwarding.
The resulting rates describe this client workload and both forwarding paths.
They do not measure maximum server capacity.

## Memory Interpretation

The driver records physical availability and total commit on the Windows host.
Background applications can change both values during each observation.
The driver also records private commit and working sets for every descendant of each owned Windows command.
Shared pages can appear in multiple working sets, so their sum does not measure unique physical RAM.

The driver records the existing WSL VM through CIM before and after each idle workload.
`WorkingSetSize` uses bytes; `PageFileUsage` uses KiB.
These counters include existing Debian and Docker workloads.
The driver reports denied access to VM counters instead of substituting zero.
WSL launcher counters describe Windows launchers, not guest processes inside Linux.

## Reproduction

Run the driver from a native Windows ARM64 host with Go, Python 3.11 or newer, and an installed WSL2 distribution.
Select an output directory that does not exist.
The driver builds both binaries and writes raw samples to `results.json` and aggregate values to `summary.json`.
The driver removes only its own temporary Linux executable and directory.

```powershell
$systrapRun = Join-Path $env:TEMP ("gvx-systrap-" + [guid]::NewGuid().ToString("N"))
python tools/bench/compare_windows.py --backend systrap --distribution Debian --output $systrapRun
$whpxRun = Join-Path $env:TEMP ("gvx-whpx-" + [guid]::NewGuid().ToString("N"))
python tools/bench/compare_windows.py --backend whpx --distribution Debian --binary-dir $systrapRun --output $whpxRun
```

Repeat only the compute diagnostic without lockdown:

> [!CAUTION]
> Disable lockdown only for the generated benchmark binary.
> This diagnostic removes the normal host containment.

```powershell
$directRun = Join-Path $env:TEMP ("gvx-whpx-direct-" + [guid]::NewGuid().ToString("N"))
python tools/bench/compare_windows.py --backend whpx --no-lockdown --binary-dir $systrapRun --phases compute --samples 7 --output $directRun
```

## Not verified

This comparison excludes WSL VM startup and shutdown.
It does not measure Docker container isolation, OCI image pulls, disk workloads, power consumption, or macOS performance.
Direct WSL execution and a confined gvx sandbox provide different isolation boundaries.
