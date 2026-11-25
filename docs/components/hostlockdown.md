# Pre-Execution Host Self-Lockdown: `pkg/hostlockdown`

This specification describes `pkg/hostlockdown`, the third ring of `gvx`'s defense-in-depth architecture. Before a sandbox executes its first guest instruction, `hostlockdown.Apply()` seals the host process using OS-native confinement primitives so that even a hypothetical Sentry vulnerability cannot spawn host processes, read or write unbound host files, or open unauthorized sockets.

---

## 1. Purpose and Scope

`gvx` enforces three concentric security boundaries:

| Ring | Owning Packages | Enforced Invariant |
| :--- | :--- | :--- |
| **Ring 1: Execution Boundary** | `platform/whpx`, `platform/hvf`, `platform/systrap` | Confines guest machine code inside 4 KiB hardware page tables (`whpx`, `hvf`) or a `seccomp`-trapped Linux `systrap` stub. Untrusted Windows workloads require `whpx`. |
| **Ring 2: Application Kernel** | `pkg/sentry/kernel`, `hostfs`, `ext4lite`, `pkg/netbackend` | Serves ~250 Linux system calls in memory-safe Go, scopes workspace I/O to `os.Root`, and confines each volume to one pre-opened file. |
| **Ring 3: Host OS Containment** | `pkg/hostlockdown` | Strips host privileges and blocks process creation, unbound file opens, and unauthorized sockets inside the host OS kernel before guest entry. |

![Host Self-Lockdown State Transition](../assets/host-lockdown.svg)

---

## 2. Design and Pre-Lockdown Ordering

> [!CAUTION]
> Open every required host resource before calling `hostlockdown.Apply()`. This includes the hypervisor partition or `systrap` stub host, all `.erofs` layer handles, `.ext4` volume handles, `os.Root` workspace handles, `.gvx_meta.lock`, host CA roots, host DNS configuration, `-p` listeners, `-control-socket`, `-checkpoint-dir`, and the `-net=wg` UDP socket. Once `Apply()` returns, the host OS kernel rejects new process spawns and unbound file opens.

### 2.1 Windows (`lockdown_windows.go`, `broker_windows.go`, `netbroker_windows.go`)

Windows applies `RestrictedSids` on thread impersonation tokens because `CreateProcessAsUser` cannot swap a running process's primary token. To defend against an attacker dropping thread impersonation (`SetThreadToken(nil, 0)`), `lockdown_windows.go` lowers the primary token itself to Untrusted integrity (`S-1-16-0`):

1. Update `TokenDefaultDacl` on the primary token so unnamed kernel objects admit `NULL_SID`.
2. Pin mounted directory and single-file handles in memory without modifying any host NTFS ACL or integrity label.
3. Strip all privileges from the primary token (`AdjustTokenPrivileges` with `SE_PRIVILEGE_REMOVED`).
4. Start locked OS broker threads (`winMountBroker` and thread sweeper) before lowering the primary token.
5. Start the locked Low-integrity `winNetBroker` worker pool when `-net=nat` or `--auto-publish` is active.
6. Verify containment with an Untrusted restricted token containing `NULL_SID`.
7. Assign the process to a Job Object with `JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1` and `JOB_OBJECT_UILIMIT_ALL`.
8. Call `SetProcessMitigationPolicy` (`DisallowWin32kSystemCalls = 1`) to block `win32kfull.sys`.
9. Lower the primary token to Untrusted integrity after binding pre-warmed Go runtime threads to the restricted token.
10. Activate the background thread sweeper so newly created Go OS threads inherit the restricted token.

### 2.2 macOS (`lockdown_darwin.go`)

1. Pin `GOMAXPROCS` so Seatbelt denials on CPU `sysctl` queries cannot collapse runtime parallelism.
2. Call `setrlimit(RLIMIT_NPROC, {0, 0})` to reject `fork()` at the XNU kernel boundary.
3. Apply a `deny default` Seatbelt SBPL profile (`sandbox_init_with_parameters`) denying `process-fork`, `process-exec*`, unbound `file-*` operations, and unauthorized binds (admitting explicit mount paths, resolved targets, and `localhost:*` only when `--auto-publish` or `--dynamic-ports` is enabled).
4. Execute denial self-probes for process creation, unbound files, and unbound sockets; fail initialization if any probe succeeds.

### 2.3 Linux and Android (`landlock_linux.go`, `lockdown_linux.go`, `pkg/gvx/syscallfilter_linux.go`)

Because `pkg/hostlockdown` may not import Sentry packages, `pkg/gvx` compiles the `seccomp-bpf` allowlist (based on `runsc/boot/filter/config`) and passes it via `Options.InstallSyscallFilter`:

1. Create a Landlock filesystem ruleset scoped to `Options.Mounts` (masked to the running kernel's Landlock ABI v1 through v5) and restrict all process threads before seccomp blocks Landlock syscalls.
2. Build `config.Rules` for `systrap`, the chosen network mode, and host mounts; merge embedder rules (`fcntl`, `sched_getaffinity`, `renameat`, `openat2`, `flock`, loopback binds when `--auto-publish` or `--dynamic-ports` is set, and cgo thread calls).
3. Append `EPERM` fallback rules for `execve`, `execveat`, `clone`, `openat`, and `socket` so callers in an embedding Go process receive Go errors rather than `SIGSYS` termination.
4. Install the seccomp program across all threads with `SECCOMP_FILTER_FLAG_TSYNC` and run containment probes.

In cgo Linux builds, threads unregister their `rseq` area across `fork` (`rseq_xplat.go`) so child stubs do not fault when unmapping inherited memory. On Android, `pkg/hostlockdown` detects Zygote's existing `untrusted_app` seccomp filter (`PR_GET_SECCOMP == 2`), skips Landlock calls that Zygote traps with `SIGSYS`, and relies on Android's per-UID SELinux domain and mount namespace.

---

## 3. Known Limits

- **Windows primary-token revert**: Host code inside a compromised Sentry could call `SetThreadToken(nil, 0)` to drop its thread restricted SIDs, reverting to the Untrusted primary token (which still blocks raw sockets, `NO_READ_UP` reads, and Low/Medium writes).
- **Linux seccomp socket addresses**: `seccomp-bpf` cannot inspect `sockaddr` pointers in memory, so Linux cannot pin a WireGuard peer UDP port at the syscall filter layer the way macOS Seatbelt does.
- **Android host mounts**: Because Zygote blocks Landlock, `Status.UnboundFileOpenBlocked` stays false on Android whenever a host bind mount is attached; sandboxes using only `ext4lite` volumes keep `UnboundFileOpenBlocked` true.
- **Opt-out flag**: `-lockdown=false` disables confinement for debugging and emits a stderr warning.

---

## 4. Implementation Map

| Files | Role |
| :--- | :--- |
| `pkg/hostlockdown/lockdown.go`, `mountpaths.go`, `dial*.go`, `bind_other.go` | Shared `Options`, `Status`, mount path normalization, broker dispatch wrappers. |
| `pkg/hostlockdown/lockdown_windows.go`, `token_windows.go`, `job_windows.go`, `broker_windows.go`, `netbroker_windows.go`, `workspace_windows.go`, `probe_windows.go` | Windows Untrusted/Restricted token setup, Job Object, Win32k block, file and socket brokers, containment probes. |
| `pkg/hostlockdown/lockdown_darwin.go`, `lockdown_darwin_*.s`, `extension_darwin.go`, `probe_darwin.go` | macOS Seatbelt SBPL generator, `sandbox_init` assembly trampolines, file-extension tokens, probes. |
| `pkg/hostlockdown/lockdown_linux.go`, `landlock*_linux.go`, `pkg/gvx/syscallfilter_linux.go` | Linux Landlock ABI v1-v5 rulesets, `seccomp-bpf` allowlist construction, `scripts/seccomp-audit.sh`. |
| Tests | `pkg/hostlockdown/*_test.go`, `e2e/gate_m4_test.go`, `e2e/sandbox_e2e_test.go` (`TestE2EHostLockdown*`), `e2e/checkpoint_e2e_test.go`. |
