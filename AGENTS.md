# Agent Operating Manual (`AGENTS.md`)

This manual defines the startup protocol, subsystem boundaries, upstream sync rules, and **ASD-STE100** writing gates for the `gvx` repository. `gvx` targets both Windows (`windows/amd64`, `windows/arm64`) and macOS (`darwin/arm64`, `darwin/amd64`) as co-equal Priority-0 platforms. It also supports Linux (`linux/amd64`, `linux/arm64`) officially. CI verifies every platform.

> [!IMPORTANT]
> Read [`docs/architecture.md`](docs/architecture.md) first at the start of every session before planning, writing code, or reviewing changes. Identify the target milestone (`M1` through `M5`) and verify the owning package boundary in [`docs/architecture.md`](docs/architecture.md) before modifying any file.

---

## 1. Mandatory Startup Protocol (Procedural Module)

Execute these numbered steps at the start of every task before editing repository files.

1. Read [`docs/architecture.md`](docs/architecture.md) to verify the subsystem architecture, syscall contracts, and milestone boundaries.
2. Inspect the target package and its build constraints (`//go:build windows`, `//go:build darwin`, `//go:build linux`, and `amd64`/`arm64` files).
3. Activate the matching engineering skills under `.agents/skills/` from the routing table below.
4. Implement and verify `darwin/arm64` code paths natively first in each milestone before adding `windows/{amd64,arm64}` and `darwin/amd64` bindings. Run the new code on `windows/amd64` through CI as soon as it builds.
5. Verify that the planned diff touches less than 5.0% of upstream gVisor files outside `_windows.go` and `_darwin.go` packages.

| Task Category | Required Skill (`.agents/skills/`) | Scope of Enforcement |
| :--- | :--- | :--- |
| **Umbrella Engineering** | [`just-good-practices`](.agents/skills/just-good-practices/SKILL.md) | Incremental implementation, guard clauses, and boundary error translation. |
| **Go Implementation** | [`go-practices`](.agents/skills/go-practices/SKILL.md) | Go 1.25+ standard library usage, context ordering, and `%w` / `errors.Join` (`gojgp` lint disabled). |
| **API & Signatures** | [`api-design`](.agents/skills/api-design/SKILL.md) | Explicit resource ownership, typed options, and constructor dependency injection. |
| **Code Health** | [`code-health`](.agents/skills/code-health/SKILL.md) | Shallow control flow, domain naming, and separation of pure logic from I/O. |
| **Testing** | [`testing-practices`](.agents/skills/testing-practices/SKILL.md) | Hermetic fixtures, `testing/synctest`, and behavioral boundary assertions. |
| **ASD-STE100 & Anti-Slop** | [`deslop`](.agents/skills/deslop/SKILL.md) & [`zero-slop`](.agents/skills/zero-slop/SKILL.md) | ASD-STE100 controlled English, S1000D modules, zero em-dashes, and behavioral tests. |
| **Diff & PR Review** | [`code-review`](.agents/skills/code-review/SKILL.md) | Atomic commits, risk classification, and evidence-backed verification reports. |

---

## 2. Layered Subsystem Map and Upstream Sync Rules (Descriptive Module)

`gvx` tracks the `go` branch of `https://github.com/google/gvisor.git` (`upstream/go`) and pins the synced upstream commit SHA in `UPSTREAM_COMMIT`. Keep Windows and macOS host bindings separated from the pure-Go Sentry kernel across three isolation tiers.

| Isolation Tier | Packages and Files | Architectural Rule |
| :--- | :--- | :--- |
| **Tier 1: Additive Packages** | `cmd/rungv`, `pkg/gvx`, `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `pkg/sentry/platform/whpx`, `pkg/sentry/platform/hvf`, `pkg/sentry/fsimpl/hostfs`, `e2e`, `tools/upstream`, `docs/` | Owned exclusively by `gvx`; never present in `upstream/go` (`0.0%` merge conflict rate). |
| **Tier 2: Sibling `_windows`, `_darwin`, & `_xplat` Files** | `pkg/sync/*_{windows,darwin}.go`, `pkg/memutil/*_{windows,darwin}.go`, `pkg/fd/*_{windows,darwin}.go`, `pkg/sentry/{pgalloc,time,hostcpu}/*_{windows,darwin}.go`, `pkg/sentry/platform/systrap/*_{windows,darwin,xplat}*` | Place alongside unmodified `*_linux.go` files so `git merge upstream/go` never conflicts. |
| **Tier 3: Build-Tag & Seam Patches** | Pure-Go files in `pkg/sentry/kernel`, `pkg/sentry/arch`, `pkg/ring0`, `pkg/sentry/vfs`, `pkg/sentry/fsimpl/{erofs,tmpfs,overlay}`, `pkg/tcpip` | Register every build-tag change (`linux \|\| windows \|\| darwin`) in `tools/upstream/buildtag_allowlist.txt`; keep modified upstream files below `5.0%`. |

---

## 3. Resource Ownership and Concurrency Invariants (Descriptive Module)

Every subsystem that allocates host kernel handles, virtual memory arenas, or CPU register state must satisfy these ownership rules.

### 3.1 Memory and Address Space Ownership

`pgalloc.MemoryFile` owns the backing shared memory created via `CreateFileMappingW` and `MapViewOfFile3` on Windows or `mmap(MAP_ANON)` and `mach_vm_remap` on macOS. `platform/whpx` (`WHvMapGpaRange`) and `platform/hvf` (`hv_vm_map`) map 4KB slices from `MemoryFile` into guest physical memory; `AddressSpace.Unmap()` unmaps GPA ranges before `MemoryFile` releases the backing pages.

`platform/systrap` on macOS `arm64` (`darwinsystrap`) owns the guest virtual arena (`[guestArenaBase, guestArenaEnd)`), shared `sysmsg` context pages, and 4KB Trampoline Islands. It disassembles executable pages on lazy execute faults using `golang.org/x/arch/arm64/arm64asm` to patch `svc #0` (`0xD4000001`) instructions in-place. The fault handler (Mach exception port and signal handler) inspects the faulting address first. It defers to the Go runtime for any fault outside `[guestArenaBase, guestArenaEnd)`.

`platform/systrap` on Windows (`winsystrap`) owns one stub process for each address space and one debug object for all stubs. A stub host that starts before `hostlockdown.Apply()` creates the stubs. The engine replaces `syscall` with `CC 90` on `amd64` and `svc #0` with `brk` on `arm64`, and it receives every stop through the debug object. Read [`docs/systrap-windows.md`](docs/systrap-windows.md) before you change it. Set `GVX_SYSTRAP_TRACE=1` to print each stop.

### 3.2 Host Handle and Lockdown Ordering

> [!CAUTION]
> Do not spawn child processes, open unbound host paths, or call `win32k` APIs after `hostlockdown.Apply()` returns. Windows Job Objects (`JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 1`) and macOS Seatbelt (`sandbox_init` with `deny process-fork` and `deny file-*`) reject or terminate violating calls immediately. Open all host handles (`whpx`/`hvf` VM, pre-spawned `systrap` stub subprocess and `sysmsg` shared memory, cached `.erofs` layers, `/workspace` `os.Root`, `-p` host listeners, and the `-net=wg` UDP socket) before calling `hostlockdown.Apply()`.

`pkg/fd.HostHandle` wraps every Windows `syscall.Handle` and macOS file descriptor with explicit `Close()` ownership. `pkg/oci` compiles multi-arch (`amd64`/`arm64`) OCI `.tar` layers in memory into cached `<sha256>.erofs` files without extracting files onto NTFS or APFS. `pkg/netbackend` routes `pkg/tcpip` traffic through either L4 Go `net` NAT and `-p` port forwarders (`-net=nat`) or an L3 in-memory `wireguard-go` tunnel (`-net=wg`). `pkg/sentry/fsimpl/hostfs` opens all workspace files relative to the pinned `os.Root` handle (`NtCreateFile` on Windows; `openat` on macOS). It enforces `FILE_OPEN_REPARSE_POINT` or `O_NOFOLLOW` and persists POSIX metadata to `.gvx_meta`.

---

## 4. Mandatory ASD-STE100 Documentation and Zero-Slop Standard

All documentation (`README.md`, `AGENTS.md`, `docs/*.md`), code comments, and commit messages must obey **ASD-STE100**, **S1000D**, **ATA iSpec 2200**, and **MIL-STD-38784**. Write all documentation, code comments, and commit messages in English. Refer to [`.agents/skills/deslop/SKILL.md`](.agents/skills/deslop/SKILL.md) for the complete lexicon and formatting rules.

| ASD-STE100 / Deslop Rule | Mandatory Quantitative Constraint |
| :--- | :--- |
| **Procedural Sentence Length** | Maximum **20 words per sentence**; maximum **1 instruction per sentence**; start with an **imperative verb** (`Run`, `Call`, `Open`, `Set`, `Verify`). |
| **Descriptive Sentence Length** | Maximum **25 words per sentence**; maximum **6 sentences per paragraph**; write in **active voice** only. |
| **Compound Noun Clusters** | Maximum **3 consecutive nouns**; unpack 4+ noun chains using prepositions (`for`, `in`, `of`, `on`) or hyphenated two-word modifiers. |
| **One Word, One Meaning** | Use exact mechanical verbs (`parse`, `validate`, `dispatch`, `allocate`, `verify`, `obey`); never use vague `handle`, `manage`, `process`, or `check`. |
| **Zero Em-Dashes & Arrows** | Never output `U+2014`, spaced `U+2013`, double hyphens, or prose arrows (`U+2192`). Use `:`, `;`, `()`, `.`, or `,`. |
| **Zero AI-Slop Vocabulary** | Never output any banned AI marketing words or throat-clearing prefaces listed in Section 4 of [`.agents/skills/deslop/SKILL.md`](.agents/skills/deslop/SKILL.md). |
| **S1000D Module Separation** | Separate Descriptive, Procedural, and Reference modules; never mix conceptual theory and numbered CLI steps in one block. |
| **Pre-Procedure Safety Alerts** | Place `> [!CAUTION]`, `> [!WARNING]`, and `> [!IMPORTANT]` **immediately before** the procedure or code block they govern (`<= 3` controlled sentences). |
| **Universal Heading Rule** | Never place two headings back-to-back without a 2-to-4 sentence scope lead or summary table. |
| **English Only** | Write every code comment, documentation file, and commit message in English. Apply every rule in this table to that English text; never use Korean or another language. |

---

## 5. Build, Audit, and Verification Procedure (Procedural Module)

Keep `e2e/` black-box tests 100% OS-agnostic across Windows and macOS (`pkg/gvx` and `cmd/rungv`), and isolate OS-specific unit tests to `*_darwin_test.go` and `*_windows_test.go`. Do not run `gojgp` lint on this repository; `gojgp` lint is disabled due to upstream gVisor code patterns. Run these commands before completing any code or documentation task.

> [!IMPORTANT]
> Run `go test` through `scripts/codesign-exec.sh` on macOS. An unsigned test binary cannot verify TLS certificates. It skips the network image tests without a failure.

1. Format source files and run native unit and `e2e/` tests on `darwin/arm64` with `scripts/codesign-exec.sh`.
2. Cross-compile all packages across the four Priority-0 targets (`darwin/arm64`, `darwin/amd64`, `windows/amd64`, `windows/arm64`) and both Linux targets (`linux/amd64`, `linux/arm64`).
3. Run the upstream diff audit tool to verify that modified upstream files remain below 5.0%.
4. Execute the mechanical `ripgrep` checks from Section 9.2 of [`.agents/skills/deslop/SKILL.md`](.agents/skills/deslop/SKILL.md) against `README.md`, `AGENTS.md`, and `docs/`.
5. Push the change and read the CI result. CI runs the tests that the local host cannot run.

```bash
# 1. Format and test natively on the active host (darwin/arm64 first; gojgp lint is disabled)
go fmt ./...
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./...

# 2. Compile check across the four Priority-0 targets and both Linux targets
GOOS=darwin  GOARCH=arm64 go build ./...
GOOS=darwin  GOARCH=amd64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=windows GOARCH=arm64 go build ./...
GOOS=linux   GOARCH=amd64 go build ./...
GOOS=linux   GOARCH=arm64 go build ./...

# 3. Verify upstream diff budget (< 5.0% touched upstream files)
go run ./tools/upstream -mode=audit -max-ratio=0.05

# 4. Verify zero em-dashes, spaced en-dashes, or prose arrows in documentation (must return 0 matches)
rg -n "\x{2014}| \x{2013} |\x{2192}" README.md AGENTS.md docs/ 2>/dev/null
```

### 5.1 Continuous Integration (Descriptive Module)

The workflow `.github/workflows/ci.yml` builds and vets all six targets, audits the upstream diff, and tests `linux/amd64`, `linux/arm64`, `darwin/arm64`, `windows/amd64`, and `windows/arm64`. A hosted macOS runner and the hosted `windows-11-arm` runner are virtual machines without a hypervisor, so they run the `systrap` suites. The workflow `.github/workflows/e2e-images.yml` pulls real images once a week. The workflow `.github/workflows/diagnose.yml` runs a chosen test selection on a chosen runner by hand. On Linux, run `scripts/seccomp-audit.sh` when a change adds a host call, because a call outside the seccomp allowlist kills the process.

Keep CI usage low. Do not add jobs that repeat work, and do not run registry tests on every push. Use these environment variables in CI only:

| Variable | Effect |
| :--- | :--- |
| `GVX_ALLOW_NO_HYPERVISOR=1` | Skips the tests that need a hypervisor when `hv_vm_create` or `WHvCreatePartition` fails. |
| `GVX_E2E_OFFLINE=1` | Skips the tests that pull from a registry. |
| `GVX_E2E_REQUIRE_NETWORK=1` | Fails, and does not skip, when the registry is unreachable. |
| `GVX_DEBUG_LOG=1` | Prints the Sentry log, which names the reason of a guest crash. The value `2` also prints debug lines, such as each fault that the Sentry cannot resolve. |
| `GVX_SYSTRAP_TRACE=1` | Prints each signal that an illegal instruction, a breakpoint, or an arithmetic exception sends to a Windows `systrap` guest, with the exception code and the bytes at the program counter. The value `2` also prints every stop and the state of each stub. The value `3` prints only the state and the count of each kind of stop. The value `4` also samples the program counter and prints the hottest addresses. |
