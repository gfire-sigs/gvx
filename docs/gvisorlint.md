# The gVisor Analyzers in CI

This document describes how `gvx` runs the static analyzers of gVisor with plain `go`. It states which analyzers run, which analyzers do not run, and how to read and fix a finding. The tool is `tools/gvisorlint`.

## 1. What Runs and Why (Descriptive Module)

Upstream gVisor runs its analyzers through Bazel and `nogo`. The `go` branch that `gvx` syncs ships only `tools/checklocks`. The tool `tools/gvisorlint` is a `go vet` tool that runs three analyzers. The CI job `build, vet, and audit` runs it for the five supported targets.

| Analyzer | Source | What it finds |
| :--- | :--- | :--- |
| `checklocks` | `tools/checklocks` (upstream `go` branch) | A guarded field that code reads or writes without its lock. A call to a function without the lock that the function needs. An unlock of a lock that the code does not hold. |
| `checkconst` | `tools/gvisorlint/checkconst` (upstream `master`) | A constant, offset, size, or alignment that differs from the annotation `+checkconst`, `+checkoffset`, `+checksize`, or `+checkalign`. It reads Go files and `#define` lines of assembly files. |
| `checklinkname` | `tools/gvisorlint/checklinkname` (upstream `master`) | A `//go:linkname` directive with a signature that differs from the symbol it names, or with a symbol that no package defines. |

The annotation `+checkoffset` protects the assembly code of the `systrap` stub, the `sysmsg` code, `ring0`, and `sigframe`. It also protects the layout of runtime types that `pkg/sync` and `pkg/state` read, such as `internal/abi.MapType`. A new Go version that moves one field fails the lint before it corrupts a process.

The target decides which files build, so the tool runs once for each target. A Linux-only file is not visible from `darwin/arm64`. A Windows-only file is not visible from Linux.

### 1.1 Differences from Upstream nogo

The tool reproduces the settings of the upstream file `nogo.yaml` for first-party code. It also adapts the analyzers to `go vet`. Each difference has a reason.

| Difference | Reason |
| :--- | :--- |
| `checklocks` drops four message groups: `may require checklocks annotation`, `unexpected call to atomic function`, `return with unexpected locks held`, and `incompatible return states`. | Upstream `nogo.yaml` suppresses the same groups. The first group asks for new annotations. The other groups come from functions that lock and return without `+checklocksacquire` or `+checklocksrelease`. |
| `checklocks` drops a finding that has no source position. | Upstream `nogo.yaml` excludes these findings. The SSA builder creates a wrapper for a method value, such as `timer.Reset(e.expired)`. No source line can carry an annotation for a wrapper. |
| `checklocks` builds SSA form only for packages of the main module. | The standard library and the other modules have no lock annotations. SSA form of the standard library costs more than the whole analysis of `gvx`. |
| `checkconst` computes the constants of a standard library package from source. | The `go vet` protocol gives a package the facts of its direct imports only. The annotation `+checkoffset internal/abi MapType.Hasher` names a package that no code can import. Nogo loads transitive facts, and `go vet` cannot. |
| `checklinkname` trusts the linknames of the standard library. | The standard library holds hundreds of push and pull directives between its own packages. They are not part of `gvx`. |
| `checklinkname` runs the final link check for every `package main`. | Nogo names the main package `main`. The `go vet` driver names it by import path. |
| `checklinkname` counts a function with a body and a `//go:linkname` directive as the definition of the symbol. | The runtime defines `sync.runtime_canSpin` this way. Upstream reported such a symbol as missing. |
| `checklinkname` splits a symbol name at the first dot after the last slash, and it keeps a symbol that has the same local name and linkname. | Upstream failed on import paths that contain a dot, such as `golang.org/x/tools/go/ssa`. |
| The tool drops a second report of one message at one position. | `checklocks` reports a closure again for each call that inlines it. |

### 1.2 Analyzers That Do Not Run

| Analyzer | Reason |
| :--- | :--- |
| `checkescape` | It compares the annotations `+checkescape` with the disassembly of compiled objects. `go vet` gives no object files, and the check is part of the Bazel build rules. |
| `checkaligned` | It forbids `sync/atomic` operations on 64-bit integers, because 32-bit targets need 8-byte alignment. All five targets of `gvx` are 64-bit. |
| `checkimports` | It requires every file that imports `unsafe` to end in `_unsafe.go`. The rule serves the Bazel `go_library` split. It reports 65 imports on `darwin/arm64`, among them generated `.pb.go` files, `internal/xsys/unix`, and every host binding of `hvf` and `whpx`. A rename would move files without fixing a defect. |
| `unsafeptr` and the other analyzers of `go vet` | The step `Vet all target platforms` of CI runs them for the packages that `gvx` wrote. Upstream packages carry findings that the project does not fix. |

## 2. Run the Tool Locally (Procedural Module)

Run the script `scripts/gvisorlint.sh` before you push a change to a Go file under `pkg/` or `tools/`. The script builds the tool and runs `go vet` for each target.

> [!IMPORTANT]
> Use the same targets as CI. A finding in a `_windows.go` file shows only when `GOOS=windows`.

1. Run `scripts/gvisorlint.sh` for the five targets. A run with a warm cache takes about 2 minutes.
2. Run `scripts/gvisorlint.sh darwin/arm64` to check one target.
3. Read each finding as `file:line:column: message`.
4. Fix the finding with the rules of section 3.
5. Run the script again until it prints nothing.

To run the tool by hand, build it and pass it to `go vet`.

```bash
go build -o "$PWD/gvisorlint" ./tools/gvisorlint
GOOS=windows GOARCH=arm64 go vet -vettool="$PWD/gvisorlint" ./pkg/sentry/mm/
```

Run `go test ./tools/gvisorlint/` after you change the tool. The tests run the real tool on small modules with and without a violation.

## 3. Fix a Finding (Procedural Module)

Fix the code first. A finding names a real defect more often than a limit of the analyzer. Use an annotation only when the analyzer cannot follow the code.

| Finding | Meaning | Fix |
| :--- | :--- | :--- |
| `invalid field access, mu (...) must be locked when accessing x` | Code reads or writes the guarded field `x` without `mu`. | Take the lock. Or annotate the function with `+checklocks:recv.mu` and take the lock in every caller. |
| `must hold mu exclusively (...) to call f, but not held` | `f` has a `+checklocks` precondition that the caller does not meet. | Take the lock in the caller. Or add the same annotation to the caller. |
| `... already unlocked or locked differently` | The code unlocks a lock that it does not hold. | Mark a function that unlocks for its caller with `+checklocksrelease:recv.mu`. Mark a function that locks for its caller with `+checklocksacquire:recv.mu`. |
| `got value A, wanted "B"` | A constant, offset, or size in Go or assembly differs from the real value. | Change the value to `B`. Read the layout change before you do. |
| `symbol "f" has signature ..., expected signature ...` | A `//go:linkname` declaration differs from its target. | Match the signature of the target in the standard library. |
| `remote symbol "f" not defined in package "p"` | No package defines the linkname target. | Find the new name of the symbol in the standard library. |

When the analyzer cannot follow correct code, use one of these annotations. Write the reason after the annotation.

| Annotation | Use |
| :--- | :--- |
| `// +checklocksforce: <reason>` after a statement | The statement runs with the lock held, and the analyzer cannot prove it. Examples: the body of a `range` over a function iterator, a closure that a caller runs with the lock, and an unlock after `TryLock`. |
| `// +checklocksignore: <reason>` in the doc comment of a function | The function needs no analysis. Use it for a function that takes a lock only on one path, or for a test that owns every object. |
| `// +checklocksfail=<text>` after a statement | The test expects a finding at this line. Use it only in analyzer tests. |

Split a struct when a lock guards only part of it. The annotation `+checklocks:mu` on a field covers every field inside it, including the atomic fields. The type `fibRules` in `pkg/tcpip/stack` holds the fields that `routeMu` guards. The type `fibState` holds the atomic fields that readers use without the lock.

## 4. The Baseline (Reference Module)

The file `tools/gvisorlint/baseline.txt` lists the findings that the tool accepts. Each line has the analyzer, the path of the file, and a regular expression for the message. The path `-` selects a finding without a position. The tool embeds the file, so a change invalidates the cached results of `go vet`.

Add a baseline line only for upstream code that `gvx` must not edit, and write the reason above the line. Fix a finding in a file that `gvx` owns. The baseline holds one entry. It covers the signature of `syscall.compileCallback` in `golang.org/x/sys/windows`.

## 5. Continuous Integration (Descriptive Module)

The step `Lint with the gVisor analyzers` of the job `build, vet, and audit` in `.github/workflows/ci.yml` first runs `go test ./tools/gvisorlint/`, then runs `scripts/gvisorlint.sh` for the five targets. It runs after the step `Vet all target platforms`. The job fails when the tool reports a finding. The test `TestVetTool` in `tools/gvisorlint/lint_test.go` proves this. It runs the real tool on a module with a new violation and expects a failure.

## 6. Update the Copied Analyzers (Procedural Module)

The packages `checkconst` and `checklinkname` are copies of upstream `master`. Their package comments name the commit. They have the changes of section 1.1.

1. Download the new files from `google/gvisor` `master`, in `tools/checkconst` and `tools/checklinkname`.
2. Apply the changes of section 1.1 to the new files.
3. Update the commit in each package comment.
4. Run `go test ./tools/gvisorlint/` and `scripts/gvisorlint.sh`.
