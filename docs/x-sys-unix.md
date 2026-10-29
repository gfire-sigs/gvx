# The Embedded `unix` Package

This module embeds a modified copy of the package `golang.org/x/sys/unix` in `internal/xsys/unix`. The copy replaces an earlier fork of the whole module `golang.org/x/sys`. This document states why the copy exists, what it changes, and how to update it.

## 1. Why the Copy Exists

The pure-Go Sentry code of gVisor imports `golang.org/x/sys/unix` and expects Linux types and constants. The upstream package has no file for Windows. On Darwin its types follow the Darwin ABI, and the Sentry expects the Linux shape. The copy closes both gaps.

The copy lives inside this module. Every import of `golang.org/x/sys/unix` in the repository points at `z.gfire.dev/gvx/internal/xsys/unix`. A `replace` directive of this module would not reach a module that imports `pkg/gvx`, and that module would fail to build. The script `scripts/check-consumer.sh` builds such a module for the five targets, and the build job of CI runs it.

The other packages of `golang.org/x/sys`, such as `windows` and `cpu`, come from the upstream module through the `require` line of `go.mod`.

## 2. What the Copy Changes

| Area | Files | Change |
| :--- | :--- | :--- |
| Windows | `gvx_windows.go`, `gvx_memory_windows.go`, `gvx_z*_windows*.go` | Adds the Linux errors, types, system call numbers, and functions such as `Mmap`. The functions call the Windows API. |
| Darwin types | `ztypes_darwin_{amd64,arm64}.go` | Gives `Stat_t`, `Dirent`, and `Msghdr` the Linux field sizes and names. |
| Darwin calls | `zsyscall_darwin_{amd64,arm64}.go`, `gvx_darwin.go` | `Stat`, `Lstat`, `Fstat`, and `Fstatat` read the native structure and convert it. |
| Darwin `mincore` | `gvx_mincore_*` | Implements the Linux `mincore` contract on top of the 16KB host page. |
| Build tags | `asm_bsd_*.s`, `syscall_unix_gc.go`, `syscall_darwin_*.go` | Drops `darwin` from the tags of three files and widens two fields of `Msghdr` in the setters. |

The copy keeps only the files for Darwin, Linux on `amd64` and `arm64`, Windows, and the shared code. It has no generator scripts and no upstream tests. The tests of the gvx changes are in the files `gvx_*_test.go`.

## 3. How to Update the Copy

Run these steps when the version of `golang.org/x/sys` in `go.mod` changes.

1. Download the new version of the module and copy its `unix` directory over `internal/xsys/unix`.
2. Delete the files for other systems, the generator scripts, and the upstream tests. Keep every file with the prefix `gvx_`.
3. Apply the changes of section 2 to the Darwin files again. A diff against the old version of the copy lists them.
4. Run `go build ./...` for the five targets and `go test ./internal/xsys/unix/`.
5. Run `scripts/check-consumer.sh`.

The sync tool `tools/upstream` rewrites the import of the package in upstream gVisor files. Its rewrite and its audit use the same rule as the rewrite of the gVisor module path.
