# Contributing to gvx

Contributions to `gvx` are welcome across host bindings, filesystem drivers, networking, extension plugins, tests, and documentation. This guide takes a new contributor from a fresh clone to a reviewed pull request.

`gvx` tracks the pre-generated `go` branch of `google/gvisor` and builds with Go 1.27.4 or newer without Bazel. Keeping host primitives separated from upstream gVisor code preserves weekly upstream merges with low friction.

Read [`docs/architecture.md`](docs/architecture.md) to verify owning packages and import boundaries before modifying source files, and follow [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## 1. Repository Orientation and Deliverables

This table maps each deliverable and core subsystem to its owning packages, test suites, and primary specification.

| Deliverable or Subsystem | Entry Package | Primary Tests | Primary Specification |
| :--- | :--- | :--- | :--- |
| Standalone CLI (`rungvx`) | `cmd/rungvx`, `pkg/rungvx` | `pkg/rungvx/*_test.go`, `e2e/` | [`docs/cli.md`](docs/cli.md) |
| Embeddable Go SDK | `pkg/gvx`, `pkg/gvx/shm`, `pkg/gvx/exttest` | `pkg/gvx/*_test.go`, `e2e/` | [`docs/architecture.md`](docs/architecture.md) |
| Extension submodule | `ext/` (`ext/cmd/rungvx`, `ext/extensions/gpu`) | `ext/...` (CI `ext.yml`) | [`docs/extensions-plan.md`](docs/extensions-plan.md) |
| Control protocol (`gvx-ctrl/2`) | `pkg/gvx/control` | `pkg/gvx/control/*_test.go`, `e2e/control_e2e_test.go` | [`docs/control-protocol.md`](docs/control-protocol.md) |
| Containerd control shim | `cmd/containerd-shim-gvx-v2`, `internal/gvxshim` | `internal/gvxshim/*_test.go`, `tools/shiminterop` | [`docs/architecture.md`](docs/architecture.md#310-optional-containerd-control-adapter) |
| Android library (`gvx-android.aar`) | `android/` | `scripts/android/emulator-smoke.sh` | [`docs/components/android.md`](docs/components/android.md) |
| Hardware hypervisors | `pkg/sentry/platform/{whpx,hvf,hvcommon}` | `pkg/sentry/platform/{whpx,hvf,hvcommon}/*_test.go` | [`docs/components/hypervisors.md`](docs/components/hypervisors.md) |
| Windows and Linux `systrap` | `pkg/sentry/platform/systrap` | `pkg/sentry/platform/systrap/*_test.go` | [`docs/systrap-windows.md`](docs/systrap-windows.md) |
| Single-file ext4 volumes | `pkg/sentry/fsimpl/ext4lite` | `pkg/sentry/fsimpl/ext4lite/*_test.go`, `scripts/pjdfstest` | [`docs/components/ext4lite.md`](docs/components/ext4lite.md) |
| Host workspace driver | `pkg/sentry/fsimpl/hostfs` | `pkg/sentry/fsimpl/hostfs/*_test.go`, `scripts/pjdfstest` | [`docs/components/hostfs.md`](docs/components/hostfs.md) |
| Networking backend | `pkg/netbackend`, `pkg/ipset`, `pkg/tcpip/link/{vxlan,wgtun}` | `pkg/netbackend/*_test.go`, `e2e/*netfilter*`, `e2e/*wireguard*` | [`docs/components/netbackend.md`](docs/components/netbackend.md) |
| OCI compiler and host CAs | `pkg/oci`, `pkg/gvx/hostcerts` | `pkg/oci/*_test.go`, `e2e/gate_m3_test.go` | [`docs/components/oci.md`](docs/components/oci.md) |
| Host self-lockdown | `pkg/hostlockdown` | `pkg/hostlockdown/*_test.go`, `e2e/gate_m4_test.go` | [`docs/components/hostlockdown.md`](docs/components/hostlockdown.md) |

---

## 2. Three-Tier Upstream Isolation Rule

`gvx` keeps its diff against upstream gVisor below 5.0% (enforced at 4.5% in CI) so upstream merges remain mechanical. Separating host code from upstream packages also keeps root `go.mod` dependencies minimal for SDK consumers.

Every file in the repository belongs to one of three isolation tiers enforced by `tools/upstream`. Choosing the highest applicable tier avoids merge conflicts on upstream releases and keeps `Tier 3` patches focused.

Place new code in the highest isolation tier from the list below that fits its package boundary.

1. **Tier 1 (Additive Packages)**: New `gvx`-owned packages (`cmd/rungvx`, `pkg/rungvx`, `pkg/gvx`, `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `ext/`, `e2e/`, `docs/`). These files never conflict with upstream.
2. **Tier 2 (Sibling Files)**: OS-specific or cross-platform helpers placed beside upstream files with `_windows`, `_darwin`, or `_xplat` filenames. These files cost zero upstream diff budget.
3. **Tier 3 (Upstream Patches)**: Minimal build-tag expansions or hook seams in upstream pure-Go files. Register each edit in `tools/upstream/buildtag_allowlist.txt` and keep PRs under ~400 changed lines.

---

## 3. Preparing a First Contribution

Follow these steps to build, verify, and submit a pull request.

> [!IMPORTANT]
> Run `go test` through `scripts/codesign-exec.sh` on macOS. Unsigned test binaries lack the hypervisor entitlement and fail TLS verification in network tests.

1. Fork the repository on GitHub and clone your fork locally.
2. Create a topic branch from `main` (for example, `git checkout -b fix/ext4lite-truncate`).
3. Implement a focused change with tests exercising the real producer and observable boundaries.
4. Run formatting, unit tests, cross-compilation, and static audits before opening a pull request.

```sh
# Format owned Go files
go fmt ./...

# Run tests locally (macOS uses codesign-exec.sh; omit -exec on Linux and Windows)
go test -race -exec "$PWD/scripts/codesign-exec.sh" ./pkg/gvx/...

# Cross-compile all five production targets
for target in darwin/arm64 windows/amd64 windows/arm64 linux/amd64 linux/arm64; do
  GOOS=${target%/*} GOARCH=${target#*/} go build ./...
done

# Verify generated state files, static analyzers, upstream diff budget, and licenses
./scripts/gostateify.sh -check
./scripts/gvisorlint.sh
go run ./tools/upstream -mode=audit -max-ratio=0.045
go run ./tools/licenses -check
```

If you modify tunables in `pkg/gvx/tuning`, regenerate the table in [`docs/cli.md`](docs/cli.md) with `go test ./pkg/gvx/tuning -run TestDocsMatchRegistry -update`. If you modify `// +stateify savable` structs, run `./scripts/gostateify.sh`.

---

## 4. Commit, Documentation, and Review Standards

Consistent commits and controlled documentation keep pull-request reviews short and factual.

- **Commit messages**: Use Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`) with an imperative subject of at most 72 characters. State cause and consequence in the body when non-obvious.
- **Documentation prose**: Write concise English without em-dashes (`\u2014`), spaced en-dashes, or prose arrows (`\u2192`). Verify edits with `rg -n "\x{2014}| \x{2013} |\x{2192}" README.md AGENTS.md CONTRIBUTING.md SECURITY.md docs/`.
- **Real producers in tests**: Cross-boundary tests (registers, signal frames, wire frames, shared memory) must obtain inputs from real platform, kernel, or guest probes.
- **Per-sandbox isolation**: One host process can run multiple sandboxes concurrently. Never store per-sandbox limits, counters, or guest-visible state in process-wide package variables.
- **Independent review**: PRs touching Tier 3 files, execution backends, signals, memory, or locking require an independent review recorded before merge.

Consult [`AGENTS.md`](AGENTS.md) for maintainer rules, CI workflows, and release versioning procedures.
