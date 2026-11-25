# Contributing to gvx

Contributions to `gvx` are welcome across host bindings, filesystem drivers, networking, tests, and documentation. This guide leads a new contributor from a fresh clone to a reviewed pull request. All participants adhere to [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

---

## 1. Repository Orientation and Deliverables

`gvx` tracks the pre-generated `go` branch of `google/gvisor` and builds with standard `go build` (Go 1.27.4 or newer) without Bazel. Before modifying any source file, read [`docs/architecture.md`](docs/architecture.md) to identify the owning package and its import boundaries.

| Deliverable | Entry Package | Primary Tests | Primary Specification |
| :--- | :--- | :--- | :--- |
| Standalone CLI (`rungvx`) | `cmd/rungvx` | `cmd/rungvx/*_test.go`, `e2e/` | [`docs/cli.md`](docs/cli.md) |
| Embeddable Go SDK | `pkg/gvx` | `pkg/gvx/*_test.go`, `e2e/` | [`docs/architecture.md`](docs/architecture.md) |
| Control protocol (`gvx-ctrl/2`) | `pkg/gvx/control` | `pkg/gvx/control/*_test.go`, `e2e/control_e2e_test.go` | [`docs/control-protocol.md`](docs/control-protocol.md) |
| Containerd control shim | `cmd/containerd-shim-gvx-v2`, `internal/gvxshim` | `internal/gvxshim/*_test.go`, `tools/shiminterop` | [`docs/architecture.md`](docs/architecture.md#310-optional-containerd-control-adapter) |
| Android library (`gvx-android.aar`) | `android/` | `scripts/android/emulator-smoke.sh` | [`docs/components/android.md`](docs/components/android.md) |
| Hardware hypervisors | `pkg/sentry/platform/{whpx,hvf,hvcommon}` | `pkg/sentry/platform/{whpx,hvf,hvcommon}/*_test.go` | [`docs/components/hypervisors.md`](docs/components/hypervisors.md) |
| Windows and Linux `systrap` | `pkg/sentry/platform/systrap` | `pkg/sentry/platform/systrap/*_test.go` | [`docs/systrap-windows.md`](docs/systrap-windows.md) |
| Single-file ext4 volumes | `pkg/sentry/fsimpl/ext4lite` | `pkg/sentry/fsimpl/ext4lite/*_test.go`, `scripts/pjdfstest` | [`docs/components/ext4lite.md`](docs/components/ext4lite.md) |
| Host workspace driver | `pkg/sentry/fsimpl/hostfs` | `pkg/sentry/fsimpl/hostfs/*_test.go`, `scripts/pjdfstest` | [`docs/components/hostfs.md`](docs/components/hostfs.md) |
| Networking backend | `pkg/netbackend`, `pkg/ipset`, `pkg/tcpip/link/{vxlan,wgtun}` | `pkg/netbackend/*_test.go`, `e2e/*netfilter*`, `e2e/*wireguard*` | [`docs/components/netbackend.md`](docs/components/netbackend.md) |
| OCI image compiler and cache | `pkg/oci`, `pkg/gvx/hostcerts` | `pkg/oci/*_test.go`, `e2e/gate_m3_test.go` | [`docs/components/oci.md`](docs/components/oci.md) |
| Host self-lockdown | `pkg/hostlockdown` | `pkg/hostlockdown/*_test.go`, `e2e/gate_m4_test.go` | [`docs/components/hostlockdown.md`](docs/components/hostlockdown.md) |

---

## 2. Three-Tier Upstream Isolation Rule

`gvx` keeps its diff against upstream gVisor below 5.0% (enforced at 4.2% in CI) so upstream merges proceed cleanly. Place new code in the highest isolation tier that fits:

1. **Tier 1 (Additive Packages)**: New `gvx`-owned packages (`pkg/gvx`, `pkg/oci`, `pkg/netbackend`, `pkg/hostlockdown`, `pkg/sentry/platform/{whpx,hvf,hvcommon}`, `pkg/sentry/fsimpl/{ext4lite,hostfs,rpcfs}`, `cmd/rungvx`, `e2e/`, `docs/`). These files never conflict with upstream.
2. **Tier 2 (Sibling Files)**: OS-specific or cross-platform helpers placed inside an upstream package with `_windows`, `_darwin`, or `_xplat` in the file name. These files cost zero upstream diff budget.
3. **Tier 3 (Upstream Patches)**: Minimal build-tag expansions or hook seams in upstream pure-Go files. Register every Tier 3 edit in `tools/upstream/buildtag_allowlist.txt` and keep each Tier 3 pull request focused on one behavior (under roughly 400 changed lines excluding tests and generated files).

---

## 3. Preparing a First Contribution

Follow this sequence to build, verify, and submit a change.

> [!IMPORTANT]
> On macOS, run `go test` through `scripts/codesign-exec.sh`. Unsigned test binaries lack the hypervisor entitlement and fail TLS verification in network tests.

1. Fork the repository on GitHub and clone your fork locally.
2. Create a topic branch from `main` (for example, `git checkout -b fix/ext4lite-truncate`).
3. Make a focused change with tests that exercise the real producer and observable boundary behavior.
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
go run ./tools/upstream -mode=audit -max-ratio=0.042
go run ./tools/licenses -check
```

If your change modifies any tunable in `pkg/gvx/tuning`, regenerate the reference table in [`docs/cli.md`](docs/cli.md) with `go test ./pkg/gvx/tuning -run TestDocsMatchRegistry -update`. If your change modifies `// +stateify savable` types, run `./scripts/gostateify.sh`.

---

## 4. Commit, Documentation, and Review Standards

Consistent commits and documentation keep reviews short and factual.

- **Commit messages**: Use Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`) with an imperative subject line of at most 72 characters. State the technical cause and consequence in the body when non-obvious.
- **Documentation prose**: Write in clear, concise English without em-dashes (`\u2014`), spaced en-dashes, or prose arrows (`\u2192`). Verify documentation edits with `rg -n "\x{2014}| \x{2013} |\x{2192}" README.md AGENTS.md CONTRIBUTING.md SECURITY.md docs/`.
- **Real producers in tests**: Tests verifying cross-boundary formats (registers, signal frames, wire frames, shared memory) must obtain inputs from the real platform, kernel, or guest binary rather than synthetic fixtures built with the same assumption.
- **Per-sandbox isolation**: One host process may run multiple sandboxes concurrently. Never store per-sandbox limits, counters, or guest-visible state in process-wide package variables.
- **Independent review**: Pull requests touching Tier 3 files, execution backends, signals, memory management, or locking paths require an independent review recorded on the pull request before merge.

For complete maintainer rules, CI workflows, and release versioning procedures, consult [`AGENTS.md`](AGENTS.md).
