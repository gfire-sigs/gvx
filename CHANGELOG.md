# Changelog

This file records the observable changes of each `gvx` release. The release workflow `.github/workflows/release.yml` publishes the section of a tag as its release notes. A tag with a hyphen, such as `v0.1.0-rc.1`, publishes a pre-release.

## [Unreleased]

This section makes the CPU features that a guest sees agree with the features that it can use.

### Bug Fixes

- **`whpx` on `windows/amd64`**: guests can use AVX, AVX2, FMA, F16C, and AVX-512. XCR0 was 3 (x87 and SSE), while CPUID and `/proc/cpuinfo` reported the AVX family. A program that checked only CPUID or `/proc/cpuinfo` got `SIGILL`, and x86-64-v3 images (RHEL 10 family) did not start. The backend now selects the `ProcessorXsaveFeatures` property and XCR0 together. It moves the compacted XSAVE state through `WHvGetVirtualProcessorState` and `WHvSetVirtualProcessorState`.
- **`whpx` feature set on `windows/amd64`**: `/proc/cpuinfo`, signal frames, and sigreturn checks list only the features of the partition. MPX, AMX, and protection keys no longer appear.
- **`AT_HWCAP` on `darwin/arm64` and `windows/arm64`**: the value was 0, and the `Features` line of `/proc/cpuinfo` was empty. `hvf` guests now get the bits of the `hw.optional` sysctl keys. `whpx` guests on `windows/arm64` get the host bits that `hvcommon.DefaultIDRegisters` also reports. glibc and OpenSSL then use LSE atomics, AES, SHA, and CRC32.

### Performance

Each value is the median of 3 runs. The baseline is `v0.2.0`.

| Workload | Host | Before | After |
| :--- | :--- | ---: | ---: |
| AES-128-GCM, `openssl speed` 16 KiB blocks in `alpine/openssl` on `hvf` | Apple M1 | 0.22 GB/s | 7.45 GB/s |
| SHA-256, same method | Apple M1 | 0.45 GB/s | 2.84 GB/s |
| ChaCha20-Poly1305, same method | Apple M1 | 0.68 GB/s | 2.12 GB/s |
| Vector state pull and push with one system call on `whpx` | `windows-latest` (AMD, AVX2, nested Hyper-V) | 68.9 us | 63.4 us |
| Vector state push on `whpx` | same | 16.1 us | 13.6 us |
| System call round trip on `whpx` | same | 18.4 us | 15.9 us |

The `hvf` microbenchmarks of `e2e/microbench_e2e_test.go` (`getpid`, `open_close`, `pipe_pingpong`, `futex_pingpong`, `fork_wait`, `fork_exec_true`) show no change outside the variation between runs.

### Not verified

- `TestRealZMMSurvivesTheSentryAndProcessorSharing` skips on a CI runner without AVX-512.
- The `windows/arm64` `AT_HWCAP` path has no run on a Windows host.

## [v0.2.0] - 2026-11-01

This release makes the `whpx` backend run guests on `windows/arm64`. The other backends and targets have no behavior change.

### Bug Fixes

- **`whpx` on `windows/arm64`**: the partition now starts guests. The backend configures GICv3 before partition setup, assigns one redistributor to each virtual processor, and starts every virtual processor active. With v0.1.0 on Windows 11 build 28000, partition setup failed without the GICv3 parameters, and secondary processors stayed suspended.
- **`whpx` stub exit on `windows/arm64`**: WHP consumes `HVC #0` without an exit to the host. The EL1 stub now returns to the host through a load from an unbacked guest physical page that only EL1 can read.

### Performance

- **`whpx` on `windows/arm64`**: each system call and fault stop costs one extra `WHvSetVirtualProcessorRegisters` call. The memory exit leaves the program counter at the load, so the host writes the program counter before it resumes the processor.

### Not verified

- The contributor ran the native `whpx` suites and the image gates on Windows 11 build 28000 only. The project has no native result on Windows 11 24H2 (build 26100), the documented minimum.
- CI cannot run `whpx` on `windows/arm64`, because the `windows-11-arm` runner has no Windows Hypervisor Platform.
- The extra program counter write has no latency measurement.

## [v0.1.0] - 2026-11-01

This section describes the first release. The API of `pkg/gvx`, the flags of `rungv`, and the on-disk formats of the image store and of `ext4lite` volumes can change before `v1.0.0`.

### Features

- **`rungv` CLI**: runs OCI images and Linux ELF64 binaries in the foreground with Docker-style flags. The commands are `run`, `pull`, `images`, `inspect`, `tag`, `rmi`, `save`, `load`, `login`, `logout`, `stub`, `license`, and `version`. [`docs/cli.md`](docs/cli.md) is the reference.
- **`pkg/gvx` SDK**: embeds one sandbox in a Go host program.
- **Execution backends**: `hvf` on `darwin/arm64`, `whpx` on `windows/amd64` and `windows/arm64`, the `gvx` `systrap` engine on `windows/amd64` and `windows/arm64`, and the upstream `systrap` platform on Linux.
- **OCI images**: pulls multi-arch images and compiles each layer in memory into a cached `.erofs` file. The guest architecture must equal the host architecture.
- **Storage**: `-workspace` and `-v` bind mounts through `hostfs`, and named volumes in one journaled `.ext4` file through `ext4lite`.
- **Network**: `-net=nat` with `-p` port forwarding, and `-net=wg` with an in-memory WireGuard tunnel.
- **Host lockdown**: Windows Restricted Token and Job Object, macOS Seatbelt, and Linux `seccomp`. The lockdown starts before the guest entrypoint runs.
- **Control shim**: the optional `containerd-shim-gvx-v2` command implements the control endpoints of runtime `io.containerd.gvx.v2`.
- **Release identity**: `rungv version` and `rungv --version` print the module version, the source commit, and the Go toolchain of the binary.
- **Release provenance**: each release archive has a SLSA v1 build provenance attestation (SLSA Build Level 2). `gh attestation verify` checks it. Section 2.4 of [`README.md`](README.md) gives the procedure.

### Known limitations

- The control shim rejects sandbox and workload creation with `Unimplemented`. It does not implement CRI.
- macOS has no `systrap` engine. `rungv` on macOS needs `Hypervisor.framework` and a binary signed with `entitlements.plist`.
- `darwin/amd64` is not supported.
- On Linux, a workspace, a bind mount, or a `hostfs` volume leaves `Status.UnboundFileOpenBlocked` false. Section 3.9 of [`docs/architecture.md`](docs/architecture.md) gives the reason.
- The release archive for macOS has an ad-hoc signature, not a Developer ID signature or notarization. Section 2.4 of [`README.md`](README.md) gives the install procedure.
- `whpx` on `windows/arm64` does not start a guest in this release. Use `-platform=systrap` on `windows/arm64`. v0.2.0 fixes `whpx`.

### Not verified

- CI cannot run `hvf`, because the hosted macOS runner has no hypervisor. The project verifies `hvf` on an Apple Silicon development host only.
- CI runs `whpx` on `windows/amd64` only. The `windows-11-arm` runner has no Windows Hypervisor Platform, so `whpx` on `windows/arm64` has no CI run.
- The control shim has no successful native sandbox creation and no guest workload on any platform.
