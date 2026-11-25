# Security Policy

`gvx` runs untrusted Linux binaries and parses untrusted container images and volume files within one host process. Enforcing strict privilege boundaries prevents guest code or malformed artifacts from escaping into the host OS.

Hardware page tables, a memory-safe Go kernel, pinned directory handles, and OS-native host self-lockdown form concentric defense layers. Any defect that bypasses one of those layers on a supported target qualifies as a security vulnerability.

This policy defines the enforced boundaries, supported versions, provenance checks, and private disclosure procedure.

## 1. Security Boundaries

A security vulnerability is any defect enabling a guest program, image, volume, or control peer to cross one boundary below. See [`docs/components/hostlockdown.md`](docs/components/hostlockdown.md) and [`docs/architecture.md`](docs/architecture.md#39-host-self-lockdown-and-security-model) for containment details.

| Boundary | Enforced Invariant |
| :--- | :--- |
| **Guest to host** | Under `whpx`, `hvf`, and Linux `systrap`, guests cannot run host syscalls, read host memory, or spawn processes. Untrusted Windows code requires `whpx`. |
| **Host lockdown** | After `hostlockdown.Apply()` succeeds, the process cannot spawn children, open unbound paths, or bind unauthorized sockets. |
| **Workspace and bind mounts** | `hostfs` opens no host file outside the mounted directory or single regular file. |
| **Untrusted input** | Malformed OCI layers, EROFS files, `ext4lite` volumes, checkpoint bundles, or registry replies fail without memory corruption or outside writes. |
| **Network isolation** | `-net=wg` forwards guest packets solely through WireGuard; `-net=none` blocks external host network access. |
| **Control shim** | `containerd-shim-gvx-v2` never signals a PID from metadata and never removes containerd-owned files. |
| **Release archives** | Every release archive carries a SLSA v1 provenance bundle from `.github/workflows/release.yml`. Reject archives failing verification. |
| **GPU renderer (`-gpu=venus`, `-gpu=virgl`)** | Guest data cannot spawn processes, write host files, or open network sockets in `gvx-gpu-renderer`. Renderer faults never corrupt Sentry memory. |

### Verifying Release Provenance

Before executing a downloaded release archive, verify its Sigstore provenance bundle with the GitHub CLI (`gh`). Grab the desired release tag from [GitHub Releases](https://github.com/gfire-sigs/gvx/releases) for `VERSION`.

1. Download the archive and its `.sigstore.json` bundle from GitHub Releases.
2. Run `gh attestation verify` against the exact repository, workflow, and tag reference.

```sh
VERSION=<release-tag>
ARCHIVE="rungvx-${VERSION}-darwin-arm64.tar.gz"
gh attestation verify "${ARCHIVE}" \
  --bundle "rungvx-${VERSION}.sigstore.json" \
  --repo gfire-sigs/gvx \
  --signer-workflow gfire-sigs/gvx/.github/workflows/release.yml \
  --source-ref "refs/tags/${VERSION}" \
  --deny-self-hosted-runners
```

### Documented Operational Limits (Not Vulnerabilities)

The following behaviors are deliberate design limits rather than security defects:

- On Windows, `--backend=auto` fails closed without `whpx` unless `-allow-unconfined-systrap` or `Config.AllowUnconfinedSystrap` opts into `systrap`.
- Windows `systrap` uses user-mode binary rewriting, a Low-integrity token, and a Job Object; it lacks a kernel syscall trap.
- On Android, host directory mounts leave `Status.UnboundFileOpenBlocked` false because Zygote's `untrusted_app` seccomp policy traps Landlock syscalls.
- Passing `-lockdown=false` disables host self-lockdown for debugging.
- Under `-net=nat`, `-p`, and `--auto-publish`, guests can reach host endpoints and loopback listeners explicitly exposed to them.
- Opt-in `-gpu=venus` and `-gpu=virgl` launch a confined C worker calling `virglrenderer`, KosmicKrisp/Metal, or Apple OpenGL. Host driver bugs stay reachable inside that worker.
- The host kernel does not bound GPU renderer memory. An internal watchdog exits above the configured limit, though a compromised renderer can bypass it.
- A guest sending malformed GPU commands stops its own renderer permanently without automatic restart.

## 2. Supported Versions

`gvx` is under active pre-release development. Security fixes land on `main` and ship in the next tagged release only.

| Version | Supported |
| :--- | :--- |
| `main` branch | Yes |
| Latest tagged release | Yes |
| Earlier releases | No |

## 3. Reporting a Vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories.

> [!WARNING]
> Do not disclose a vulnerability in a public issue, pull request, or discussion. Public disclosure exposes users before a remediation exists.

1. Open <https://github.com/gfire-sigs/gvx/security/advisories/new>.
2. Include the complete output of `rungvx version -V`.
3. State the host OS, CPU architecture, and execution backend (`hvf`, `whpx`, or `systrap`).
4. Attach the minimal guest binary, OCI image, or volume file reproducing the defect.
5. Identify which boundary from Section 1 the defect violates.

Maintainers respond in the private advisory thread and coordinate disclosure with the fix. Report defects reproducing in unmodified upstream gVisor through the [gVisor security policy](https://github.com/google/gvisor/security/policy).
