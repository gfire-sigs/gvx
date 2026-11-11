# Security Policy

`gvx` runs untrusted Linux code and untrusted image data inside one host process. This file defines the security boundaries of `gvx`, the supported versions, and the private procedure for reporting a vulnerability.

## 1. Security Boundaries (Descriptive Module)

A vulnerability is a defect that lets a guest, an image, or a volume file cross one of these boundaries. [`docs/architecture.md`](docs/architecture.md) Section 3.9 describes the containment model.

| Boundary | Expected Behavior |
| :--- | :--- |
| Guest to host | On `whpx`, `hvf`, and Linux `systrap`, guest code cannot run host system calls, read or write host memory, or start a host process. Untrusted workloads on Windows require `whpx`. |
| Host lockdown | After `hostlockdown.Apply()` returns, the host process cannot start a process, open an unbound host path, or create a blocked socket. |
| Workspace and bind mounts | `hostfs` opens no host file outside the mounted directory or file. |
| Untrusted input | A malformed image layer, EROFS image, `ext4lite` volume file, or registry response causes an error, not memory corruption or a host write outside the cache. |
| Network isolation | `-net=wg` sends guest traffic only through the WireGuard tunnel. `-net=none` gives the guest no host network. |
| Control shim | `containerd-shim-gvx-v2` never signals a stored PID and never deletes files that containerd owns. |
| Release archives | Every archive of a release has a SLSA build provenance attestation from `.github/workflows/release.yml` for the tag of the release. An archive that fails `gh attestation verify` is not a `gvx` release. |

These limits are documented behavior, not vulnerabilities:

- On Windows, `PlatformAuto` refuses fallback to `systrap` when `whpx` is unavailable unless `Config.AllowUnconfinedSystrap` or `-allow-unconfined-systrap` enables it.
- On Windows, `systrap` uses user-mode syscall patching with Low-integrity token and job containment; it provides no hardware or kernel syscall trap.
- On Android, a host mount leaves `Status.UnboundFileOpenBlocked` false because the `untrusted_app` seccomp policy of Zygote blocks Landlock calls.
- `-lockdown=false` disables the host lockdown.
- A guest can use the host network that `-net=nat` and `-p` expose.

## 2. Supported Versions (Reference Module)

The project is in pre-release. It fixes vulnerabilities on the `main` branch and in the next release only.

| Version | Supported |
| :--- | :--- |
| `main` | Yes |
| Latest release | Yes |
| Older releases | No |

## 3. Vulnerability Report Procedure (Procedural Module)

Report a vulnerability through a private GitHub security advisory.

> [!WARNING]
> Do not open a public issue, pull request, or discussion for a vulnerability. Public disclosure exposes users before a fix exists.

1. Open <https://github.com/gfire-sigs/gvx/security/advisories/new>.
2. Write the output of `rungv version` in the report.
3. Write the host OS, the host architecture, and the backend (`hvf`, `whpx`, or `systrap`).
4. Attach the smallest guest program, image, or volume file that reproduces the defect.
5. Describe the boundary from Section 1 that the defect crosses.

The maintainers reply in the advisory thread and publish the advisory with the fix. Report a defect that also exists in upstream gVisor through the [gVisor security policy](https://github.com/google/gvisor/security/policy).
