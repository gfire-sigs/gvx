# GPU Renderer (`gvx-gpu-renderer`)

`gpurenderer/` builds the confined macOS GPU renderer executable (`gvx-gpu-renderer`) and its `libvulkan.dylib` shim for `darwin/arm64`. The build links `virglrenderer` (`venus` and `vrend`) and `libepoxy` statically and bundles KosmicKrisp (`libvulkan_kosmickrisp.dylib`).

## Build Modes (Descriptive Module)

`scripts/gpu/build-renderer.sh` reads all pinned source commits, archive digests, and Homebrew pins from [`third_party.lock`](third_party.lock). It supports three driver sources through `--driver-source`.

| Driver source | Driver origin | Intended use |
| :--- | :--- | :--- |
| `pinned` (default) | SHA-256-verified Homebrew bottles (`BOTTLE.*` in `third_party.lock`) | Fast local development and `ci.yml` validation |
| `mesa-source` | Pinned Mesa tarball (`DRIVER_SOURCE_*`) with `patches/mesa/*.patch` | Release archives (`release.yml`) and full WebGL conformance runs |
| `homebrew` | Local unpinned Homebrew formulas | Local experiments only; `package-renderer.sh` rejects it |

When `build-renderer.sh` stages a driver into `build/gpu/cache/`, it writes SHA-256 digests of every staged output file to `.gvx-stage.sha256`. On later runs, the script verifies that manifest before reusing the cached directory and rebuilds the staged driver on any missing file or digest mismatch.

## Release Reproducibility and Toolchain Pins (Descriptive Module)

In `--driver-source mesa-source` mode, Meson links static archives and bitcode from four Homebrew formulas (`llvm`, `libclc`, `spirv-llvm-translator`, and `spirv-tools`) into `libvulkan_kosmickrisp.dylib`. Release reproducibility therefore depends on matching those exact Homebrew toolchain versions in addition to the Mesa source tarball and patches.

`third_party.lock` pins each required formula version under `TOOLCHAIN.<formula>.version`. Both `scripts/gpu/build-renderer.sh` and `scripts/gpu/stage_driver.py` compare `brew list --versions <formula>` against the pinned version and fail on any mismatch. The scripts record the verified versions as `BUILD_TOOL` lines in `BUILDINFO`.

The version pin is a host check that fails closed; it does not download a pinned toolchain. When Homebrew updates one of the four formulas, the `release.yml` build fails until a maintainer updates `third_party.lock`. Run a `mesa-source` build with the new pins before you push a release tag. An old tag cannot be rebuilt after Homebrew removes the pinned formula version.

## Build and Verification Procedure (Procedural Module)

Run these steps on an Apple Silicon host with macOS 26 or later.

1. Install the build tools `meson`, `ninja`, and `pkgconf`.
2. For a `mesa-source` build, install `cmake`, `llvm`, `libclc`, `spirv-llvm-translator`, and `spirv-tools`.
3. Run `scripts/gpu/build-renderer.sh` to create the bundle in `build/gpu/gvx-gpu-renderer/`.
4. Run the `venus` self-test.
5. Verify that the `venus` self-test prints `selftest: PASS`.
6. Run the `virgl` self-test.
7. Verify that the `virgl` self-test prints `selftest: PASS`.

```bash
scripts/gpu/build-renderer.sh
build/gpu/gvx-gpu-renderer/bin/gvx-gpu-renderer --selftest
build/gpu/gvx-gpu-renderer/bin/gvx-gpu-renderer --selftest --mode=virgl
```
