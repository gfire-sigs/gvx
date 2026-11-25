# Pinned `mesa` Patches

These `gvx` patches apply to the pinned KosmicKrisp 26.3.0 source tarball during `scripts/gpu/build-renderer.sh --driver-source mesa-source`. Every patch uses the MIT license of Mesa. As of Mesa `main` commit `22c08cc53`, upstream does not include a fix for any of these five defects.

Release reproducibility for `--driver-source mesa-source` depends on the pinned Homebrew toolchain versions in `ext/workers/gpu-renderer/third_party.lock`. Mesa links static archives or bitcode from `llvm`, `libclc`, `spirv-llvm-translator`, and `spirv-tools` into `libvulkan_kosmickrisp.dylib`. `scripts/gpu/build-renderer.sh` verifies `brew list --versions` against each `TOOLCHAIN.<formula>.version` pin before building and records the installed versions in `BUILDINFO`.

| Patch | File | Purpose |
| :--- | :--- | :--- |
| `0001-kk-restart-only-for-indexed-draws.patch` | `src/kosmickrisp/vulkan/kk_cmd_draw.c` | Enables `data->restart` only when `data->indexed` is true. Prevents non-indexed flat-shaded draws on the unroll path from dropping vertex 0. First bad upstream commit: `1388ec1b7`. |
| `0002-kk-hash-color-attachment-locations.patch` | `src/kosmickrisp/vulkan/kk_shader.c` | Adds `color_map`, `input_color_map`, and `input_color_attachment_count` to `struct kk_fs_key`. Copies `state->cal` and `state->ial` maps in `kk_populate_fs_key`. Prevents pipelines with different attachment locations from reusing the wrong cached fragment shader. First bad upstream commit: `59627d905`. |
| `0003-kk-scalarize-clip-cull-distance-inputs.patch` | `src/kosmickrisp/compiler/msl_nir_lower_common.c` | Extends `msl_nir_lower_clip_cull_distance` to scalarize `load_input` and `load_interpolated_input` on `nir_var_shader_in`. Fixes fragment reads of `gl_ClipDistance` and `gl_CullDistance` that previously returned element 0. |
| `0004-kk-relaxed-math-mode.patch` | `src/kosmickrisp/vulkan/kk_shader.c` | Compiles compute, vertex, and fragment Metal libraries with `MTL_MATH_MODE_RELAXED` instead of `MTL_MATH_MODE_FAST`. Preserves infinity and NaN arithmetic when SPIR-V omits `SignedZeroInfNanPreserve` (upstream issue 16920). |
| `0005-kk-max-viewport-dimensions.patch` | `src/kosmickrisp/vulkan/kk_physical_device.c` | Reports `maxViewportDimensions` as `{16384, 16384}` and `viewportBoundsRange` as `{-32768, 32767}`. Avoids empty draws at viewports of 28672 or larger while obeying the Vulkan bounds rule. |
