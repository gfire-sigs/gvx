# Pinned `virglrenderer` Patches

These patches apply to the pinned `virglrenderer` checkout (`211ca6e3ac98a2c1`) during `scripts/gpu/build-renderer.sh`. Every patch uses the MIT license of `virglrenderer` and is a candidate for upstream submission.

| Patch | Purpose |
| :--- | :--- |
| `0001-vrend-strip-core-desktop-extensions.patch` | Drops `#extension GL_<name> : require\|enable` lines for features core in the host desktop GLSL version when the host omits those extension strings (Apple OpenGL 4.1 core), and raises the desktop `#version` line to match. |
| `0002-vrend-multisample-without-storage.patch` | Uses `glTexImage2DMultisample` on desktop GL hosts that support `GL_ARB_texture_storage` without `GL_ARB_texture_storage_multisample`, populating `supported_multisample_formats` and guarding multisample texture allocation. |
