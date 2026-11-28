# Android Host Runtime and Library Packaging: `android/` and `tools/androidprobe`

This specification describes `gvx-android.aar`, its Java launcher (`dev.gfire.gvx.Gvx`), its sample service (`android/sample`), and the capability probe (`tools/androidprobe`). Android executes `gvx` on `android/arm64` (and `android/amd64` in CI emulators) using Linux `systrap`.

---

## 1. Purpose and Scope

Unprivileged Android apps (`untrusted_app`) cannot open `/dev/kvm`, lack `/etc/resolv.conf`, and cannot execute binaries downloaded into writable app directories under SELinux W^X. Copying standard Linux CLI installers onto Android fails at `execve` or DNS resolution.

`scripts/android/build-sdk.sh` compiles `cmd/rungvx` into `jni/arm64-v8a/librungvx.so` inside `gvx-android.aar`, so PackageManager extracts it into the executable `apk_data_file` library directory. The Java wrapper passes app-private storage directories and active `--host-dns` resolvers before Sentry self-lockdown begins.

The sections below document library packaging, DNS injection, `systrap` adaptations, emulator verification, and Android-specific limits.

---

## 2. Design and Invariants

Android packaging spans three layers: NDK compilation into a native library, Java launching with DNS injection, and kernel-level `systrap` adaptations.

### 2.1 Library Packaging (`scripts/android/build-sdk.sh`)

`scripts/android/build-sdk.sh` cross-compiles `cmd/rungvx` with the Android NDK (`GOOS=android`, `CGO_ENABLED=1`, `GOARM64=v8.0`, PIE mode) and builds two artifacts:

1. **`gvx-android.aar`** (`minSdkVersion 31`): Bundles `AndroidManifest.xml` (`INTERNET`, `ACCESS_NETWORK_STATE`), `classes.jar` (`dev.gfire.gvx.Gvx`), and `jni/arm64-v8a/librungvx.so`.
2. **`gvx-sample.apk`**: Debug-signed foreground-service demo (`RunService`) aligned with `zipalign -P 16`. Setting `android:extractNativeLibs="true"` extracts `librungvx.so` into the executable `ApplicationInfo.nativeLibraryDir`.

### 2.2 Java Launcher and DNS Injection (`dev.gfire.gvx.Gvx`)

`Gvx.start(Context ctx, List<String> args)` builds a `ProcessBuilder` targeting `<nativeLibraryDir>/librungvx.so`:

- **App-private storage env**: Sets `HOME` to `ctx.getFilesDir()` and sets `XDG_CACHE_HOME` and `TMPDIR` to `ctx.getCacheDir()`. Named volumes default to `ctx.getFilesDir()/.local/share/gvx/volumes`, and named control sockets resolve under `TMPDIR/gvx-run` because Android lacks `/tmp`. Set `XDG_DATA_HOME` or `GVX_VOLUME_DIR` to `ctx.getNoBackupFilesDir()` to exclude large volumes from Android Auto Backup.
- **Active DNS injection**: For `run` and `pull`, reads `LinkProperties.getDnsServers()`, skips link-local IPv6 addresses, and prepends `--host-dns <ip>`.
- **Process streaming**: Returns `java.lang.Process` so callers consume stdout, stderr, and exit codes while `librungvx.so` applies host lockdown.

`android/sample/.../RunService.java` executes commands sequentially inside an Android 14+ `FOREGROUND_SERVICE_TYPE_SPECIAL_USE` foreground service to prevent background throttling.

### 2.3 Kernel and `systrap` Adaptations on Android

Inside `librungvx.so`, four runtime adaptations accommodate Android kernel and SELinux policies:

- **Executable stub memory**: Allocates stub memory with `memfd_create(MFD_EXEC)` and probes `vm.mmap_min_addr` (`0x8000`) via `MAP_FIXED_NOREPLACE`.
- **16 KiB page support**: Enables `platform/systrap/subblock_xplat.go` on 16 KiB ARM64 kernels, preserving 4 KiB guest pages over 16 KiB host mappings.
- **Process budget clamping**: Caps `idleStubLimit` and `maxSysmsgThreads` at `2` per stub so sandboxes stay below Android's 32-child ceiling.
- **Zygote seccomp compatibility**: `pkg/hostlockdown` detects `PR_GET_SECCOMP == 2`, skips Landlock calls trapped with `SIGSYS`, and relies on SELinux and mount namespaces.

---

## 3. Verification and Capability Probing

`.github/workflows/android.yml` executes `scripts/android/emulator-smoke.sh` on an x86-64 Android 16 KVM emulator. It runs `tools/androidprobe`, unit tests for `systrap`, `hostfs`, and `ext4lite`, offline `e2e/`, and `gvx-sample.apk` via `adb shell am start-foreground-service`. Physical ARM64 hosts verify `arm64` emulator behavior manually because hosted runners lack nested ARM64 virtualization.

---

## 4. Component Limits

Consult [`../compatibility.md`](../compatibility.md) and [`../cli.md`](../cli.md#12-android-operation) for host-wide limits and `adb` overrides; Android-specific invariants follow:

- **32 phantom-process ceiling**: Android 12+ terminates child processes when total app children exceed 32. Keep concurrent guest processes below 10 or disable child restrictions.
- **Background CPU throttling**: Android kills background app child processes consuming sustained CPU; run long workloads from a foreground service.
- **SELinux hard-link restriction**: `linkat` fails with `EACCES` on app-data files under `hostfs`; use `ext4lite` volumes (`-v data:/data`) for hard links.
- **Landlock unavailable under Zygote**: `Status.UnboundFileOpenBlocked` stays false when attaching host bind mounts on Android (`ext4lite`-only runs keep it true).

---

## 5. Implementation Map

This table maps the Android runtime, sample app, build scripts, and kernel probe files.

| Files | Role |
| :--- | :--- |
| `android/library/src/dev/gfire/gvx/Gvx.java` | Java launcher locating `librungvx.so`, setting app storage vars, and injecting `--host-dns`. |
| `android/sample/AndroidManifest.xml`, `android/sample/src/dev/gfire/gvx/sample/RunService.java` | Sample `specialUse` foreground service invoking `Gvx.start` and logging to `files/run.log`. |
| `scripts/android/build-sdk.sh`, `scripts/android/lib.sh`, `scripts/android/emulator-smoke.sh` | NDK build scripts for `gvx-android.aar` and `gvx-sample.apk`, plus CI smoke runner. |
| `tools/androidprobe/` | Standalone Android kernel page-size, `memfd`, seccomp, and `systrap` probe tool. |
| `pkg/gvx/enginefault_android.go`, `pkg/sentry/platform/systrap/subblock_xplat.go`, `pkg/sentry/platform/systrap/hostpage_xplat.go` | Android diagnostic messages, 16 KiB sub-block paging, and 2-stub idle pool cap. |
