# Android Host Runtime and Library Packaging: `android/` and `tools/androidprobe`

This specification describes the Android runtime deliverable (`gvx-android.aar`), its Java entry point (`dev.gfire.gvx.Gvx`), its sample foreground service (`android/sample`), and the device capability probe (`tools/androidprobe`). Android runs `gvx` on `android/arm64` (and `android/amd64` in CI emulators) using the Linux `systrap` backend.

---

## 1. Purpose and Scope

Unprivileged Android applications (`untrusted_app` SELinux domain) cannot open `/dev/kvm`, cannot execute binaries downloaded into writable app directories (`app_data_file`, enforced by Android 10+ SELinux W^X), and lack `/etc/resolv.conf`. Packaging `cmd/rungv` as a native shared library (`librungv.so`) inside an Android archive (`gvx-android.aar`) allows Android applications to launch isolated Linux containers and ELF64 binaries without root access.

---

## 2. Design and Invariants

Android packaging spans three layers: NDK compilation into a native library, Java process launching with DNS discovery, and kernel-level `systrap` adaptations.

### 2.1 Library Packaging (`scripts/android/build-sdk.sh`)

`scripts/android/build-sdk.sh` cross-compiles `cmd/rungv` with the Android NDK (`GOOS=android`, `CGO_ENABLED=1`, `GOARM64=v8.0`, PIE mode) and packages two artifacts:

1. **`gvx-android.aar`** (`minSdkVersion 31`): Contains `AndroidManifest.xml` (requesting `INTERNET` and `ACCESS_NETWORK_STATE`), `classes.jar` (`dev.gfire.gvx.Gvx`), and `jni/arm64-v8a/librungv.so`.
2. **`gvx-sample.apk`**: A debug-signed sample application demonstrating foreground-service execution (`dev.gfire.gvx.sample.RunService`), aligned with `zipalign -P 16` and setting `android:extractNativeLibs="true"` so PackageManager extracts `librungv.so` into the immutable, executable `ApplicationInfo.nativeLibraryDir` (`apk_data_file` SELinux label).

### 2.2 Java Launcher and DNS Injection (`dev.gfire.gvx.Gvx`)

`Gvx.start(Context ctx, List<String> args)` constructs a `ProcessBuilder` targeting `<nativeLibraryDir>/librungv.so`:

- Sets `HOME` to `ctx.getFilesDir()` and both `XDG_CACHE_HOME` and `TMPDIR` to `ctx.getCacheDir()`.
- For commands that resolve remote names (`run`, `pull`), queries `ConnectivityManager.getActiveNetwork()` and `LinkProperties.getDnsServers()`, skips link-local IPv6 addresses requiring zone IDs, and prepends `--host-dns <ip>` flags before passing remaining arguments.
- Returns the running `java.lang.Process` so callers consume stdout, stderr, and the exit code directly while the child Sentry enforces host lockdown.

`android/sample/.../RunService.java` executes commands sequentially inside an Android 14+ `FOREGROUND_SERVICE_TYPE_SPECIAL_USE` foreground service so Android does not throttle or kill long-running guest workloads when the user switches apps.

### 2.3 Kernel and `systrap` Adaptations on Android

Inside `librungv.so`, four runtime adaptations accommodate Android kernel policies:

- **Executable stub memory**: Allocates stub memory with `memfd_create(MFD_EXEC)` and probes `vm.mmap_min_addr` (`0x8000`) via `MAP_FIXED_NOREPLACE`.
- **16 KiB page support**: Activates `platform/systrap/subblock_xplat.go` automatically on 16 KiB ARM64 kernels, preserving 4 KiB Linux guest pages across 16 KiB host mappings.
- **Process budget clamping**: Caps `idleStubLimit` and `maxSysmsgThreads` to `2` per stub so ordinary sandboxes stay well below Android 12+'s system-wide 32-child-process ceiling.
- **Zygote seccomp compatibility**: `pkg/hostlockdown` detects `PR_GET_SECCOMP == 2`, skips Landlock syscalls trapped by Zygote with `SIGSYS`, and relies on per-UID SELinux and mount-namespace confinement.

---

## 3. Verification and Capability Probing

`.github/workflows/android.yml` executes `scripts/android/emulator-smoke.sh` on an x86-64 Android 16 KVM emulator, running `tools/androidprobe` (reporting kernel page size, `memfd`, seccomp, and `systrap` readiness), unit tests for `systrap`, `hostfs`, and `ext4lite`, the offline `e2e/` suite, and an end-to-end launch of `gvx-sample.apk` via `adb shell am start-foreground-service`. Because hosted runners lack nested ARM64 virtualization, `arm64` emulator runs are executed manually on physical ARM64 hosts.

---

## 4. Known Limits

- **32 phantom-process ceiling**: Android 12 and newer terminate the oldest child processes once total child processes across all apps exceed 32. Because each live guest address space uses one stub process plus up to two `sysmsg` processes, keep concurrent guest processes below 10 or disable child process restrictions (see [`../cli.md`](../cli.md#12-android-operation)).
- **Background CPU throttling**: Android kills background app child processes consuming sustained CPU; run long workloads from a foreground service.
- **SELinux hard-link restriction**: `linkat` hard links fail with `EACCES` on app-data files under `hostfs`; use `ext4lite` volumes (`-v data:/data`) when guests require hard links.
- **Landlock unavailable under Zygote**: `Status.UnboundFileOpenBlocked` remains false when a host bind mount is attached on Android (sandboxes using only `ext4lite` volumes keep it true).

---

## 5. Implementation Map

| Files | Role |
| :--- | :--- |
| `android/library/src/dev/gfire/gvx/Gvx.java` | Java launcher locating `librungv.so`, configuring app storage env vars, and injecting `--host-dns`. |
| `android/sample/AndroidManifest.xml`, `android/sample/src/dev/gfire/gvx/sample/RunService.java` | Sample `specialUse` foreground service invoking `Gvx.start` and logging to `files/run.log` and logcat. |
| `scripts/android/build-sdk.sh`, `scripts/android/lib.sh`, `scripts/android/emulator-smoke.sh` | NDK build scripts for `gvx-android.aar` and `gvx-sample.apk`, plus the CI emulator smoke runner. |
| `tools/androidprobe/` | Standalone Android kernel page-size, `memfd`, seccomp, and `systrap` probe tool. |
| `pkg/gvx/enginefault_android.go`, `pkg/sentry/platform/systrap/subblock_xplat.go`, `pkg/sentry/platform/systrap/hostpage_xplat.go` | Android diagnostic messages, 16 KiB sub-block paging, and 2-stub idle pool cap. |
