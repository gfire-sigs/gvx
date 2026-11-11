// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "restore",
		aliases: []string{"resume"},
		summary: "Restore and run a sandbox from a checkpoint bundle directory (alias: resume).",
		usage: []string{
			"rungv restore -dir=<dir> [flags]",
		},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return restoreSubcommand(ctx, args, streams.stdin, streams.stdout, streams.stderr)
		},
	})
}

// restoreConfig holds the parsed flags of `rungv restore`.
type restoreConfig struct {
	dir              string
	cfg              gvx.Config
	autoPlatform     bool
	checkpointSocket string
}

// parseRestoreArgs converts `rungv restore` arguments into a restoreConfig.
func parseRestoreArgs(args []string, stdin io.Reader, stdout, stderr io.Writer) (rc restoreConfig, exitCode int, done bool) {
	fs := flag.NewFlagSet("rungv restore", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageError := func(format string, a ...any) (restoreConfig, int, bool) {
		_, _ = fmt.Fprintf(stderr, "rungv restore: "+format+"\n", a...)
		return restoreConfig{}, 2, true
	}

	alias := func(names []string, define func(name string)) {
		for _, n := range names {
			define(n)
		}
	}

	dirFlag := fs.String("dir", "", "Checkpoint bundle directory")
	platformFlag := fs.String("platform", string(gvx.PlatformAuto), "Execution backend (auto, whpx, hvf, or systrap) or image platform (linux/amd64 or linux/arm64)")
	allowUnconfinedSystrapFlag := fs.Bool("allow-unconfined-systrap", false, "Allow -platform=auto on Windows to fall back to systrap when whpx is unavailable")
	archFlag := fs.String("arch", "", "Guest Linux architecture: amd64 or arm64 (defaults to checkpoint manifest)")
	var netFlag string
	alias([]string{"net", "network"}, func(n string) {
		fs.StringVar(&netFlag, n, "", "Network backend: nat (or bridge), wg, or none (defaults to checkpoint manifest)")
	})
	isolateLANFlag := fs.Bool("isolate-lan", false, "Block RFC1918 and loopback LAN destinations in NAT mode")
	privilegedFlag := fs.Bool("privileged", true, "Turn on --net-raw, --allow-packet-socket-write, and --allow-suid; --privileged=false turns them off")
	netRawFlag := fs.Bool("net-raw", true, "Allow raw sockets and iptables in the guest (default from --privileged)")
	packetWriteFlag := fs.Bool("allow-packet-socket-write", true, "Allow writes on AF_PACKET sockets; needs --net-raw (default from --privileged)")
	allowSUIDFlag := fs.Bool("allow-suid", true, "Obey the set-user-ID and set-group-ID bits of guest executables (default from --privileged)")
	wgConfFlag := fs.String("wg-conf", "", "Path to WireGuard INI configuration file")
	wgConfigAlias := fs.String("wg-config", "", "Alias for -wg-conf")
	imageFlag := fs.String("image", "", "Optional OCI image reference or archive path")
	binFlag := fs.String("bin", "", "Optional host path to a Linux ELF64 executable")
	var workspaceFlag string
	alias([]string{"workspace", "w"}, func(n string) {
		fs.StringVar(&workspaceFlag, n, "", "Host directory mounted at /workspace")
	})
	readOnlyFlag := fs.Bool("ro", false, "Mount /workspace read-only")
	workDirFlag := fs.String("workdir", "", "Guest working directory")
	cacheDirFlag := fs.String("cache-dir", "", "EROFS layer cache directory")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL")
	hostDNSFlag := addHostDNSFlag(fs)
	pullFlag := fs.String("pull", string(gvx.PullMissing), "Pull policy when -image is set: missing, always, or never")
	lockdownFlag := fs.Bool("lockdown", true, "Lock down the host process before guest entry; use -lockdown=false to opt out")
	ttyFlag := fs.Bool("t", false, "Allocate a pseudo-TTY for guest stdio")
	fs.Bool("i", false, "Keep STDIN open")
	itFlag := fs.Bool("it", false, "Allocate an interactive pseudo-TTY for guest stdio")
	detachFlag := fs.Bool("d", false, "Run in the background (not supported)")
	fs.Bool("rm", false, "Remove the container at exit")
	publishAllFlag := fs.Bool("P", false, "Publish every port that the image exposes to a free port of 127.0.0.1")

	var envFlags, envFileFlags listFlag
	alias([]string{"e", "env"}, func(n string) {
		fs.Var(&envFlags, n, "Set an environment variable: KEY=VALUE, or KEY to copy it from the host")
	})
	fs.Var(&envFileFlags, "env-file", "Read environment variables from a file")
	var userFlag string
	alias([]string{"u", "user"}, func(n string) { fs.StringVar(&userFlag, n, "", "Run as user[:group], by name or number") })
	var hostnameFlag string
	alias([]string{"h", "hostname"}, func(n string) { fs.StringVar(&hostnameFlag, n, "", "Guest hostname") })
	nameFlag := fs.String("name", "", "Container name")
	var memoryFlag string
	alias([]string{"m", "memory"}, func(n string) { fs.StringVar(&memoryFlag, n, "", "Memory limit, such as 512m or 1g") })
	cpusFlag := fs.String("cpus", "", "CPU quota, such as 1.5")
	hostCACertsFlag := fs.Bool("host-ca-certs", false, "Make the guest trust the root certificates that the host trusts")
	readOnlyRootFlag := fs.Bool("read-only", false, "Mount the root file system of the guest read-only")
	var volumeFlags, mountFlags, tmpfsFlags listFlag
	alias([]string{"v", "volume"}, func(n string) {
		fs.Var(&volumeFlags, n, "Mount a host directory, one host file, or a named volume (an ext4 image file): src:dst[:ro|rw]")
	})
	fs.Var(&mountFlags, "mount", "Mount with Docker syntax: type=bind|volume|tmpfs,src=...,dst=...,readonly[,driver=ext4lite|hostfs]")
	fs.Var(&tmpfsFlags, "tmpfs", "Mount a tmpfs: /path[:size=64m,ro]")

	tuneFlag := addTuneFlags(fs)

	var portSpecs multiStringFlag
	alias([]string{"p", "publish"}, func(n string) {
		fs.Var(&portSpecs, n, "Publish a container port: [ip:][hostPort:]guestPort[/proto]")
	})
	checkpointDirFlag := fs.String("checkpoint-dir", "", "Host directory pre-opened before lockdown for re-checkpoint output")
	checkpointSocketFlag := fs.String("checkpoint-socket", "", "Host path or loopback address for the checkpoint control listener")

	if err := fs.Parse(expandShortClusters(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return restoreConfig{}, 0, true
		}
		return restoreConfig{}, 2, true
	}
	if *detachFlag {
		return usageError("-d is not supported: rungv runs in the foreground and keeps no container after the guest exits")
	}
	if fs.NArg() > 0 {
		return usageError("unexpected positional arguments: %s", strings.Join(fs.Args(), " "))
	}

	dir := strings.TrimSpace(*dirFlag)
	if dir == "" {
		return usageError("specify -dir=<path>")
	}

	tuned, err := tuneFlag.values()
	if err != nil {
		return usageError("%v", err)
	}
	if _, err := gvx.ParseHostDNSServers(*hostDNSFlag); err != nil {
		return usageError("--host-dns: %v", err)
	}

	var portForwards []gvx.PortForward
	for _, spec := range portSpecs {
		pfs, err := gvx.ParsePortForwardsWith(spec, tuned)
		if err != nil {
			return usageError("%v", err)
		}
		portForwards = append(portForwards, pfs...)
	}

	var envv []string
	for _, path := range envFileFlags {
		entries, err := readEnvFile(path)
		if err != nil {
			return usageError("--env-file %s: %v", path, err)
		}
		envv = append(envv, entries...)
	}
	for _, entry := range envFlags {
		kv, ok, err := resolveEnvEntry(entry, os.LookupEnv)
		if err != nil {
			return usageError("-e: %v", err)
		}
		if ok {
			envv = append(envv, kv)
		}
	}

	var mounts []gvx.Mount
	for _, spec := range volumeFlags {
		m, err := gvx.ParseVolume(spec)
		if err != nil {
			return usageError("-v: %v", err)
		}
		mounts = append(mounts, m)
	}
	for _, spec := range mountFlags {
		m, err := gvx.ParseMount(spec)
		if err != nil {
			return usageError("--mount: %v", err)
		}
		mounts = append(mounts, m)
	}
	for _, spec := range tmpfsFlags {
		m, err := gvx.ParseTmpfs(spec)
		if err != nil {
			return usageError("--tmpfs: %v", err)
		}
		mounts = append(mounts, m)
	}

	var resources gvx.Resources
	if memoryFlag != "" {
		n, err := gvx.ParseMemory(memoryFlag)
		if err != nil {
			return usageError("-m: %v", err)
		}
		resources.MemoryBytes = n
	}
	if *cpusFlag != "" {
		n, err := gvx.ParseCPUs(*cpusFlag, runtime.NumCPU())
		if err != nil {
			return usageError("--cpus: %v", err)
		}
		resources.CPUMillis = n
	}

	backend, imageArch, err := splitPlatform(*platformFlag)
	if err != nil {
		return usageError("--platform: %v", err)
	}
	arch := strings.ToLower(strings.TrimSpace(*archFlag))
	if imageArch != "" {
		arch = imageArch
	}

	var netMode gvx.NetworkMode
	if strings.TrimSpace(netFlag) != "" {
		netMode, err = networkFor(netFlag)
		if err != nil {
			return usageError("--network: %v", err)
		}
	}

	pullPolicy, err := gvx.ParsePullPolicy(*pullFlag)
	if err != nil {
		return usageError("--pull: %q must be always, missing, or never", *pullFlag)
	}

	wgConfPath := strings.TrimSpace(*wgConfFlag)
	if wgConfPath == "" {
		wgConfPath = strings.TrimSpace(*wgConfigAlias)
	}

	priv := resolvePrivileges(fs, *privilegedFlag, *netRawFlag, *packetWriteFlag, *allowSUIDFlag)

	cfg := gvx.Config{
		Platform:               backend,
		AllowUnconfinedSystrap: *allowUnconfinedSystrapFlag,
		Architecture:           arch,
		NetworkMode:            netMode,
		IsolateLAN:             *isolateLANFlag,
		HostDNSServers:         *hostDNSFlag,
		NetRaw:                 priv.netRaw,
		AllowPacketSocketWrite: priv.packetWrite,
		AllowSUID:              priv.allowSUID,
		PortForwards:           portForwards,
		PublishAll:             *publishAllFlag,
		WireGuardConfigPath:    wgConfPath,
		OCIImage:               strings.TrimSpace(*imageFlag),
		OCICacheDir:            strings.TrimSpace(*cacheDirFlag),
		RegistryBaseURL:        strings.TrimSpace(*registryURLFlag),
		PullPolicy:             pullPolicy,
		Warnings:               stderr,
		BinaryPath:             strings.TrimSpace(*binFlag),
		WorkspacePath:          strings.TrimSpace(workspaceFlag),
		WorkspaceReadOnly:      *readOnlyFlag,
		Mounts:                 mounts,
		ReadOnlyRoot:           *readOnlyRootFlag,
		HostCACerts:            *hostCACertsFlag,
		WorkDir:                strings.TrimSpace(*workDirFlag),
		Envv:                   envv,
		User:                   strings.TrimSpace(userFlag),
		Hostname:               strings.TrimSpace(hostnameFlag),
		Name:                   strings.TrimSpace(*nameFlag),
		Resources:              resources,
		Tuning:                 tuned,
		Stdin:                  stdin,
		Stdout:                 stdout,
		Stderr:                 stderr,
		TTY:                    *ttyFlag || *itFlag,
		DisableHostLockdown:    !*lockdownFlag,
		CheckpointDir:          strings.TrimSpace(*checkpointDirFlag),
	}
	return restoreConfig{
		dir:              dir,
		cfg:              cfg,
		autoPlatform:     backend == gvx.PlatformAuto,
		checkpointSocket: strings.TrimSpace(*checkpointSocketFlag),
	}, 0, false
}

func restoreSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	rc, exitCode, done := parseRestoreArgs(args, stdin, stdout, stderr)
	if done {
		return exitCode
	}

	cleanCkptDir, absCkptDir := resolveCheckpointDirs(rc.cfg.CheckpointDir)
	var cleanupSocket func()
	if rc.checkpointSocket != "" {
		ln, sockCleanup, err := listenCheckpointSocket(rc.checkpointSocket)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "rungv restore: listen checkpoint socket: %v\n", err)
			return 1
		}
		rc.cfg.CheckpointListener = ln
		cleanupSocket = sockCleanup
	}
	if cleanupSocket != nil {
		defer cleanupSocket()
	}

	sb, err := gvx.Restore(ctx, rc.cfg, gvx.RestoreOptions{Dir: rc.dir})
	if err != nil {
		if rc.cfg.CheckpointListener != nil {
			_ = rc.cfg.CheckpointListener.Close()
		}
		_, _ = fmt.Fprintf(stderr, "rungv restore: %v\n", err)
		if errors.Is(err, gvx.ErrInvalidConfig) {
			return 2
		}
		return 1
	}
	defer func() {
		_ = sb.Close()
	}()
	stopControl := startCheckpointControl(ctx, sb, rc.cfg.CheckpointListener, cleanCkptDir, absCkptDir)
	defer stopControl()

	if rc.autoPlatform {
		_, _ = fmt.Fprintf(stderr, "rungv: platform=%s\n", sb.PlatformName())
		if reason := sb.FallbackReason(); reason != "" {
			_, _ = fmt.Fprintf(stderr, "rungv: warning: the hardware hypervisor is not available, so the guest runs on %s, which is slower: %s\n", sb.PlatformName(), reason)
		}
	}
	if !sb.SecurityPosture().HardwareOrKernelSyscallIsolation {
		_, _ = fmt.Fprintln(stderr, "rungv: warning: Windows systrap lacks hardware or kernel syscall isolation; use whpx for untrusted workloads")
	}
	if rc.cfg.DisableHostLockdown {
		_, _ = fmt.Fprintln(stderr, "rungv: warning: host lockdown disabled")
	}
	reportPublishedPorts(stderr, sb)
	if rc.cfg.Resources.CPUMillis > 0 && !sb.Limits().CPUTime {
		_, _ = fmt.Fprintf(stderr, "rungv: warning: --cpus sets the number of CPUs that the guest sees; this host does not cap the CPU time\n")
	}

	exitCode, err = sb.Run(ctx)
	stopControl()
	if errors.Is(err, gvx.ErrMemoryLimit) {
		_, _ = fmt.Fprintf(stderr, "rungv: the guest was killed: it passed the memory limit of %d bytes\n", rc.cfg.Resources.MemoryBytes)
		return exitCode
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv restore: %v\n", err)
		if exitCode == 0 {
			return 1
		}
		return exitCode
	}
	return exitCode
}
