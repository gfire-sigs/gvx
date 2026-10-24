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
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
)

func init() {
	register(command{
		name:    "run",
		summary: "Run a command in an OCI image or a Linux ELF64 binary inside the sandbox.",
		usage: []string{
			"rungv run [flags] -image=<oci-image> [-- command args...]",
			"rungv run [flags] -bin=<linux-elf64>",
		},
		run: func(ctx context.Context, args []string, streams cliIO) int {
			return runSubcommand(ctx, args, streams.stdin, streams.stdout, streams.stderr)
		},
	})
}

// multiStringFlag collects a repeatable flag and splits each value at commas.
type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(val string) error {
	for _, part := range strings.Split(val, ",") {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			*m = append(*m, trimmed)
		}
	}
	return nil
}

// listFlag collects a repeatable flag and keeps each value whole.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, " ") }

func (l *listFlag) Set(val string) error {
	*l = append(*l, val)
	return nil
}

// runConfig is the parsed result of `rungv run` arguments.
type runConfig struct {
	cfg gvx.Config
	// autoPlatform reports that the user left the backend selection to gvx.
	autoPlatform bool
}

// shortBoolFlags are the one-letter flags that Docker lets a user cluster, as in -it.
const shortBoolFlags = "itdP"

// expandShortClusters splits a cluster of one-letter boolean flags such as
// "-itd" into "-i", "-t", and "-d". The standard flag package does not cluster.
// It leaves every other argument alone, and it stops at "--" and at the first
// argument that is not a flag, because the rest belongs to the guest.
func expandShortClusters(args []string) []string {
	out := make([]string, 0, len(args))
	for i, a := range args {
		if a == "--" || !strings.HasPrefix(a, "-") {
			return append(out, args[i:]...)
		}
		if len(a) > 2 && a[1] != '-' && strings.Trim(a[1:], shortBoolFlags) == "" {
			for _, c := range a[1:] {
				out = append(out, "-"+string(c))
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

// splitPlatform tells a Docker image platform ("linux/arm64") from a gvx
// execution backend ("systrap"). A value with a slash is an image platform.
func splitPlatform(v string) (backend gvx.PlatformType, arch string, err error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if !strings.Contains(v, "/") {
		return gvx.PlatformType(v), "", nil
	}
	parts := strings.Split(v, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "linux" || (parts[1] != "amd64" && parts[1] != "arm64") {
		return "", "", fmt.Errorf("unsupported image platform %q (want linux/amd64 or linux/arm64)", v)
	}
	return gvx.PlatformAuto, parts[1], nil
}

// networkFor maps a Docker network name to a gvx network mode.
func networkFor(v string) (gvx.NetworkMode, error) {
	switch v = strings.ToLower(strings.TrimSpace(v)); v {
	case "bridge", "default":
		return gvx.NetModeNAT, nil
	case "host", "container":
		return "", fmt.Errorf("network %q is not available: the guest has its own network stack", v)
	}
	return gvx.NetworkMode(v), nil
}

// parseRunArgs converts `rungv run` arguments into a gvx.Config. It returns
// the process exit code when the arguments end the command without a run.
func parseRunArgs(args []string, stdin io.Reader, stdout, stderr io.Writer) (rc runConfig, exitCode int, done bool) {
	fs := flag.NewFlagSet("rungv run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	usageError := func(format string, a ...any) (runConfig, int, bool) {
		_, _ = fmt.Fprintf(stderr, "rungv run: "+format+"\n", a...)
		return runConfig{}, 2, true
	}

	// alias registers one variable under a long and a short flag name.
	alias := func(names []string, define func(name string)) {
		for _, n := range names {
			define(n)
		}
	}

	platformFlag := fs.String("platform", string(gvx.PlatformAuto), "Execution backend (auto, whpx, hvf, or systrap) or image platform (linux/amd64 or linux/arm64)")
	archFlag := fs.String("arch", runtime.GOARCH, "Guest Linux architecture: amd64 or arm64")
	var netFlag string
	alias([]string{"net", "network"}, func(n string) {
		fs.StringVar(&netFlag, n, string(gvx.NetModeNAT), "Network backend: nat (or bridge), wg, or none")
	})
	isolateLANFlag := fs.Bool("isolate-lan", false, "Block RFC1918 and loopback LAN destinations in NAT mode")
	wgConfFlag := fs.String("wg-conf", "", "Path to WireGuard INI configuration file")
	wgConfigAlias := fs.String("wg-config", "", "Alias for -wg-conf")
	imageFlag := fs.String("image", "", "OCI image reference or archive path")
	binFlag := fs.String("bin", "", "Host path to a Linux ELF64 executable")
	workspaceFlag := fs.String("workspace", "", "Host directory mounted at /workspace")
	readOnlyFlag := fs.Bool("ro", false, "Mount /workspace read-only")
	var workDirFlag string
	alias([]string{"workdir", "w"}, func(n string) {
		fs.StringVar(&workDirFlag, n, "", "Initial guest working directory")
	})
	cacheDirFlag := fs.String("cache-dir", "", "EROFS layer cache directory")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL")
	lockdownFlag := fs.Bool("lockdown", true, "Lock down the host process before guest entry (RestrictedToken and JobObject, or Seatbelt); use -lockdown=false to opt out")
	elfCheckFlag := fs.Bool("elf-check", true, "Refuse an executable whose segments do not fit the guest page size, and name the segment; use -elf-check=false to opt out")
	ttyFlag := fs.Bool("t", false, "Allocate a pseudo-TTY for guest stdio")
	fs.Bool("i", false, "Keep STDIN open (the guest always reads the standard input of rungv)")
	itFlag := fs.Bool("it", false, "Allocate an interactive pseudo-TTY for guest stdio")
	detachFlag := fs.Bool("d", false, "Run in the background (not supported: a run has no daemon)")
	fs.Bool("rm", false, "Remove the container at exit (every run does this)")
	publishAllFlag := fs.Bool("P", false, "Publish every port that the image exposes to a free port of 127.0.0.1")

	var envFlags, envFileFlags listFlag
	alias([]string{"e", "env"}, func(n string) {
		fs.Var(&envFlags, n, "Set an environment variable: KEY=VALUE, or KEY to copy it from the host")
	})
	fs.Var(&envFileFlags, "env-file", "Read environment variables from a file")
	entrypointFlag := fs.String("entrypoint", "", "Replace the image entrypoint; an empty value clears it")
	var userFlag string
	alias([]string{"u", "user"}, func(n string) { fs.StringVar(&userFlag, n, "", "Run as user[:group], by name or number") })
	var hostnameFlag string
	alias([]string{"h", "hostname"}, func(n string) { fs.StringVar(&hostnameFlag, n, "", "Guest hostname") })
	nameFlag := fs.String("name", "", "Container name")
	var memoryFlag string
	alias([]string{"m", "memory"}, func(n string) { fs.StringVar(&memoryFlag, n, "", "Memory limit, such as 512m or 1g") })
	cpusFlag := fs.String("cpus", "", "CPU quota, such as 1.5")
	readOnlyRootFlag := fs.Bool("read-only", false, "Mount the root file system of the guest read-only")
	var volumeFlags, mountFlags, tmpfsFlags listFlag
	alias([]string{"v", "volume"}, func(n string) {
		fs.Var(&volumeFlags, n, "Mount a host directory or a named volume (an ext4 image file): src:dst[:ro|rw]")
	})
	fs.Var(&mountFlags, "mount", "Mount with Docker syntax: type=bind|volume|tmpfs,src=...,dst=...,readonly[,driver=ext4lite|hostfs]")
	fs.Var(&tmpfsFlags, "tmpfs", "Mount a tmpfs: /path[:size=64m,ro]")

	var portSpecs multiStringFlag
	alias([]string{"p", "publish"}, func(n string) {
		fs.Var(&portSpecs, n, "Publish a container port: [ip:][hostPort:]guestPort[/proto]")
	})

	if err := fs.Parse(expandShortClusters(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return runConfig{}, 0, true
		}
		return runConfig{}, 2, true
	}
	if *detachFlag {
		return usageError("-d is not supported: rungv runs in the foreground and keeps no container after the guest exits")
	}

	remaining := fs.Args()
	if len(remaining) > 0 && remaining[0] == "--" {
		remaining = remaining[1:]
	}

	imageRef := strings.TrimSpace(*imageFlag)
	binPath := strings.TrimSpace(*binFlag)
	guestArgs := remaining

	// If neither -image nor -bin was set, treat the first positional argument
	// as an ELF binary path (if it exists on the host with an ELF header) or
	// an OCI image reference.
	if imageRef == "" && binPath == "" && len(guestArgs) > 0 {
		first := guestArgs[0]
		if isHostELFFile(first) {
			binPath = first
		} else {
			imageRef = first
		}
		guestArgs = guestArgs[1:]
	}

	if imageRef == "" && binPath == "" {
		return usageError("specify -image=<image>, -bin=<elf>, or a positional target")
	}

	var portForwards []gvx.PortForward
	for _, spec := range portSpecs {
		pf, err := gvx.ParsePortForward(spec)
		if err != nil {
			return usageError("%v", err)
		}
		portForwards = append(portForwards, pf)
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
	netMode, err := networkFor(netFlag)
	if err != nil {
		return usageError("--network: %v", err)
	}

	wgConfPath := strings.TrimSpace(*wgConfFlag)
	if wgConfPath == "" {
		wgConfPath = strings.TrimSpace(*wgConfigAlias)
	}

	cfg := gvx.Config{
		Platform:            backend,
		Architecture:        arch,
		NetworkMode:         netMode,
		IsolateLAN:          *isolateLANFlag,
		PortForwards:        portForwards,
		PublishAll:          *publishAllFlag,
		WireGuardConfigPath: wgConfPath,
		OCIImage:            imageRef,
		OCICacheDir:         strings.TrimSpace(*cacheDirFlag),
		RegistryBaseURL:     strings.TrimSpace(*registryURLFlag),
		BinaryPath:          binPath,
		WorkspacePath:       strings.TrimSpace(*workspaceFlag),
		WorkspaceReadOnly:   *readOnlyFlag,
		Mounts:              mounts,
		ReadOnlyRoot:        *readOnlyRootFlag,
		WorkDir:             strings.TrimSpace(workDirFlag),
		Envv:                envv,
		User:                strings.TrimSpace(userFlag),
		Hostname:            strings.TrimSpace(hostnameFlag),
		Name:                strings.TrimSpace(*nameFlag),
		Resources:           resources,
		Stdin:               stdin,
		Stdout:              stdout,
		Stderr:              stderr,
		TTY:                 *ttyFlag || *itFlag,
		DisableHostLockdown: !*lockdownFlag,
	}
	cfg.DisableELFLayoutCheck = !*elfCheckFlag
	if len(guestArgs) > 0 {
		if binPath != "" {
			// A bare ELF has no image command: the arguments are the whole vector.
			cfg.Argv = guestArgs
		} else {
			// For an image, the arguments replace the image Cmd and keep the image Entrypoint.
			cfg.Cmd = guestArgs
		}
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "entrypoint" {
			cfg.EntrypointSet = true
			if *entrypointFlag != "" {
				cfg.Entrypoint = []string{*entrypointFlag}
			}
		}
	})
	return runConfig{autoPlatform: backend == gvx.PlatformAuto, cfg: cfg}, 0, false
}

// readEnvFile reads and parses one env file against the host environment.
func readEnvFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	entries, parseErr := parseEnvFile(f, os.LookupEnv)
	return entries, errors.Join(parseErr, f.Close())
}

func runSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	rc, exitCode, done := parseRunArgs(args, stdin, stdout, stderr)
	if done {
		return exitCode
	}

	sb, err := gvx.New(ctx, rc.cfg)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv run: init sandbox: %v\n", err)
		if errors.Is(err, gvx.ErrInvalidConfig) {
			return 2
		}
		return 1
	}
	defer func() {
		_ = sb.Close()
	}()
	if rc.autoPlatform {
		_, _ = fmt.Fprintf(stderr, "rungv: platform=%s\n", sb.PlatformName())
	}
	if rc.cfg.DisableHostLockdown {
		_, _ = fmt.Fprintln(stderr, "rungv: warning: host lockdown disabled")
	}
	reportPublishedPorts(stderr, sb)
	if rc.cfg.Resources.CPUMillis > 0 && !sb.Limits().CPUTime {
		_, _ = fmt.Fprintf(stderr, "rungv: warning: --cpus sets the number of CPUs that the guest sees; this host does not cap the CPU time\n")
	}

	exitCode, err = sb.Run(ctx)
	if errors.Is(err, gvx.ErrMemoryLimit) {
		_, _ = fmt.Fprintf(stderr, "rungv: the guest was killed: it passed the memory limit of %d bytes\n", rc.cfg.Resources.MemoryBytes)
		return exitCode
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv run: %v\n", err)
		if exitCode == 0 {
			return 1
		}
		return exitCode
	}
	return exitCode
}

// reportPublishedPorts tells the user which host port serves each guest port,
// because a free port that the host picked is not known to the user.
func reportPublishedPorts(w io.Writer, sb *gvx.Sandbox) {
	for _, p := range sb.PublishedPorts() {
		_, _ = fmt.Fprintf(w, "rungv: publishing %s -> %d/%s\n", net.JoinHostPort(p.HostAddr, strconv.Itoa(int(p.HostPort))), p.GuestPort, p.Protocol)
	}
}

func isHostELFFile(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer func() {
		_ = f.Close()
	}()
	var hdr [5]byte
	if _, err := io.ReadFull(f, hdr[:]); err != nil {
		return false
	}
	return hdr[0] == 0x7f && hdr[1] == 'E' && hdr[2] == 'L' && hdr[3] == 'F' && hdr[4] == 2
}
