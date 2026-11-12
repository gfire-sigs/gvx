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
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

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

// shortBoolFlags are the one-letter flags that Docker lets a user cluster, as in -it.
const shortBoolFlags = "itdP"

// expandShortClusters splits a cluster of one-letter boolean flags such as
// "-itd" into "-i", "-t", and "-d". It stops at "--" and at the first
// argument that does not start with a hyphen.
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

// splitPlatform separates a Docker image platform ("linux/arm64") from a gvx
// execution backend ("systrap"). A value with a slash names an image platform.
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

// flagDefaults configures the subcommand-specific flag defaults and aliases
// shared between `rungv run` and `rungv restore`.
type flagDefaults struct {
	archDefault        string
	netDefault         string
	shortWForWorkspace bool
	includeEntrypoint  bool
}

// sandboxFlagValues holds raw flag values bound to a FlagSet before validation.
type sandboxFlagValues struct {
	platform               string
	allowUnconfinedSystrap bool
	arch                   string
	net                    string
	isolateLAN             bool
	privileged             bool
	netRaw                 bool
	packetWrite            bool
	allowSUID              bool
	wgConf                 string
	wgConfigAlias          string
	image                  string
	bin                    string
	workspace              string
	readOnly               bool
	workDir                string
	cacheDir               string
	registryURL            string
	hostDNS                *multiStringFlag
	pull                   string
	lockdown               bool
	tty                    bool
	it                     bool
	detach                 bool
	publishAll             bool
	envFlags               listFlag
	envFileFlags           listFlag
	entrypoint             string
	user                   string
	hostname               string
	name                   string
	memory                 string
	cpus                   string
	hostCACerts            bool
	readOnlyRoot           bool
	volumeFlags            listFlag
	mountFlags             listFlag
	tmpfsFlags             listFlag
	tune                   *tuneFlags
	portSpecs              multiStringFlag
	checkpointDir          string
	controlSocket          string
}

// registerAlias binds a registration callback to each flag name in names.
func registerAlias(names []string, define func(name string)) {
	for _, n := range names {
		define(n)
	}
}

// registerSandboxFlags binds all sandbox CLI flags onto fs and returns their raw value holders.
func registerSandboxFlags(fs *flag.FlagSet, defs flagDefaults) *sandboxFlagValues {
	f := &sandboxFlagValues{}
	f.registerPlatformAndNetFlags(fs, defs)
	f.registerTargetAndMountFlags(fs, defs)
	f.registerIdentityAndEnvFlags(fs, defs)
	f.registerResourceAndCheckpointFlags(fs)
	return f
}

func (f *sandboxFlagValues) registerPlatformAndNetFlags(fs *flag.FlagSet, defs flagDefaults) {
	fs.StringVar(&f.platform, "platform", string(gvx.PlatformAuto), "Execution backend (auto, whpx, hvf, or systrap) or image platform (linux/amd64 or linux/arm64)")
	fs.BoolVar(&f.allowUnconfinedSystrap, "allow-unconfined-systrap", false, "Allow -platform=auto on Windows to fall back to systrap when whpx is unavailable")
	fs.StringVar(&f.arch, "arch", defs.archDefault, "Guest Linux architecture: amd64 or arm64")
	registerAlias([]string{"net", "network"}, func(n string) {
		fs.StringVar(&f.net, n, defs.netDefault, "Network backend: nat (or bridge), wg, or none")
	})
	fs.BoolVar(&f.isolateLAN, "isolate-lan", false, "Block RFC1918 and loopback LAN destinations in NAT mode")
	fs.BoolVar(&f.privileged, "privileged", true, "Turn on --net-raw, --allow-packet-socket-write, and --allow-suid; --privileged=false turns them off")
	fs.BoolVar(&f.netRaw, "net-raw", true, "Allow raw sockets and iptables in the guest (default from --privileged)")
	fs.BoolVar(&f.packetWrite, "allow-packet-socket-write", true, "Allow writes on AF_PACKET sockets; needs --net-raw (default from --privileged)")
	fs.BoolVar(&f.allowSUID, "allow-suid", true, "Obey the set-user-ID and set-group-ID bits of guest executables (default from --privileged)")
	fs.StringVar(&f.wgConf, "wg-conf", "", "Path to WireGuard INI configuration file")
	fs.StringVar(&f.wgConfigAlias, "wg-config", "", "Alias for -wg-conf")
	f.hostDNS = addHostDNSFlag(fs)
	fs.BoolVar(&f.publishAll, "P", false, "Publish every port that the image exposes to a free port of 127.0.0.1")
	registerAlias([]string{"p", "publish"}, func(n string) {
		fs.Var(&f.portSpecs, n, "Publish a container port: [ip:][hostPort:]guestPort[/proto]")
	})
}

func (f *sandboxFlagValues) registerTargetAndMountFlags(fs *flag.FlagSet, defs flagDefaults) {
	fs.StringVar(&f.image, "image", "", "OCI image reference or archive path")
	fs.StringVar(&f.bin, "bin", "", "Host path to a Linux ELF64 executable")
	if defs.shortWForWorkspace {
		registerAlias([]string{"workspace", "w"}, func(n string) {
			fs.StringVar(&f.workspace, n, "", "Host directory mounted at /workspace")
		})
		fs.StringVar(&f.workDir, "workdir", "", "Guest working directory")
	} else {
		fs.StringVar(&f.workspace, "workspace", "", "Host directory mounted at /workspace")
		registerAlias([]string{"workdir", "w"}, func(n string) {
			fs.StringVar(&f.workDir, n, "", "Initial guest working directory")
		})
	}
	fs.BoolVar(&f.readOnly, "ro", false, "Mount /workspace read-only")
	fs.StringVar(&f.cacheDir, "cache-dir", "", "EROFS layer cache directory")
	fs.StringVar(&f.registryURL, "registry-url", "", "OCI registry base URL")
	fs.StringVar(&f.pull, "pull", string(gvx.PullMissing), "Pull the image: missing (use the cache first, the default), always (ask the registry first), or never (cache only)")
	fs.BoolVar(&f.hostCACerts, "host-ca-certs", false, "Make the guest trust the root certificates that the host trusts")
	fs.BoolVar(&f.readOnlyRoot, "read-only", false, "Mount the root file system of the guest read-only")
	registerAlias([]string{"v", "volume"}, func(n string) {
		fs.Var(&f.volumeFlags, n, "Mount a host directory, one host file, or a named volume (an ext4 image file): src:dst[:ro|rw]")
	})
	fs.Var(&f.mountFlags, "mount", "Mount with Docker syntax: type=bind|volume|tmpfs,src=...,dst=...,readonly[,driver=ext4lite|hostfs]; a volume src with a path separator names an image file")
	fs.Var(&f.tmpfsFlags, "tmpfs", "Mount a tmpfs: /path[:size=64m,ro]")
}

func (f *sandboxFlagValues) registerIdentityAndEnvFlags(fs *flag.FlagSet, defs flagDefaults) {
	fs.BoolVar(&f.lockdown, "lockdown", true, "Lock down the host process before guest entry (RestrictedToken and JobObject, or Seatbelt); use -lockdown=false to opt out")
	fs.BoolVar(&f.tty, "t", false, "Allocate a pseudo-TTY for guest stdio")
	fs.Bool("i", false, "Keep STDIN open (the guest always reads the standard input of rungv)")
	fs.BoolVar(&f.it, "it", false, "Allocate an interactive pseudo-TTY for guest stdio")
	fs.BoolVar(&f.detach, "d", false, "Run in the background (not supported: a run has no daemon)")
	fs.Bool("rm", false, "Remove the container at exit (every run does this)")
	registerAlias([]string{"e", "env"}, func(n string) {
		fs.Var(&f.envFlags, n, "Set an environment variable: KEY=VALUE, or KEY to copy it from the host")
	})
	fs.Var(&f.envFileFlags, "env-file", "Read environment variables from a file")
	if defs.includeEntrypoint {
		fs.StringVar(&f.entrypoint, "entrypoint", "", "Replace the image entrypoint; an empty value clears it")
	}
	registerAlias([]string{"u", "user"}, func(n string) {
		fs.StringVar(&f.user, n, "", "Run as user[:group], by name or number")
	})
	registerAlias([]string{"h", "hostname"}, func(n string) {
		fs.StringVar(&f.hostname, n, "", "Guest hostname")
	})
	fs.StringVar(&f.name, "name", "", "Container name")
}

func (f *sandboxFlagValues) registerResourceAndCheckpointFlags(fs *flag.FlagSet) {
	registerAlias([]string{"m", "memory"}, func(n string) {
		fs.StringVar(&f.memory, n, "", "Memory limit, such as 512m or 1g")
	})
	fs.StringVar(&f.cpus, "cpus", "", "CPU quota, such as 1.5")
	f.tune = addTuneFlags(fs)
	fs.StringVar(&f.checkpointDir, "checkpoint-dir", "", "Host directory pre-opened before lockdown for checkpoint output")
	fs.StringVar(&f.controlSocket, "control-socket", "", "Host path or loopback address for the control listener")
}

// buildPortForwards parses repeatable -p / --publish flags with tuning applied.
func (f *sandboxFlagValues) buildPortForwards(tuned tuning.Values) ([]gvx.PortForward, error) {
	var portForwards []gvx.PortForward
	for _, spec := range f.portSpecs {
		pfs, err := gvx.ParsePortForwardsWith(spec, tuned)
		if err != nil {
			return nil, err
		}
		portForwards = append(portForwards, pfs...)
	}
	return portForwards, nil
}

// buildEnvv loads --env-file entries followed by -e / --env overrides.
func (f *sandboxFlagValues) buildEnvv() ([]string, error) {
	var envv []string
	for _, path := range f.envFileFlags {
		entries, err := readEnvFile(path)
		if err != nil {
			return nil, fmt.Errorf("--env-file %s: %w", path, err)
		}
		envv = append(envv, entries...)
	}
	for _, entry := range f.envFlags {
		kv, ok, err := resolveEnvEntry(entry, os.LookupEnv)
		if err != nil {
			return nil, fmt.Errorf("-e: %w", err)
		}
		if ok {
			envv = append(envv, kv)
		}
	}
	return envv, nil
}

// buildMounts parses -v, --mount, and --tmpfs specifications in flag order.
func (f *sandboxFlagValues) buildMounts() ([]gvx.Mount, error) {
	var mounts []gvx.Mount
	for _, spec := range f.volumeFlags {
		m, err := gvx.ParseVolume(spec)
		if err != nil {
			return nil, fmt.Errorf("-v: %w", err)
		}
		mounts = append(mounts, m)
	}
	for _, spec := range f.mountFlags {
		m, err := gvx.ParseMount(spec)
		if err != nil {
			return nil, fmt.Errorf("--mount: %w", err)
		}
		mounts = append(mounts, m)
	}
	for _, spec := range f.tmpfsFlags {
		m, err := gvx.ParseTmpfs(spec)
		if err != nil {
			return nil, fmt.Errorf("--tmpfs: %w", err)
		}
		mounts = append(mounts, m)
	}
	return mounts, nil
}

// buildResources parses -m / --memory and --cpus limits.
func (f *sandboxFlagValues) buildResources() (gvx.Resources, error) {
	var resources gvx.Resources
	if f.memory != "" {
		n, err := gvx.ParseMemory(f.memory)
		if err != nil {
			return gvx.Resources{}, fmt.Errorf("-m: %w", err)
		}
		resources.MemoryBytes = n
	}
	if f.cpus != "" {
		n, err := gvx.ParseCPUs(f.cpus, runtime.NumCPU())
		if err != nil {
			return gvx.Resources{}, fmt.Errorf("--cpus: %w", err)
		}
		resources.CPUMillis = n
	}
	return resources, nil
}

// resolveBackendAndNetwork validates platform, architecture, network mode, and pull policy.
func (f *sandboxFlagValues) resolveBackendAndNetwork(allowEmptyNet bool) (gvx.PlatformType, string, gvx.NetworkMode, gvx.PullPolicy, error) {
	backend, imageArch, err := splitPlatform(f.platform)
	if err != nil {
		return "", "", "", "", fmt.Errorf("--platform: %w", err)
	}
	arch := strings.ToLower(strings.TrimSpace(f.arch))
	if imageArch != "" {
		arch = imageArch
	}
	var netMode gvx.NetworkMode
	if !allowEmptyNet || strings.TrimSpace(f.net) != "" {
		netMode, err = networkFor(f.net)
		if err != nil {
			return "", "", "", "", fmt.Errorf("--network: %w", err)
		}
	}
	pullPolicy, err := gvx.ParsePullPolicy(f.pull)
	if err != nil {
		return "", "", "", "", fmt.Errorf("--pull: %q must be always, missing, or never", f.pull)
	}
	return backend, arch, netMode, pullPolicy, nil
}

// wireGuardPath returns the configured WireGuard config path from -wg-conf or -wg-config.
func (f *sandboxFlagValues) wireGuardPath() string {
	if p := strings.TrimSpace(f.wgConf); p != "" {
		return p
	}
	return strings.TrimSpace(f.wgConfigAlias)
}

// buildBaseConfig validates common flags and constructs a gvx.Config.
func (f *sandboxFlagValues) buildBaseConfig(fs *flag.FlagSet, stdin io.Reader, stdout, stderr io.Writer, allowEmptyNet bool) (gvx.Config, bool, error) {
	tuned, err := f.tune.values()
	if err != nil {
		return gvx.Config{}, false, err
	}
	if _, err := gvx.ParseHostDNSServers(*f.hostDNS); err != nil {
		return gvx.Config{}, false, fmt.Errorf("--host-dns: %w", err)
	}
	portForwards, err := f.buildPortForwards(tuned)
	if err != nil {
		return gvx.Config{}, false, err
	}
	envv, err := f.buildEnvv()
	if err != nil {
		return gvx.Config{}, false, err
	}
	mounts, err := f.buildMounts()
	if err != nil {
		return gvx.Config{}, false, err
	}
	resources, err := f.buildResources()
	if err != nil {
		return gvx.Config{}, false, err
	}
	backend, arch, netMode, pullPolicy, err := f.resolveBackendAndNetwork(allowEmptyNet)
	if err != nil {
		return gvx.Config{}, false, err
	}
	priv := resolvePrivileges(fs, f.privileged, f.netRaw, f.packetWrite, f.allowSUID)

	cfg := gvx.Config{
		Platform:               backend,
		AllowUnconfinedSystrap: f.allowUnconfinedSystrap,
		Architecture:           arch,
		NetworkMode:            netMode,
		IsolateLAN:             f.isolateLAN,
		HostDNSServers:         *f.hostDNS,
		NetRaw:                 priv.netRaw,
		AllowPacketSocketWrite: priv.packetWrite,
		AllowSUID:              priv.allowSUID,
		PortForwards:           portForwards,
		PublishAll:             f.publishAll,
		WireGuardConfigPath:    f.wireGuardPath(),
		OCIImage:               strings.TrimSpace(f.image),
		OCICacheDir:            strings.TrimSpace(f.cacheDir),
		RegistryBaseURL:        strings.TrimSpace(f.registryURL),
		PullPolicy:             pullPolicy,
		Warnings:               stderr,
		BinaryPath:             strings.TrimSpace(f.bin),
		WorkspacePath:          strings.TrimSpace(f.workspace),
		WorkspaceReadOnly:      f.readOnly,
		Mounts:                 mounts,
		ReadOnlyRoot:           f.readOnlyRoot,
		HostCACerts:            f.hostCACerts,
		WorkDir:                strings.TrimSpace(f.workDir),
		Envv:                   envv,
		User:                   strings.TrimSpace(f.user),
		Hostname:               strings.TrimSpace(f.hostname),
		Name:                   strings.TrimSpace(f.name),
		Resources:              resources,
		Tuning:                 tuned,
		Stdin:                  stdin,
		Stdout:                 stdout,
		Stderr:                 stderr,
		TTY:                    f.tty || f.it,
		DisableHostLockdown:    !f.lockdown,
		CheckpointDir:          strings.TrimSpace(f.checkpointDir),
	}
	return cfg, backend == gvx.PlatformAuto, nil
}
