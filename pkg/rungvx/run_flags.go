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

package rungvx

import (
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
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

// expandShortClusters splits short-flag clusters and attached values before
// "--" or the first positional target.
func expandShortClusters(args []string) []string {
	fs := flag.NewFlagSet("rungvx", flag.ContinueOnError)
	registerSandboxFlags(fs, flagDefaults{includeEntrypoint: true})
	return normalizeRunArgs(fs, args)
}

func parseBackend(v string) (gvx.PlatformType, error) {
	switch b := gvx.PlatformType(strings.ToLower(strings.TrimSpace(v))); b {
	case gvx.PlatformAuto, gvx.PlatformWHPX, gvx.PlatformHVF, gvx.PlatformSystrap:
		return b, nil
	default:
		return "", fmt.Errorf("unsupported execution backend %q (want auto, whpx, hvf, or systrap)", v)
	}
}

func parseImagePlatformArch(v string) (string, error) {
	v = strings.ToLower(strings.TrimSpace(v))
	parts := strings.Split(v, "/")
	if len(parts) < 2 || len(parts) > 3 || parts[0] != "linux" || (parts[1] != "amd64" && parts[1] != "arm64") {
		return "", fmt.Errorf("unsupported image platform %q (want linux/amd64 or linux/arm64)", v)
	}
	return parts[1], nil
}

// splitPlatform separates a Docker image platform ("linux/arm64") from a gvx
// execution backend ("systrap"). A value with a slash names an image platform.
func splitPlatform(v string) (backend gvx.PlatformType, arch string, err error) {
	v = strings.ToLower(strings.TrimSpace(v))
	if !strings.Contains(v, "/") {
		b, err := parseBackend(v)
		if err != nil {
			return "", "", err
		}
		return b, "", nil
	}
	arch, err = parseImagePlatformArch(v)
	if err != nil {
		return "", "", err
	}
	return gvx.PlatformAuto, arch, nil
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
// shared between `rungvx run` and `rungvx restore`.
type flagDefaults struct {
	archDefault       string
	netDefault        string
	includeEntrypoint bool
}

// sandboxFlagValues holds raw flag values bound to a FlagSet before validation.
type sandboxFlagValues struct {
	platform               string
	backend                string
	allowUnconfinedSystrap bool
	arch                   string
	net                    string
	isolateLAN             bool
	netTXBPS               uint64
	netRXBPS               uint64
	natPolicyFile          string
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
	volumeDir              string
	keepBlobs              bool
	registryURL            string
	hostDNS                *multiStringFlag
	pull                   string
	lockdown               bool
	tty                    bool
	it                     bool
	detach                 bool
	publishAll             bool
	autoPublish            bool
	autoPublishAddr        string
	envFlags               listFlag
	envFileFlags           listFlag
	entrypoint             string
	user                   string
	hostname               string
	name                   string
	memory                 string
	cpus                   string
	pidsLimit              int64
	hostCACerts            bool
	readOnlyRoot           bool
	rootVolume             string
	volumeFlags            listFlag
	mountFlags             listFlag
	tmpfsFlags             listFlag
	tune                   *tuneFlags
	portSpecs              multiStringFlag
	unixForwardSpecs       listFlag
	checkpointDir          string
	controlSocket          string
	controlAuto            bool
	controlPolicy          string
	controlDisable         multiStringFlag
	controlTokenFile       string
	dynamicPorts           bool
	dynamicPortAddrs       multiStringFlag
	allowVolumeAttach      bool
	allowBindAttach        bool
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
	f.registerTargetAndMountFlags(fs)
	f.registerIdentityAndEnvFlags(fs, defs)
	f.registerResourceAndCheckpointFlags(fs)
	return f
}

func (f *sandboxFlagValues) registerPlatformAndNetFlags(fs *flag.FlagSet, defs flagDefaults) {
	fs.StringVar(&f.platform, "platform", string(gvx.PlatformAuto), "Execution backend (auto, whpx, hvf, or systrap) or image platform (linux/amd64 or linux/arm64)")
	fs.StringVar(&f.backend, "backend", "", "Execution backend: auto, whpx, hvf, or systrap")
	fs.BoolVar(&f.allowUnconfinedSystrap, "allow-unconfined-systrap", false, "Allow -platform=auto on Windows to fall back to systrap when whpx is unavailable")
	fs.StringVar(&f.arch, "arch", defs.archDefault, "Guest Linux architecture: amd64 or arm64")
	registerAlias([]string{"net", "network"}, func(n string) {
		fs.StringVar(&f.net, n, defs.netDefault, "Network backend: nat (or bridge), wg, or none")
	})
	fs.BoolVar(&f.isolateLAN, "isolate-lan", false, "Block RFC1918 and loopback LAN destinations in NAT mode")
	registerNetworkBandwidthFlags(fs, &f.netTXBPS, &f.netRXBPS)
	fs.StringVar(&f.natPolicyFile, "nat-policy-file", "", "Read host NAT firewall policy (.json, .yaml, or .yml)")
	fs.BoolVar(&f.privileged, "privileged", true, "Turn on --net-raw, --allow-packet-socket-write, and --allow-suid; --privileged=false turns them off")
	fs.BoolVar(&f.netRaw, "net-raw", true, "Allow raw sockets and iptables in the guest (default from --privileged)")
	fs.BoolVar(&f.packetWrite, "allow-packet-socket-write", true, "Allow writes on AF_PACKET sockets; needs --net-raw (default from --privileged)")
	fs.BoolVar(&f.allowSUID, "allow-suid", true, "Obey the set-user-ID and set-group-ID bits of guest executables (default from --privileged)")
	fs.StringVar(&f.wgConf, "wg-conf", "", "Path to WireGuard INI configuration file")
	fs.StringVar(&f.wgConfigAlias, "wg-config", "", "Alias for -wg-conf")
	f.hostDNS = addHostDNSFlag(fs)
	fs.BoolVar(&f.publishAll, "P", false, "Publish every port that the image exposes to a free port of 127.0.0.1")
	fs.BoolVar(&f.autoPublish, "auto-publish", false, "Automatically publish guest TCP listeners and iptables NAT DNAT ports on host 127.0.0.1 (or --auto-publish-addr)")
	fs.StringVar(&f.autoPublishAddr, "auto-publish-addr", "", "Host IP literal for --auto-publish (defaults to 127.0.0.1; e.g. 0.0.0.0 or a LAN IP)")
	fs.BoolVar(&f.dynamicPorts, "dynamic-ports", false, "Allow runtime loopback port publishing via `rungvx port add` under host lockdown")
	fs.Var(&f.dynamicPortAddrs, "dynamic-ports-addr", "Repeatable host IP literal allowed for runtime `rungvx port add` under host lockdown (e.g. 0.0.0.0 or a LAN IP)")
	registerAlias([]string{"p", "publish"}, func(n string) {
		fs.Var(&f.portSpecs, n, "Publish a container port: [ip:][hostPort:]guestPort[/proto]")
	})
	fs.Var(&f.unixForwardSpecs, "unix-forward", "Forward a guest Unix socket to a host Unix socket: GUEST_PATH=HOST_SOCKET[,uid=N,gid=N,mode=0600]")
}

func registerNetworkBandwidthFlags(fs *flag.FlagSet, tx, rx *uint64) {
	fs.Uint64Var(tx, "net-tx-bps", 0, "NAT bandwidth from guest to host in bits per second (0 for unlimited)")
	fs.Uint64Var(rx, "net-rx-bps", 0, "NAT bandwidth from host to guest in bits per second (0 for unlimited)")
}

func (f *sandboxFlagValues) registerTargetAndMountFlags(fs *flag.FlagSet) {
	fs.StringVar(&f.image, "image", "", "OCI image reference or archive path")
	fs.StringVar(&f.bin, "bin", "", "Host path to a Linux ELF64 executable")
	fs.StringVar(&f.workspace, "workspace", "", "Host directory mounted at /workspace")
	registerAlias([]string{"workdir", "w"}, func(n string) {
		fs.StringVar(&f.workDir, n, "", "Initial guest working directory")
	})
	fs.BoolVar(&f.readOnly, "ro", false, "Mount /workspace read-only")
	fs.StringVar(&f.cacheDir, "cache-dir", "", "EROFS layer cache directory (also sets named volumes to DIR/volumes unless -volume-dir is set)")
	fs.StringVar(&f.volumeDir, "volume-dir", "", "Named volume directory (overrides -cache-dir and GVX_VOLUME_DIR)")
	fs.BoolVar(&f.keepBlobs, "keep-blobs", defaultKeepBlobs(), keepBlobsUsage)
	fs.StringVar(&f.registryURL, "registry-url", "", "OCI registry base URL")
	fs.StringVar(&f.pull, "pull", string(gvx.PullMissing), "Pull the image: missing (use the cache first, the default), always (ask the registry first), or never (cache only)")
	fs.BoolVar(&f.hostCACerts, "host-ca-certs", false, "Make the guest trust the root certificates that the host trusts")
	fs.BoolVar(&f.readOnlyRoot, "read-only", false, "Mount the root file system of the guest read-only")
	fs.StringVar(&f.rootVolume, "rootfs-volume", "", "Persistent ext4lite volume name or .ext4 image path for the container rootfs")
	registerAlias([]string{"v", "volume"}, func(n string) {
		fs.Var(&f.volumeFlags, n, "Mount a host directory, one host file, or a named volume (an ext4 image file): src:dst[:ro|rw]")
	})
	fs.Var(&f.mountFlags, "mount", "Mount with Docker syntax: type=bind|volume|tmpfs|overlay,src=...,dst=...[,upper=...][,size=...][,ephemeral][,tmpfs-size=...][,readonly][,driver=ext4lite|hostfs]")
	fs.Var(&f.tmpfsFlags, "tmpfs", "Mount a tmpfs: /path[:size=64m,ro]")
}

func (f *sandboxFlagValues) registerIdentityAndEnvFlags(fs *flag.FlagSet, defs flagDefaults) {
	fs.BoolVar(&f.lockdown, "lockdown", true, "Lock down the host process before guest entry (RestrictedToken and JobObject, or Seatbelt); use -lockdown=false to opt out")
	fs.BoolVar(&f.tty, "t", false, "Allocate a pseudo-TTY for guest stdio")
	fs.Bool("i", false, "Keep STDIN open (the guest always reads the standard input of rungvx)")
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
	fs.Int64Var(&f.pidsLimit, "pids-limit", 0, "Maximum number of guest processes/tasks (0 means unlimited)")
	f.tune = addTuneFlags(fs)
	fs.StringVar(&f.checkpointDir, "checkpoint-dir", "", "Host directory pre-opened before lockdown for checkpoint output")
	registerAlias([]string{"control-socket", "S"}, func(n string) {
		fs.StringVar(&f.controlSocket, n, "", "Host path or loopback address for the control listener")
	})
	fs.BoolVar(&f.controlAuto, "control", false, "Bind an owner-only control socket automatically for --name")
	fs.StringVar(&f.controlPolicy, "control-policy", string(control.PolicyDefault), "Control capability profile: default, readonly, or checkpoint-only")
	fs.Var(&f.controlDisable, "control-disable", "Comma-separated control capabilities or groups to disable (e.g. exec,net.dial)")
	fs.StringVar(&f.controlTokenFile, "control-token-file", "", "Path for the control authentication token file (forces token auth on POSIX Unix sockets)")
	fs.BoolVar(&f.allowVolumeAttach, "allow-volume-attach", false, "Allow POSIX SCM_RIGHTS ext4lite volume attachment via `rungvx mount add --type volume` under lockdown")
	fs.BoolVar(&f.allowBindAttach, "allow-bind-attach", false, "Allow POSIX SCM_RIGHTS hostfs bind attachment via `rungvx mount add --type bind` under lockdown")
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

// buildResources parses -m / --memory, --cpus, and --pids-limit limits.
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
	if f.pidsLimit < 0 {
		return gvx.Resources{}, fmt.Errorf("--pids-limit must be >= 0, got %d", f.pidsLimit)
	}
	resources.PidsLimit = f.pidsLimit
	return resources, nil
}

func (f *sandboxFlagValues) resolveControlSocket() (string, error) {
	if s := strings.TrimSpace(f.controlSocket); s != "" {
		return s, nil
	}
	if f.controlAuto {
		name := strings.TrimSpace(f.name)
		if name == "" {
			return "", fmt.Errorf("--control requires --name <NAME> (or specify -S/--control-socket)")
		}
		return control.NamedSocketPath(name)
	}
	return "", nil
}

// resolveBackendAndNetwork validates backend, platform, architecture, network mode, and pull policy.
func (f *sandboxFlagValues) resolveBackendAndNetwork(fs *flag.FlagSet, allowEmptyNet bool) (gvx.PlatformType, string, gvx.NetworkMode, gvx.PullPolicy, error) {
	backend, imageArch, err := splitPlatform(f.platform)
	if err != nil {
		return "", "", "", "", fmt.Errorf("--platform: %w", err)
	}
	if flagVisited(fs, "backend") || strings.TrimSpace(f.backend) != "" {
		explicitBackend, err := parseBackend(f.backend)
		if err != nil {
			return "", "", "", "", fmt.Errorf("--backend: %w", err)
		}
		if flagVisited(fs, "platform") && imageArch == "" && backend != explicitBackend {
			return "", "", "", "", fmt.Errorf("--backend=%s conflicts with --platform=%s; pass --platform=linux/<arch> with --backend=<engine>", explicitBackend, backend)
		}
		backend = explicitBackend
	}
	arch := strings.ToLower(strings.TrimSpace(f.arch))
	if imageArch != "" {
		if flagVisited(fs, "arch") && arch != "" && arch != imageArch {
			return "", "", "", "", fmt.Errorf("--arch=%s conflicts with --platform=linux/%s", arch, imageArch)
		}
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
	var unixForwards []gvx.UnixForward
	for _, spec := range f.unixForwardSpecs {
		uf, err := gvx.ParseUnixForward(spec)
		if err != nil {
			return gvx.Config{}, false, fmt.Errorf("--unix-forward: %w", err)
		}
		unixForwards = append(unixForwards, uf)
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
	backend, arch, netMode, pullPolicy, err := f.resolveBackendAndNetwork(fs, allowEmptyNet)
	if err != nil {
		return gvx.Config{}, false, err
	}
	var networkPolicy *gvx.NATPolicyConfig
	if flagVisited(fs, "nat-policy-file") {
		if allowEmptyNet && !flagVisited(fs, "net") && !flagVisited(fs, "network") {
			netMode = gvx.NetModeNAT
		}
		if netMode != gvx.NetModeNAT {
			return gvx.Config{}, false, fmt.Errorf("--nat-policy-file requires -net=nat")
		}
		policy, err := readNATPolicyFile(f.natPolicyFile)
		if err != nil {
			return gvx.Config{}, false, fmt.Errorf("--nat-policy-file: %w", err)
		}
		networkPolicy = &policy
	}
	if flagVisited(fs, "net-tx-bps") || flagVisited(fs, "net-rx-bps") {
		if netMode == "" {
			// If restore inherits the mode, the bundle must use NAT.
			netMode = gvx.NetModeNAT
		}
		if netMode != gvx.NetModeNAT {
			return gvx.Config{}, false, fmt.Errorf("--net-tx-bps and --net-rx-bps require -net=nat")
		}
	}
	priv := resolvePrivileges(fs, f.privileged, f.netRaw, f.packetWrite, f.allowSUID)
	ctrlPolicy, err := control.ParsePolicy(f.controlPolicy)
	if err != nil {
		return gvx.Config{}, false, fmt.Errorf("--control-policy: %w", err)
	}
	rootVolume := strings.TrimSpace(f.rootVolume)
	if flagVisited(fs, "rootfs-volume") && rootVolume == "" {
		return gvx.Config{}, false, fmt.Errorf("--rootfs-volume must not be empty")
	}

	warningsOut := stderr
	stderrOut := stderr
	if f.autoPublish && stderr != nil {
		sw := &syncWriter{w: stderr}
		warningsOut = sw
		stderrOut = sw
	}

	cfg := gvx.Config{
		Platform:               backend,
		AllowUnconfinedSystrap: f.allowUnconfinedSystrap,
		Architecture:           arch,
		NetworkMode:            netMode,
		NetworkPolicy:          networkPolicy,
		IsolateLAN:             f.isolateLAN,
		HostDNSServers:         *f.hostDNS,
		NetRaw:                 priv.netRaw,
		AllowPacketSocketWrite: priv.packetWrite,
		AllowSUID:              priv.allowSUID,
		PortForwards:           portForwards,
		UnixForwards:           unixForwards,
		PublishAll:             f.publishAll,
		AutoPublishPorts:       f.autoPublish,
		AutoPublishAddr:        strings.TrimSpace(f.autoPublishAddr),
		WireGuardConfigPath:    f.wireGuardPath(),
		OCIImage:               strings.TrimSpace(f.image),
		OCICacheDir:            strings.TrimSpace(f.cacheDir),
		VolumeDir:              strings.TrimSpace(f.volumeDir),
		OCIKeepBlobs:           f.keepBlobs,
		RegistryBaseURL:        strings.TrimSpace(f.registryURL),
		PullPolicy:             pullPolicy,
		Warnings:               warningsOut,
		BinaryPath:             strings.TrimSpace(f.bin),
		WorkspacePath:          strings.TrimSpace(f.workspace),
		WorkspaceReadOnly:      f.readOnly,
		Mounts:                 mounts,
		ReadOnlyRoot:           f.readOnlyRoot,
		RootVolume:             rootVolume,
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
		Stderr:                 stderrOut,
		TTY:                    f.tty || f.it,
		DisableHostLockdown:    !f.lockdown,
		CheckpointDir:          strings.TrimSpace(f.checkpointDir),
		ControlPolicy:          ctrlPolicy,
		ControlDisable:         append([]string(nil), f.controlDisable...),
		DynamicPorts:           f.dynamicPorts,
		DynamicPortAddrs:       append([]string(nil), f.dynamicPortAddrs...),
		AllowVolumeAttach:      f.allowVolumeAttach,
		AllowBindAttach:        f.allowBindAttach,
	}
	cfg.NetworkBandwidth.TXBPS, cfg.NetworkBandwidth.RXBPS = f.netTXBPS, f.netRXBPS
	if err := cfg.NetworkBandwidth.Validate(); err != nil {
		return gvx.Config{}, false, err
	}
	if err := control.ValidateDisableList(cfg.ControlDisable); err != nil {
		return gvx.Config{}, false, fmt.Errorf("--control-disable: %w", err)
	}
	return cfg, backend == gvx.PlatformAuto, nil
}

type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}
