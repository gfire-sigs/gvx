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

// runConfig is the parsed result of `rungv run` arguments.
type runConfig struct {
	cfg gvx.Config
	// autoPlatform reports that the user left the backend selection to gvx.
	autoPlatform bool
	// controlSocket is the host path or loopback address for the control listener.
	controlSocket string
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

	flags := registerSandboxFlags(fs, flagDefaults{
		archDefault:       runtime.GOARCH,
		netDefault:        string(gvx.NetModeNAT),
		includeEntrypoint: true,
	})
	if err := fs.Parse(expandShortClusters(args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return runConfig{}, 0, true
		}
		return runConfig{}, 2, true
	}
	if flags.detach {
		return usageError("-d is not supported: rungv runs in the foreground and keeps no container after the guest exits")
	}

	imageRef, binPath, guestArgs, err := resolveRunTarget(flags.image, flags.bin, fs.Args())
	if err != nil {
		return usageError("%v", err)
	}

	cfg, autoPlatform, err := flags.buildBaseConfig(fs, stdin, stdout, stderr, false)
	if err != nil {
		return usageError("%v", err)
	}
	cfg.OCIImage = imageRef
	cfg.BinaryPath = binPath
	applyGuestCommand(&cfg, fs, flags.entrypoint, binPath, guestArgs)

	return runConfig{
		autoPlatform:  autoPlatform,
		cfg:           cfg,
		controlSocket: strings.TrimSpace(flags.controlSocket),
	}, 0, false
}

// resolveRunTarget determines the image reference or binary path and remaining guest arguments.
func resolveRunTarget(rawImage, rawBin string, rawArgs []string) (imageRef, binPath string, guestArgs []string, err error) {
	guestArgs = rawArgs
	if len(guestArgs) > 0 && guestArgs[0] == "--" {
		guestArgs = guestArgs[1:]
	}
	imageRef = strings.TrimSpace(rawImage)
	binPath = strings.TrimSpace(rawBin)
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
		return "", "", nil, errors.New("specify -image=<image>, -bin=<elf>, or a positional target")
	}
	return imageRef, binPath, guestArgs, nil
}

// applyGuestCommand populates Argv, Cmd, and Entrypoint fields on cfg.
func applyGuestCommand(cfg *gvx.Config, fs *flag.FlagSet, entrypointFlag, binPath string, guestArgs []string) {
	if len(guestArgs) > 0 {
		if binPath != "" {
			cfg.Argv = guestArgs
		} else {
			cfg.Cmd = guestArgs
		}
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "entrypoint" {
			cfg.EntrypointSet = true
			if entrypointFlag != "" {
				cfg.Entrypoint = []string{entrypointFlag}
			}
		}
	})
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

	cleanCkptDir, absCkptDir := resolveCheckpointDirs(rc.cfg.CheckpointDir)
	control, ok := bindControlSocket(&rc.cfg, rc.controlSocket, "rungv run", stderr)
	if !ok {
		return 1
	}
	var sb *gvx.Sandbox
	if control != nil {
		defer func() {
			if sb == nil || !sb.LockdownStatus().Applied {
				control.Cleanup()
			}
		}()
	}

	var err error
	sb, err = gvx.New(ctx, rc.cfg)
	if err != nil {
		if rc.cfg.CheckpointListener != nil {
			_ = rc.cfg.CheckpointListener.Close()
		}
		_, _ = fmt.Fprintf(stderr, "rungv run: init sandbox: %v\n", err)
		if errors.Is(err, gvx.ErrInvalidConfig) {
			return 2
		}
		return 1
	}
	defer func() {
		_ = sb.Close()
	}()
	return executeSandboxWithControl(ctx, sb, &rc.cfg, control.token(), rc.autoPlatform, cleanCkptDir, absCkptDir, "rungv run", stderr)
}

// bindControlSocket opens the control listener before host lockdown when requested.
func bindControlSocket(cfg *gvx.Config, socketSpec, cmdPrefix string, stderr io.Writer) (*controlEndpoint, bool) {
	if socketSpec == "" {
		return nil, true
	}
	ep, err := listenCheckpointSocket(socketSpec)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: listen control socket: %v\n", cmdPrefix, err)
		return nil, false
	}
	cfg.CheckpointListener = ep.Listener
	return ep, true
}

// executeSandboxWithControl emits startup warnings, starts checkpoint control, and runs the sandbox.
func executeSandboxWithControl(ctx context.Context, sb *gvx.Sandbox, cfg *gvx.Config, controlToken string, autoPlatform bool, cleanCkptDir, absCkptDir, cmdPrefix string, stderr io.Writer) int {
	stopControl := startCheckpointControl(ctx, sb, cfg.CheckpointListener, controlToken, cleanCkptDir, absCkptDir)
	defer stopControl()

	reportSandboxStartup(stderr, sb, cfg, autoPlatform)
	exitCode, err := sb.Run(ctx)
	stopControl()
	if errors.Is(err, gvx.ErrMemoryLimit) {
		_, _ = fmt.Fprintf(stderr, "rungv: the guest was killed: it passed the memory limit of %d bytes\n", cfg.Resources.MemoryBytes)
		return exitCode
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", cmdPrefix, err)
		if exitCode == 0 {
			return 1
		}
		return exitCode
	}
	return exitCode
}

// reportSandboxStartup logs platform selection, security posture warnings, and published ports.
func reportSandboxStartup(stderr io.Writer, sb *gvx.Sandbox, cfg *gvx.Config, autoPlatform bool) {
	if autoPlatform {
		_, _ = fmt.Fprintf(stderr, "rungv: platform=%s\n", sb.PlatformName())
		if reason := sb.FallbackReason(); reason != "" {
			_, _ = fmt.Fprintf(stderr, "rungv: warning: the hardware hypervisor is not available, so the guest runs on %s, which is slower: %s\n", sb.PlatformName(), reason)
		}
	}
	if !sb.SecurityPosture().HardwareOrKernelSyscallIsolation {
		_, _ = fmt.Fprintln(stderr, "rungv: warning: Windows systrap lacks hardware or kernel syscall isolation; use whpx for untrusted workloads")
	}
	if cfg.DisableHostLockdown {
		_, _ = fmt.Fprintln(stderr, "rungv: warning: host lockdown disabled")
	}
	reportPublishedPorts(stderr, sb)
	if cfg.Resources.CPUMillis > 0 && !sb.Limits().CPUTime {
		_, _ = fmt.Fprintf(stderr, "rungv: warning: --cpus sets the number of CPUs that the guest sees; this host does not cap the CPU time\n")
	}
}

// guestPrivileges are the guest privileges that --privileged groups.
type guestPrivileges struct {
	netRaw, packetWrite, allowSUID bool
}

// resolvePrivileges applies --privileged and the flags that it groups. Each
// flag that the user set explicitly wins. A flag that the user did not set
// takes the value of --privileged. Packet socket writes need raw sockets, so
// they stay off when raw sockets are off, unless the user asked for both.
func resolvePrivileges(fs *flag.FlagSet, privileged, netRaw, packetWrite, allowSUID bool) guestPrivileges {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	pick := func(name string, value bool) bool {
		if set[name] {
			return value
		}
		return privileged
	}
	p := guestPrivileges{
		netRaw:      pick("net-raw", netRaw),
		packetWrite: pick("allow-packet-socket-write", packetWrite),
		allowSUID:   pick("allow-suid", allowSUID),
	}
	if !set["allow-packet-socket-write"] && !p.netRaw {
		p.packetWrite = false
	}
	return p
}

// reportPublishedPorts tells the user which host port serves each guest port,
// because a free port that the host picked is not known to the user.
func reportPublishedPorts(w io.Writer, sb *gvx.Sandbox) {
	for _, p := range sb.PublishedPorts() {
		host := net.JoinHostPort(p.HostAddr, strconv.Itoa(int(p.HostPort)))
		if p.HostSocket != "" {
			host = "unix:" + p.HostSocket
		}
		_, _ = fmt.Fprintf(w, "rungv: publishing %s -> %d/%s\n", host, p.GuestPort, p.Protocol)
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
