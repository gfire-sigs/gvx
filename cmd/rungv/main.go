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

// Binary rungv is the standalone CLI runner for gvx on Windows and macOS.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"z.gfire.dev/gvx/pkg/gvx"
)

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

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := executeCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}

func executeCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	subcmd := args[0]
	switch subcmd {
	case "worker":
		if err := gvx.ServeProcess(ctx, gvx.WorkerOptions{}); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		return 0
	case "run":
		return runSubcommand(ctx, args[1:], stdin, stdout, stderr)
	case "pull":
		return pullSubcommand(ctx, args[1:], stdout, stderr)
	case "stub":
		return stubSubcommand(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		// Allow invoking rungv directly with flags if "run" was omitted.
		if strings.HasPrefix(subcmd, "-") {
			return runSubcommand(ctx, args, stdin, stdout, stderr)
		}
		_, _ = fmt.Fprintf(stderr, "rungv: unknown subcommand %q\n", subcmd)
		printUsage(stderr)
		return 2
	}
}

// runConfig is the parsed result of `rungv run` arguments.
type runConfig struct {
	cfg gvx.Config
	// autoPlatform reports that the user left the backend selection to gvx.
	autoPlatform bool
}

// parseRunArgs converts `rungv run` arguments into a gvx.Config. It returns
// the process exit code when the arguments end the command without a run.
func parseRunArgs(args []string, stdin io.Reader, stdout, stderr io.Writer) (rc runConfig, exitCode int, done bool) {
	fs := flag.NewFlagSet("rungv run", flag.ContinueOnError)
	fs.SetOutput(stderr)

	platformFlag := fs.String("platform", string(gvx.PlatformAuto), "Execution backend: auto, whpx, hvf, or systrap")
	archFlag := fs.String("arch", runtime.GOARCH, "Guest Linux architecture: amd64 or arm64")
	netFlag := fs.String("net", string(gvx.NetModeNAT), "Network backend: nat, wg, or none")
	isolateLANFlag := fs.Bool("isolate-lan", false, "Block RFC1918 and loopback LAN destinations in NAT mode")
	wgConfFlag := fs.String("wg-conf", "", "Path to WireGuard INI configuration file")
	wgConfigAlias := fs.String("wg-config", "", "Alias for -wg-conf")
	imageFlag := fs.String("image", "", "OCI image reference or archive path")
	binFlag := fs.String("bin", "", "Host path to a Linux ELF64 executable")
	workspaceFlag := fs.String("workspace", "", "Host directory mounted at /workspace")
	readOnlyFlag := fs.Bool("ro", false, "Mount /workspace read-only")
	workDirFlag := fs.String("workdir", "", "Initial guest working directory")
	cacheDirFlag := fs.String("cache-dir", "", "EROFS layer cache directory")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL")
	lockdownFlag := fs.Bool("lockdown", true, "Apply host isolation before guest entry; use -lockdown=false to opt out")
	ttyFlag := fs.Bool("t", false, "Allocate a pseudo-TTY for guest stdio")
	interactiveFlag := fs.Bool("i", false, "Keep STDIN open")
	itFlag := fs.Bool("it", false, "Allocate an interactive pseudo-TTY for guest stdio")

	var portSpecs multiStringFlag
	fs.Var(&portSpecs, "p", "Publish a container port to the host (hostPort:guestPort[/proto])")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return runConfig{}, 0, true
		}
		return runConfig{}, 2, true
	}

	remaining := fs.Args()
	if len(remaining) > 0 && remaining[0] == "--" {
		remaining = remaining[1:]
	}

	imageRef := strings.TrimSpace(*imageFlag)
	binPath := strings.TrimSpace(*binFlag)
	guestArgv := remaining

	// If neither -image nor -bin was set, treat the first positional argument
	// as an ELF binary path (if it exists on the host with an ELF header) or
	// an OCI image reference.
	if imageRef == "" && binPath == "" && len(guestArgv) > 0 {
		first := guestArgv[0]
		if isHostELFFile(first) {
			binPath = first
			guestArgv = guestArgv[1:]
		} else {
			imageRef = first
			guestArgv = guestArgv[1:]
		}
	}

	if imageRef == "" && binPath == "" {
		_, _ = fmt.Fprintln(stderr, "rungv run: specify -image=<image>, -bin=<elf>, or a positional target")
		return runConfig{}, 2, true
	}

	var portForwards []gvx.PortForward
	for _, spec := range portSpecs {
		pf, err := gvx.ParsePortForward(spec)
		if err != nil {
			_, _ = fmt.Fprintf(stderr, "rungv run: %v\n", err)
			return runConfig{}, 2, true
		}
		portForwards = append(portForwards, pf)
	}

	wgConfPath := strings.TrimSpace(*wgConfFlag)
	if wgConfPath == "" {
		wgConfPath = strings.TrimSpace(*wgConfigAlias)
	}

	platform := gvx.PlatformType(strings.ToLower(strings.TrimSpace(*platformFlag)))
	return runConfig{
		autoPlatform: platform == gvx.PlatformAuto,
		cfg: gvx.Config{
			Platform:            platform,
			Architecture:        strings.ToLower(strings.TrimSpace(*archFlag)),
			NetworkMode:         gvx.NetworkMode(strings.ToLower(strings.TrimSpace(*netFlag))),
			IsolateLAN:          *isolateLANFlag,
			PortForwards:        portForwards,
			WireGuardConfigPath: wgConfPath,
			OCIImage:            imageRef,
			OCICacheDir:         strings.TrimSpace(*cacheDirFlag),
			RegistryBaseURL:     strings.TrimSpace(*registryURLFlag),
			BinaryPath:          binPath,
			WorkspacePath:       strings.TrimSpace(*workspaceFlag),
			WorkspaceReadOnly:   *readOnlyFlag,
			Argv:                guestArgv,
			WorkDir:             strings.TrimSpace(*workDirFlag),
			Stdin:               stdin,
			Stdout:              stdout,
			Stderr:              stderr,
			TTY:                 *ttyFlag || *itFlag || *interactiveFlag,
			DisableHostLockdown: !*lockdownFlag,
		},
	}, 0, false
}

func runSubcommand(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	rc, exitCode, done := parseRunArgs(args, stdin, stdout, stderr)
	if done {
		return exitCode
	}

	sb, err := openSandbox(ctx, rc.cfg)
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

	exitCode, err = sb.Run(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv run: %v\n", err)
		if exitCode == 0 {
			return 1
		}
		return exitCode
	}
	return exitCode
}

type runningSandbox interface {
	Run(context.Context) (int, error)
	Close() error
	PlatformName() string
}

func openSandbox(ctx context.Context, cfg gvx.Config) (runningSandbox, error) {
	if runtime.GOOS == "windows" && !cfg.DisableHostLockdown {
		executable, err := os.Executable()
		if err != nil {
			return nil, err
		}
		return gvx.NewProcess(ctx, gvx.WorkerCommand{Executable: executable, Arguments: []string{"worker"}}, cfg)
	}
	return gvx.New(ctx, cfg)
}

func pullSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rungv pull", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cacheDirFlag := fs.String("cache-dir", "", "EROFS layer cache directory")
	registryURLFlag := fs.String("registry-url", "", "OCI registry base URL")
	archFlag := fs.String("arch", runtime.GOARCH, "Target Linux architecture (amd64 or arm64)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	remaining := fs.Args()
	if len(remaining) == 0 {
		_, _ = fmt.Fprintln(stderr, "rungv pull: missing <image-or-archive> argument")
		return 2
	}
	target := remaining[0]

	cache, err := gvx.NewLayerCache(strings.TrimSpace(*cacheDirFlag))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", err)
		return 1
	}

	resolved, resolveErr := gvx.ResolveImage(ctx, cache, strings.TrimSpace(*registryURLFlag), target, *archFlag)
	if resolveErr != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", resolveErr)
		return 1
	}
	layerCount := len(resolved.LayerDigests)
	if closeErr := resolved.Close(); closeErr != nil {
		_, _ = fmt.Fprintf(stderr, "rungv pull: %v\n", closeErr)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "pulled %s (%d EROFS layers cached in %s)\n", target, layerCount, cache.Dir())
	return 0
}

// stubSubcommand spawns the systrap stub, completes the handshake, and prints
// what the stub reported. It exits with 1 and the engine error when the host
// has no usable systrap engine.
func stubSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("rungv stub", flag.ContinueOnError)
	fs.SetOutput(stderr)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(stderr, "rungv stub: unexpected argument %q\n", fs.Arg(0))
		return 2
	}

	info, err := gvx.ProbeStub(ctx)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "rungv stub: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "systrap stub ok\n"+
		"architecture: %s\n"+
		"host page size: %d\n"+
		"stub pid: %d\n"+
		"protocol version: %d\n"+
		"syscall round trip: %s\n",
		info.Arch, info.HostPageSize, info.PID, info.ProtocolVersion, info.RoundTrip)
	if info.UserMax != 0 {
		_, _ = fmt.Fprintf(stdout, "guest address range: %#x-%#x\n", info.UserMin, info.UserMax)
	}
	return 0
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

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage:")
	_, _ = fmt.Fprintln(w, "  rungv run [flags] -image=<oci-image> [-- command args...]")
	_, _ = fmt.Fprintln(w, "  rungv run [flags] -bin=<linux-elf64>")
	_, _ = fmt.Fprintln(w, "  rungv pull [flags] <oci-image-or-archive>")
	_, _ = fmt.Fprintln(w, "  rungv stub")
	_, _ = fmt.Fprintln(w, "      Start the systrap stub, print its handshake data, and stop it.")
	_, _ = fmt.Fprintln(w, "      Exit code 1 and the engine error mean systrap cannot run on this host.")
}
