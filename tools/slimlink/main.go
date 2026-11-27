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

// Command slimlink builds Go binaries using an overlay-patched cmd/link from
// the active GOROOT that prevents name-only R_USENAMEDMETHOD("Methods")
// relocations from falsely marking reflect iterator Methods() reachable and
// disabling linker dead-method elimination across the binary.
//
// Stack traces, pclntab metadata, runtime.Caller, GC tables, and pprof remain
// identical to stock Go builds.
//
// Soundness boundary for -fix-reflect-methods:
//   - Direct calls and concrete interface calls to reflect's iterator Methods()
//     remain reachable, but programs calling reflect's Methods() solely via a
//     generic interface constraint or reflect.Value.MethodByName("Methods")
//     must disable -fix-reflect-methods.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"
)

type options struct {
	goBin            string
	cacheDir         string
	fixReflectMethod bool
	execLinkPath     string
	execModeID       string
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	var opts options
	fs := flag.NewFlagSet("slimlink", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&opts.goBin, "go", "go", "Go toolchain executable")
	fs.StringVar(&opts.cacheDir, "cache-dir", "", "Directory for caching the patched cmd/link binary")
	fs.BoolVar(&opts.fixReflectMethod, "fix-reflect-methods", true, "Prevent generic Methods name collisions from triggering reflectSeen")
	fs.StringVar(&opts.execLinkPath, "toolexec-link", "", "Internal -toolexec mode: path to patched link binary")
	fs.StringVar(&opts.execModeID, "toolexec-id", "", "Internal -toolexec mode: build cache discriminator")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	if opts.execLinkPath != "" {
		return runToolexec(opts, fs.Args())
	}

	buildArgs := fs.Args()
	if len(buildArgs) == 0 {
		fmt.Fprintln(os.Stderr, "usage: slimlink [flags] -- <go build args...>")
		return 2
	}

	if err := runSlimBuild(opts, buildArgs); err != nil {
		var childErr *childExitError
		if errors.As(err, &childErr) {
			return childErr.code
		}
		fmt.Fprintf(os.Stderr, "slimlink: %v\n", err)
		return 1
	}
	return 0
}

type childExitError struct {
	code int
}

func (e *childExitError) Error() string {
	return fmt.Sprintf("child process exited with status %d", e.code)
}

func exitCodeOrOne(err *exec.ExitError) int {
	if code := err.ExitCode(); code > 0 {
		return code
	}
	return 1
}

func runToolexec(opts options, toolInvocation []string) int {
	if len(toolInvocation) == 0 {
		fmt.Fprintln(os.Stderr, "slimlink: empty toolexec invocation")
		return 2
	}
	toolPath := toolInvocation[0]
	toolArgs := toolInvocation[1:]
	base := filepath.Base(toolPath)
	isLink := base == "link" || strings.EqualFold(base, "link.exe")
	if isLink {
		toolPath = opts.execLinkPath
	}

	// Include slimlink configuration in link -V=full so Go's build cache never
	// conflates stock linker outputs with slimlink outputs.
	if isLink && len(toolArgs) == 1 && toolArgs[0] == "-V=full" {
		out, err := exec.Command(toolPath, toolArgs...).Output()
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				_, _ = os.Stderr.Write(exitErr.Stderr)
				return exitCodeOrOne(exitErr)
			}
			fmt.Fprintf(os.Stderr, "slimlink: run patched link -V=full: %v\n", err)
			return 1
		}
		trimmed := strings.TrimRight(string(out), "\r\n")
		if strings.Contains(trimmed, "buildID=") {
			_, _ = fmt.Fprintf(os.Stdout, "%s:%s\n", trimmed, opts.execModeID)
		} else {
			_, _ = fmt.Fprintf(os.Stdout, "%s buildID=%s\n", trimmed, opts.execModeID)
		}
		return 0
	}

	cmd := exec.Command(toolPath, toolArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if isLink {
		cmd.Env = append(os.Environ(), slimlinkEnv(opts)...)
	}
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitCodeOrOne(exitErr)
		}
		fmt.Fprintf(os.Stderr, "slimlink: exec %s: %v\n", toolPath, err)
		return 1
	}
	return 0
}

func slimlinkEnv(opts options) []string {
	val := "0"
	if opts.fixReflectMethod {
		val = "1"
	}
	return []string{
		"GVX_SLIMLINK_FIX_REFLECT_METHODS=" + val,
	}
}

func modeTag(opts options, patchKey string) string {
	val := "0"
	if opts.fixReflectMethod {
		val = "1"
	}
	return fmt.Sprintf("slimlink=%s:dce=%s", patchKey, val)
}

func resolveGoBin(goBin string) (string, error) {
	p, err := exec.LookPath(goBin)
	if err != nil {
		return "", fmt.Errorf("locate go executable %q: %w", goBin, err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("resolve go executable path %q: %w", p, err)
	}
	return abs, nil
}

func runSlimBuild(opts options, buildArgs []string) error {
	goBin, err := resolveGoBin(opts.goBin)
	if err != nil {
		return err
	}

	changeDir, err := validateAndExtractChangeDir(buildArgs)
	if err != nil {
		return err
	}

	patchedLink, patchKey, err := ensurePatchedLinker(goBin, opts.cacheDir, changeDir)
	if err != nil {
		return err
	}

	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate slimlink executable: %w", err)
	}
	selfExe, err = filepath.Abs(selfExe)
	if err != nil {
		return fmt.Errorf("resolve slimlink executable path: %w", err)
	}

	fixFlag := "false"
	if opts.fixReflectMethod {
		fixFlag = "true"
	}
	toolexecArg, err := joinToolexecArgs([]string{
		selfExe,
		"-toolexec-link=" + patchedLink,
		"-toolexec-id=" + modeTag(opts, patchKey),
		"-fix-reflect-methods=" + fixFlag,
	})
	if err != nil {
		return fmt.Errorf("format -toolexec argument: %w", err)
	}

	args := buildGoBuildArgs(toolexecArg, buildArgs)

	cmd := exec.Command(goBin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &childExitError{code: exitCodeOrOne(exitErr)}
		}
		return err
	}
	return nil
}

type goOverlay struct {
	Replace map[string]string `json:"Replace"`
}

func goEnvValue(goBin, changeDir, name string) (string, error) {
	args := make([]string, 0, 4)
	args = append(args, "env")
	if changeDir != "" {
		args = append(args, "-C", changeDir)
	}
	args = append(args, name)
	out, err := exec.Command(goBin, args...).Output()
	if err != nil {
		return "", fmt.Errorf("go env %s: %w", name, err)
	}
	val := strings.TrimSpace(string(out))
	if val == "" {
		return "", fmt.Errorf("go env %s returned empty value", name)
	}
	return val, nil
}

func ensurePatchedLinker(goBin, cacheDir, changeDir string) (string, string, error) {
	goroot, err := goEnvValue(goBin, changeDir, "GOROOT")
	if err != nil {
		return "", "", err
	}
	goVersion, err := goEnvValue(goBin, changeDir, "GOVERSION")
	if err != nil {
		goVersion = runtime.Version()
	}

	deadcodePath := filepath.Join(goroot, "src", "cmd", "link", "internal", "ld", "deadcode.go")
	deadcodeRaw, err := os.ReadFile(deadcodePath)
	if err != nil {
		return "", "", fmt.Errorf("read %s: %w", deadcodePath, err)
	}
	deadcodePatched, err := patchDeadcodeSource(string(deadcodeRaw))
	if err != nil {
		return "", "", err
	}

	patchKey := computePatchKey(goVersion, runtime.GOOS, runtime.GOARCH, deadcodePatched)

	if cacheDir == "" {
		userCache, err := os.UserCacheDir()
		if err != nil {
			cacheDir = filepath.Join(os.TempDir(), "gvx-slimlink")
		} else {
			cacheDir = filepath.Join(userCache, "gvx-slimlink")
		}
	}
	cacheDir, err = filepath.Abs(cacheDir)
	if err != nil {
		return "", "", fmt.Errorf("resolve cache dir: %w", err)
	}

	binName := "link"
	if runtime.GOOS == "windows" {
		binName += ".exe"
	}
	targetDir := filepath.Join(cacheDir, patchKey)
	targetBin := filepath.Join(targetDir, binName)
	if info, err := os.Stat(targetBin); err == nil && !info.IsDir() {
		return targetBin, patchKey, nil
	}

	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return "", "", fmt.Errorf("create cache dir: %w", err)
	}

	tmpDir, err := os.MkdirTemp(targetDir, "build-*")
	if err != nil {
		return "", "", fmt.Errorf("create build temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	patchedDeadcodeFile := filepath.Join(tmpDir, "deadcode.go")
	if err := os.WriteFile(patchedDeadcodeFile, []byte(deadcodePatched), 0o600); err != nil {
		return "", "", err
	}

	overlay := goOverlay{
		Replace: map[string]string{
			deadcodePath: patchedDeadcodeFile,
		},
	}
	overlayBytes, err := json.Marshal(overlay)
	if err != nil {
		return "", "", err
	}
	overlayFile := filepath.Join(tmpDir, "overlay.json")
	if err := os.WriteFile(overlayFile, overlayBytes, 0o600); err != nil {
		return "", "", err
	}

	tmpOut := filepath.Join(tmpDir, binName)
	buildCmd := exec.Command(goBin, "build", "-overlay="+overlayFile, "-o", tmpOut, "cmd/link")
	buildCmd.Dir = filepath.Join(goroot, "src")
	// Build the linker for the host OS/architecture with target microarch and
	// experiment flags scrubbed so cross-compilation never poisons the host cache.
	buildCmd.Env = replaceEnv(os.Environ(), map[string]string{
		"GOOS":         runtime.GOOS,
		"GOARCH":       runtime.GOARCH,
		"GOAMD64":      "",
		"GOARM64":      "",
		"GO386":        "",
		"GOARM":        "",
		"GOEXPERIMENT": "",
		"GOFIPS140":    "off",
		"GODEBUG":      "",
		"CGO_ENABLED":  "0",
		"GOWORK":       "off",
		"GOFLAGS":      "",
		"GOENV":        "off",
	})
	var stderr bytes.Buffer
	buildCmd.Stderr = &stderr
	if err := buildCmd.Run(); err != nil {
		return "", "", fmt.Errorf("compile patched cmd/link: %w\n%s", err, stderr.String())
	}

	if err := os.Rename(tmpOut, targetBin); err != nil {
		// Another process may have populated targetBin concurrently.
		if info, statErr := os.Stat(targetBin); statErr == nil && !info.IsDir() {
			return targetBin, patchKey, nil
		}
		return "", "", fmt.Errorf("install patched cmd/link: %w", err)
	}
	return targetBin, patchKey, nil
}

// validateAndExtractChangeDir inspects leading go build flags, rejects any
// caller-supplied -toolexec flag (which would override slimlink), and returns
// the directory specified by a leading -C / --C flag if present.
func validateAndExtractChangeDir(buildArgs []string) (string, error) {
	changeDir := ""
	rest := buildArgs
	if len(rest) >= 2 && (rest[0] == "-C" || rest[0] == "--C") {
		changeDir = rest[1]
		rest = rest[2:]
	} else if len(rest) >= 1 && strings.HasPrefix(rest[0], "-C=") {
		changeDir = strings.TrimPrefix(rest[0], "-C=")
		rest = rest[1:]
	} else if len(rest) >= 1 && strings.HasPrefix(rest[0], "--C=") {
		changeDir = strings.TrimPrefix(rest[0], "--C=")
		rest = rest[1:]
	}

	for _, arg := range rest {
		if arg == "--" {
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			continue
		}
		name := strings.TrimLeft(arg, "-")
		if name == "toolexec" || strings.HasPrefix(name, "toolexec=") {
			return "", errors.New("conflicting -toolexec flag in go build arguments")
		}
	}
	return changeDir, nil
}

func buildGoBuildArgs(toolexecArg string, buildArgs []string) []string {
	args := make([]string, 0, len(buildArgs)+2)
	args = append(args, "build")
	rest := buildArgs
	// Go requires -C / --C to be the first flag after the subcommand.
	if len(rest) >= 2 && (rest[0] == "-C" || rest[0] == "--C") {
		args = append(args, rest[0], rest[1])
		rest = rest[2:]
	} else if len(rest) >= 1 && (strings.HasPrefix(rest[0], "-C=") || strings.HasPrefix(rest[0], "--C=")) {
		args = append(args, rest[0])
		rest = rest[1:]
	}
	args = append(args, "-toolexec="+toolexecArg)
	args = append(args, rest...)
	return args
}

// joinToolexecArgs formats arguments to match Go's cmd/internal/quoted.Split.
func joinToolexecArgs(args []string) (string, error) {
	var buf []byte
	for i, arg := range args {
		if i > 0 {
			buf = append(buf, ' ')
		}
		if arg == "" {
			buf = append(buf, '\'', '\'')
			continue
		}
		var sawSpace, sawSingle, sawDouble bool
		for _, c := range arg {
			if c > unicode.MaxASCII {
				continue
			}
			switch byte(c) {
			case ' ', '\t', '\n', '\r':
				sawSpace = true
			case '\'':
				sawSingle = true
			case '"':
				sawDouble = true
			}
		}
		switch {
		case !sawSpace && !sawSingle && !sawDouble:
			buf = append(buf, arg...)
		case !sawSingle:
			buf = append(buf, '\'')
			buf = append(buf, arg...)
			buf = append(buf, '\'')
		case !sawDouble:
			buf = append(buf, '"')
			buf = append(buf, arg...)
			buf = append(buf, '"')
		default:
			return "", fmt.Errorf("argument %q contains both single and double quotes", arg)
		}
	}
	return string(buf), nil
}

func replaceEnv(env []string, overrides map[string]string) []string {
	out := make([]string, 0, len(env)+len(overrides))
	for _, kv := range env {
		key, _, ok := strings.Cut(kv, "=")
		if ok {
			if _, drop := overrides[key]; drop {
				continue
			}
		}
		out = append(out, kv)
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}
