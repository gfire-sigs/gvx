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

package control

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	controlTokenBytes        = 32
	maxControlTokenFileBytes = 256
	// maxUnixSunPath leaves safety room under macOS's 104-byte sockaddr_un.sun_path.
	maxUnixSunPath = 100
)

var sandboxNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]+$`)

// Endpoint holds a bound control listener, its request token, and pre-lockdown cleanup.
type Endpoint struct {
	Network   string
	Address   string
	Listener  net.Listener
	Token     string
	TokenPath string
	// Cleanup removes the socket file and token file. Call only before host lockdown.
	Cleanup func()
}

// ListenOptions configures Listen.
type ListenOptions struct {
	// TokenFile overrides the default token file path and forces token auth even
	// on POSIX Unix domain sockets.
	TokenFile string
}

// ParseEndpoint resolves a raw socket specification into a net.Listen / net.Dial
// network and address pair. It accepts Unix paths and loopback TCP addresses.
func ParseEndpoint(raw string) (network, address string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("control socket address is empty")
	}
	if strings.HasPrefix(s, "tcp://") {
		addr := strings.TrimPrefix(s, "tcp://")
		if err := validateLoopbackTCPAddr(addr); err != nil {
			return "", "", err
		}
		return "tcp", addr, nil
	}
	if strings.HasPrefix(s, "unix://") {
		return "unix", strings.TrimPrefix(s, "unix://"), nil
	}
	if strings.HasPrefix(s, "unix:") {
		return "unix", strings.TrimPrefix(s, "unix:"), nil
	}
	if !strings.ContainsAny(s, `/\`) {
		if host, port, splitErr := net.SplitHostPort(s); splitErr == nil && port != "" {
			if host == "localhost" {
				return "tcp", s, nil
			}
			if ip := net.ParseIP(host); ip != nil {
				if !ip.IsLoopback() {
					return "", "", fmt.Errorf("control TCP socket must bind a loopback address, got %q", s)
				}
				return "tcp", s, nil
			}
		}
	}
	return "unix", s, nil
}

func validateLoopbackTCPAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return fmt.Errorf("invalid TCP control socket address %q", addr)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("control TCP socket must bind a loopback address, got %q", addr)
	}
	return nil
}

// NamedSocketPath returns the owner-only runtime Unix socket path for a named
// sandbox launched with --control.
func NamedSocketPath(name string) (string, error) {
	name = strings.TrimSpace(name)
	if !sandboxNamePattern.MatchString(name) {
		return "", fmt.Errorf("invalid sandbox name %q (want [a-zA-Z0-9][a-zA-Z0-9_.-]+)", name)
	}
	dir, err := runtimeSocketDir()
	if err != nil {
		return "", err
	}
	sock := filepath.Join(dir, name+".sock")
	if runtime.GOOS != "windows" && len(sock) > maxUnixSunPath {
		return "", fmt.Errorf("control socket path %q exceeds %d bytes", sock, maxUnixSunPath)
	}
	return sock, nil
}

func runtimeSocketDir() (string, error) {
	if runtime.GOOS == "windows" {
		base, err := os.UserCacheDir()
		if err != nil || base == "" {
			return filepath.Join(os.TempDir(), "gvx-run"), nil
		}
		return filepath.Join(base, "gvx", "run"), nil
	}
	if runtime.GOOS == "linux" {
		if xdg := strings.TrimSpace(os.Getenv("XDG_RUNTIME_DIR")); xdg != "" {
			cand := filepath.Join(xdg, "gvx")
			if len(cand)+40 <= maxUnixSunPath {
				return cand, nil
			}
		}
	}
	// macOS sockaddr_un.sun_path is limited to 104 bytes; use a short uid-scoped
	// directory under /tmp rather than ~/Library/Caches.
	return filepath.Join("/tmp", "gvx-run-"+strconv.Itoa(os.Geteuid())), nil
}

// TokenRequired reports whether a listener on network requires a per-run token
// by default on the current host OS.
func TokenRequired(network string) bool {
	return network == "tcp" || runtime.GOOS == "windows"
}

func controlTokenDir() (string, error) {
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		return filepath.Join(base, "gvx", "control"), nil
	}
	return filepath.Join(os.TempDir(), "gvx-control-"+strconv.Itoa(os.Getuid())), nil
}

// DefaultTokenPath returns the default token file path for an endpoint.
func DefaultTokenPath(network, address string) (string, error) {
	if network == "unix" {
		return address + ".token", nil
	}
	_, port, err := net.SplitHostPort(address)
	if err != nil || port == "" {
		return "", fmt.Errorf("invalid TCP control address %q", address)
	}
	dir, err := controlTokenDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "tcp-"+port+".token"), nil
}

// NewToken generates a random 256-bit hexadecimal token.
func NewToken() (string, error) {
	raw := make([]byte, controlTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate control token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

func writeTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create control token directory %q: %w", dir, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale control token %q: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create control token %q: %w", path, err)
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write control token %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close control token %q: %w", path, err)
	}
	return nil
}

// ReadToken reads a control token from overridePath when set, or from the
// default token path for (network, address). A missing default file returns an
// empty token without error because POSIX Unix sockets do not require one.
func ReadToken(network, address, overridePath string) (string, error) {
	path := strings.TrimSpace(overridePath)
	explicit := path != ""
	if !explicit {
		var err error
		path, err = DefaultTokenPath(network, address)
		if err != nil {
			return "", err
		}
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) && !explicit {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read control token %q: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxControlTokenFileBytes))
	if err != nil {
		return "", fmt.Errorf("read control token %q: %w", path, err)
	}
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	return string(data), nil
}

// TokenMatches compares expected and presented tokens in constant time. An empty
// expected token accepts every request.
func TokenMatches(expected, presented string) bool {
	if expected == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

// Listen binds an owner-only control listener before host lockdown applies.
// Token files are written only after bind succeeds so a failed bind never
// overwrites the token of a live listener.
func Listen(raw string, opts ListenOptions) (*Endpoint, error) {
	network, address, err := ParseEndpoint(raw)
	if err != nil {
		return nil, err
	}

	var token, tokenPath string
	needToken := TokenRequired(network) || strings.TrimSpace(opts.TokenFile) != ""
	if needToken {
		if token, err = NewToken(); err != nil {
			return nil, err
		}
		if strings.TrimSpace(opts.TokenFile) != "" {
			tokenPath = strings.TrimSpace(opts.TokenFile)
		} else if tokenPath, err = DefaultTokenPath(network, address); err != nil {
			return nil, err
		}
	}
	removeToken := func() {
		if tokenPath != "" {
			_ = os.Remove(tokenPath)
		}
	}

	if network == "tcp" {
		ln, err := net.Listen("tcp", address)
		if err != nil {
			return nil, err
		}
		actualAddr := ln.Addr().String()
		if tokenPath != "" && strings.TrimSpace(opts.TokenFile) == "" {
			if tokenPath, err = DefaultTokenPath("tcp", actualAddr); err != nil {
				_ = ln.Close()
				return nil, err
			}
		}
		if tokenPath != "" {
			if err := writeTokenFile(tokenPath, token); err != nil {
				_ = ln.Close()
				return nil, err
			}
		}
		return &Endpoint{
			Network:   "tcp",
			Address:   actualAddr,
			Listener:  ln,
			Token:     token,
			TokenPath: tokenPath,
			Cleanup:   removeToken,
		}, nil
	}

	parent := filepath.Dir(address)
	if parent != "" && parent != "." {
		if err := ensureSecureSocketDir(parent); err != nil {
			return nil, err
		}
	}
	if fi, err := os.Lstat(address); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("control socket path %q already exists and is not a socket", address)
		}
		// Probe whether a live listener already serves this socket before replacing it.
		if probe, dialErr := net.DialTimeout("unix", address, 100*time.Millisecond); dialErr == nil {
			_ = probe.Close()
			return nil, fmt.Errorf("control socket %q is already in use by a live sandbox", address)
		}
		if err := os.Remove(address); err != nil {
			return nil, fmt.Errorf("remove stale control socket %q: %w", address, err)
		}
	}
	ln, err := net.Listen("unix", address)
	if err != nil {
		return nil, err
	}
	if ul, ok := ln.(*net.UnixListener); ok {
		ul.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(address, 0o600); err != nil && runtime.GOOS != "windows" {
		_ = ln.Close()
		_ = os.Remove(address)
		return nil, fmt.Errorf("chmod control socket %q: %w", address, err)
	}
	if tokenPath != "" {
		if err := writeTokenFile(tokenPath, token); err != nil {
			_ = ln.Close()
			_ = os.Remove(address)
			return nil, err
		}
	}
	cleanup := func() {
		_ = os.Remove(address)
		removeToken()
	}
	return &Endpoint{
		Network:   "unix",
		Address:   address,
		Listener:  ln,
		Token:     token,
		TokenPath: tokenPath,
		Cleanup:   cleanup,
	}, nil
}

func ensureSecureSocketDir(dir string) error {
	clean := filepath.Clean(dir)
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			// On macOS, /tmp is a system symlink to private/tmp.
			if clean != "/tmp" {
				return fmt.Errorf("control socket directory %q must not be a symlink", dir)
			}
			resolved, statErr := os.Stat(clean)
			if statErr != nil || !resolved.IsDir() {
				return fmt.Errorf("control socket directory %q is not a directory", dir)
			}
			return nil
		}
		if !info.IsDir() {
			return fmt.Errorf("control socket directory %q is not a directory", dir)
		}
		return nil
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("create control socket directory %q: %w", dir, err)
	}
	return nil
}
