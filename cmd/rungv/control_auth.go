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
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// TCP and Windows AF_UNIX connections require a per-run token. POSIX Unix
// connections use filesystem permissions instead.

const (
	controlTokenBytes = 32

	// maxControlTokenFileBytes bounds the read of a token file.
	maxControlTokenFileBytes = 256
)

// controlTokenRequired reports whether a listener on network and the current
// host OS needs a request token.
func controlTokenRequired(network string) bool {
	return network == "tcp" || runtime.GOOS == "windows"
}

// controlTokenDir returns the owner-only directory for the token files of TCP
// listeners.
func controlTokenDir() (string, error) {
	if base, err := os.UserCacheDir(); err == nil && base != "" {
		return filepath.Join(base, "gvx", "control"), nil
	}
	if runtime.GOOS == "windows" {
		return "", errors.New("Windows user cache directory is unavailable")
	}
	return filepath.Join(os.TempDir(), "gvx-control-"+strconv.Itoa(os.Getuid())), nil
}

// controlTokenPath returns the token file for the endpoint. A Unix socket
// keeps its token beside the socket. A TCP endpoint keeps it in the control
// directory of the user, named by the port.
func controlTokenPath(network, address string) (string, error) {
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

// newControlToken returns a random token as a hexadecimal string.
func newControlToken() (string, error) {
	raw := make([]byte, controlTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate control token: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Replace stale tokens only after binding the corresponding endpoint.
func writeControlToken(path, token string, protected bool) (string, error) {
	dir, err := privatePolicyControlDir(filepath.Dir(path), true)
	if err != nil {
		return "", err
	}
	path = filepath.Join(dir, filepath.Base(path))
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("control token path %q is not a regular file", path)
		}
		if protected {
			if _, err := readControlTokenFile(path); err != nil {
				return "", fmt.Errorf("verify stale control token: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove stale control token %q: %w", path, err)
	}
	f, err := createControlTokenFile(path)
	if err != nil {
		return "", fmt.Errorf("create control token %q: %w", path, err)
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write control token %q: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("close control token %q: %w", path, err)
	}
	return path, nil
}

// A missing token is permitted only on transports that do not require one.
func readControlToken(network, address string) (string, error) {
	if !controlTokenRequired(network) {
		return "", nil
	}
	path, err := controlTokenPath(network, address)
	if err != nil {
		return "", err
	}
	dir, err := privatePolicyControlDir(filepath.Dir(path), false)
	if err != nil {
		return "", err
	}
	return readControlTokenFile(filepath.Join(dir, filepath.Base(path)))
}

func readControlTokenFile(path string) (string, error) {
	f, err := openControlInput(path, true)
	if err != nil {
		return "", fmt.Errorf("read control token: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxControlTokenFileBytes+1))
	if err := errors.Join(err, f.Close()); err != nil {
		return "", fmt.Errorf("read control token %q: %w", path, err)
	}
	if len(data) > maxControlTokenFileBytes {
		return "", errors.New("invalid control token file")
	}
	for len(data) > 0 && (data[len(data)-1] == '\n' || data[len(data)-1] == '\r') {
		data = data[:len(data)-1]
	}
	var decoded [controlTokenBytes]byte
	if len(data) != hex.EncodedLen(len(decoded)) {
		return "", errors.New("invalid control token file")
	}
	if _, err := hex.Decode(decoded[:], data); err != nil {
		return "", errors.New("invalid control token file")
	}
	return string(data), nil
}

// controlTokenMatches compares a presented token with the expected one in
// constant time. An empty expected token accepts every request.
func controlTokenMatches(expected, presented string) bool {
	if expected == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}

func privatePolicyControlDir(dir string, create bool) (string, error) {
	if create {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", fmt.Errorf("create private control directory %q: %w", dir, err)
		}
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", fmt.Errorf("control directory %q is not a directory or is a link", dir)
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return "", err
	}
	if err := validateControlDirectory(dir); err != nil {
		return "", fmt.Errorf("control directory %q: %w", dir, err)
	}
	return dir, nil
}

func validateControlStatePaths(statePath, endpointPath string) error {
	state, err := canonicalControlPath(statePath)
	if err != nil {
		return err
	}
	endpoint, err := canonicalControlPath(endpointPath)
	if err != nil {
		return err
	}
	if state == endpoint || runtime.GOOS == "windows" && strings.EqualFold(state, endpoint) {
		return errors.New("state_mismatch: control endpoint overlaps the network policy store")
	}
	a, aErr := os.Stat(state)
	b, bErr := os.Stat(endpoint)
	for _, err := range []error{aErr, bErr} {
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if aErr == nil && bErr == nil && os.SameFile(a, b) {
		return errors.New("state_mismatch: control endpoint aliases the network policy store")
	}
	return nil
}

func canonicalControlPath(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return resolveExistingControlPrefix(path)
}

func resolveExistingControlPrefix(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err == nil {
		return resolved, nil
	}
	parent := filepath.Dir(path)
	if !errors.Is(err, os.ErrNotExist) || parent == path {
		return "", err
	}
	dir, err := resolveExistingControlPrefix(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, filepath.Base(path)), nil
}
