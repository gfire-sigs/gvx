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
)

// Control token rules: a loopback TCP listener and any Windows AF_UNIX
// listener have no owner-only file mode, so every request on them carries a
// per-run secret. The listener process writes the secret to a 0600 token file
// before it binds, and `rungv checkpoint` of the same user reads that file.
// A POSIX Unix socket relies on its 0600 mode and has no token.

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

// writeControlToken creates a fresh 0600 token file at path. It removes an
// older file first, so a stale or pre-created file never supplies the token.
func writeControlToken(path, token string) error {
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

// readControlToken returns the token that the listener of the endpoint
// published. A missing file returns an empty token and no error, because a
// POSIX Unix socket has no token.
func readControlToken(network, address string) (string, error) {
	path, err := controlTokenPath(network, address)
	if err != nil {
		return "", err
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read control token: %w", err)
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

// controlTokenMatches compares a presented token with the expected one in
// constant time. An empty expected token accepts every request.
func controlTokenMatches(expected, presented string) bool {
	if expected == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(presented)) == 1
}
