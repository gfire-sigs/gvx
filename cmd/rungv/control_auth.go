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
	"sync"
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
	if dir, err := appControlTokenDir(); dir != "" || err != nil {
		return dir, err
	}
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

type controlTokenTarget interface {
	verifyRegular() error
	open() (*os.File, error)
	create() (*os.File, error)
	remove() error
	removeIfSame(*os.File) error
}

func openControlTokenTarget(network, path string, create bool) (controlTokenTarget, func() error, error) {
	if network == "tcp" {
		if target, closeTarget, err := openAppControlTokenTarget(path, create); target != nil || err != nil {
			return target, closeTarget, err
		}
	}
	return openPathControlTokenTarget(path, create)
}

type controlTokenArtifact struct {
	file   *os.File
	finish func(remove bool)
}

// Replace stale tokens only after binding the corresponding endpoint.
func writeControlToken(network, path, token string, protected bool) (controlTokenArtifact, error) {
	target, closeTarget, err := openControlTokenTarget(network, path, true)
	if err != nil {
		return controlTokenArtifact{}, err
	}
	f, err := publishControlToken(target, token, protected)
	if err != nil {
		if closeTarget != nil {
			err = errors.Join(err, closeTarget())
		}
		return controlTokenArtifact{}, fmt.Errorf("publish control token %q: %w", path, err)
	}
	if runtime.GOOS == "windows" {
		// Windows removes the token by file handle, not through the directories.
		if err := closeTarget(); err != nil {
			return controlTokenArtifact{}, errors.Join(err, target.removeIfSame(f), f.Close())
		}
		closeTarget = nil
	}
	var once sync.Once
	finish := func(remove bool) {
		once.Do(func() {
			if remove {
				_ = target.removeIfSame(f)
			}
			_ = f.Close()
			if closeTarget != nil {
				_ = closeTarget()
			}
		})
	}
	return controlTokenArtifact{file: f, finish: finish}, nil
}

func publishControlToken(target controlTokenTarget, token string, protected bool) (*os.File, error) {
	if err := target.verifyRegular(); err == nil {
		if protected {
			if _, err := readControlTokenFile(target.open()); err != nil {
				return nil, fmt.Errorf("verify stale control token: %w", err)
			}
		}
		if err := target.remove(); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("remove stale control token: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	f, err := target.create()
	if err != nil {
		return nil, fmt.Errorf("create control token: %w", err)
	}
	if _, err := f.WriteString(token + "\n"); err != nil {
		return nil, errors.Join(err, target.removeIfSame(f), f.Close())
	}
	pinned, err := pinControlTokenFile(target, f)
	if err != nil {
		return nil, errors.Join(err, target.removeIfSame(f), f.Close())
	}
	if err := f.Close(); err != nil {
		return nil, errors.Join(err, target.removeIfSame(pinned), pinned.Close())
	}
	return pinned, nil
}

func controlTokenFileName(f *os.File) string {
	if f == nil {
		return ""
	}
	return f.Name()
}

// A missing token is permitted only on transports that do not require one.
func readControlToken(network, address string) (token string, err error) {
	if !controlTokenRequired(network) {
		return "", nil
	}
	path, err := controlTokenPath(network, address)
	if err != nil {
		return "", err
	}
	target, closeTarget, err := openControlTokenTarget(network, path, false)
	if err != nil {
		return "", err
	}
	if closeTarget != nil {
		defer func() { err = errors.Join(err, closeTarget()) }()
	}
	return readControlTokenFile(target.open())
}

func readControlTokenFile(f *os.File, err error) (string, error) {
	if err != nil {
		return "", fmt.Errorf("read control token: %w", err)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxControlTokenFileBytes+1))
	if err := errors.Join(err, f.Close()); err != nil {
		return "", fmt.Errorf("read control token %q: %w", f.Name(), err)
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
