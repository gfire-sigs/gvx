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

//go:build !windows

package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func ensureSecureSocketDir(dir string) error {
	clean := filepath.Clean(dir)
	requirePrivate := isManagedControlDir(clean)
	if info, err := os.Lstat(clean); err == nil {
		return verifyUnixSocketDir(dir, clean, info, requirePrivate)
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("create control socket directory %q: %w", dir, err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return fmt.Errorf("stat control socket directory %q: %w", dir, err)
	}
	return verifyUnixSocketDir(dir, clean, info, requirePrivate)
}

func verifyUnixSocketDir(rawDir, clean string, info os.FileInfo, requirePrivate bool) error {
	if info.Mode()&os.ModeSymlink != 0 {
		// On macOS, /tmp is a system symlink to private/tmp.
		if clean != "/tmp" || requirePrivate {
			return fmt.Errorf("control socket directory %q must not be a symlink", rawDir)
		}
		resolved, statErr := os.Stat(clean)
		if statErr != nil || !resolved.IsDir() {
			return fmt.Errorf("control socket directory %q is not a directory", rawDir)
		}
		info = resolved
	}
	if !info.IsDir() {
		return fmt.Errorf("control socket directory %q is not a directory", rawDir)
	}
	// Shared system temp roots with sticky bit prevent cross-user unlinking.
	if !requirePrivate && info.Mode()&os.ModeSticky != 0 && (clean == "/tmp" || clean == "/private/tmp" || clean == filepath.Clean(os.TempDir())) {
		return nil
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("inspect ownership of control socket directory %q", rawDir)
	}
	wantUID := uint32(os.Geteuid())
	if st.Uid != wantUID {
		return fmt.Errorf("control socket directory %q is owned by uid %d (want %d)", rawDir, st.Uid, wantUID)
	}
	perm := info.Mode().Perm()
	if requirePrivate {
		if perm&0o077 != 0 {
			return fmt.Errorf("control socket directory %q has unsafe permissions %04o (want 0700)", rawDir, perm)
		}
	} else if perm&0o022 != 0 {
		return fmt.Errorf("control socket directory %q is group- or world-writable (%04o)", rawDir, perm)
	}
	return nil
}

func writeTokenFilePlatform(path, token string) error {
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
