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

//go:build windows

package control

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ensureSecureSocketDir(dir string) error {
	clean := filepath.Clean(dir)
	if info, err := os.Lstat(clean); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("control socket directory %q must not be a symlink", dir)
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

func ownerOnlySecurityAttributes() (*windows.SecurityAttributes, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("query current Windows token user: %w", err)
	}
	owner := user.User.Sid.String()
	sddl := "D:P(A;;GA;;;" + owner + ")"
	if owner != "S-1-5-18" {
		sddl += "(A;;GA;;;SY)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build token file security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: sd,
	}, nil
}

func writeTokenFilePlatform(path, token string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale control token %q: %w", path, err)
	}
	sa, err := ownerOnlySecurityAttributes()
	if err != nil {
		return err
	}
	p16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode control token path %q: %w", path, err)
	}
	h, err := windows.CreateFile(
		p16,
		windows.GENERIC_WRITE,
		0,
		sa,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return fmt.Errorf("create control token %q: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
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
