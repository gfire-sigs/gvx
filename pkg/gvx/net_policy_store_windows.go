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

package gvx

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	policyWindowsDirectoryAccess = windows.FILE_READ_ATTRIBUTES | windows.FILE_TRAVERSE | windows.READ_CONTROL
	policyWindowsFileAccess      = windows.GENERIC_READ | windows.GENERIC_WRITE | windows.READ_CONTROL
	policyWindowsShare           = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
)

func openPolicyStoreFile(path string, initialize func(*os.File) error) (result *os.File, err error) {
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		return nil, fmt.Errorf("%w: expected a local drive path", errPolicyStoreUnsafe)
	}
	components := strings.Split(path[len(volume)+1:], `\`)
	for _, name := range components {
		if !filepath.IsLocal(name) || strings.ContainsAny(name, `\/:*?"<>|`) || strings.TrimRight(name, " .") != name {
			return nil, fmt.Errorf("%w: invalid Windows path component", errPolicyStoreUnsafe)
		}
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("read Windows account SID: %w", err)
	}
	installer, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		return nil, err
	}
	identity := policyWindowsIdentity{owner: user.User.Sid, trustedInstaller: installer}
	root, err := openPolicyWindowsVolume(volume + `\`)
	if err != nil {
		return nil, err
	}
	dirs := make([]windows.Handle, 1, len(components))
	dirs[0] = root
	defer func() {
		for i := len(dirs) - 1; i >= 0; i-- {
			err = errors.Join(err, windows.CloseHandle(dirs[i]))
		}
		if err != nil && result != nil {
			err = errors.Join(err, result.Close())
			result = nil
		}
	}()
	for i, name := range components[:len(components)-1] {
		if err := identity.validate(dirs[i], true, false); err != nil {
			return nil, err
		}
		next, err := openPolicyWindowsAt(dirs[i], name, policyWindowsDirectoryAccess, policyWindowsShare, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, nil)
		if err != nil {
			return nil, fmt.Errorf("open parent component %q: %w", name, err)
		}
		dirs = append(dirs, next)
	}
	parent := dirs[len(dirs)-1]
	if err := identity.validate(parent, true, true); err != nil {
		return nil, err
	}
	name := components[len(components)-1]
	if initialize != nil {
		return createPolicyWindowsFile(parent, name, identity, initialize)
	}
	h, err := openPolicyWindowsAt(parent, name, policyWindowsFileAccess, policyWindowsShare, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, nil)
	if err != nil {
		return nil, err
	}
	return lockPolicyWindowsFile(h, path, identity)
}

func openPolicyWindowsVolume(path string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	if windows.GetDriveType(name) != windows.DRIVE_FIXED {
		return 0, fmt.Errorf("%w: expected a fixed local drive", errPolicyStoreUnsafe)
	}
	h, err := windows.CreateFile(name, policyWindowsDirectoryAccess, policyWindowsShare, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, err
	}
	if err := validatePolicyWindowsVolume(h); err != nil {
		return 0, errors.Join(err, windows.CloseHandle(h))
	}
	return h, nil
}

func validatePolicyWindowsVolume(h windows.Handle) error {
	path, err := policyWindowsPath(h)
	if err != nil {
		return err
	}
	guid, ok := strings.CutPrefix(path, `\\?\Volume{`)
	if !ok || len(guid) != 38 || !strings.HasSuffix(guid, `}\`) {
		return fmt.Errorf("%w: drive does not name a volume root", errPolicyStoreUnsafe)
	}
	var flags uint32
	if err := windows.GetVolumeInformationByHandle(h, nil, 0, nil, nil, &flags, nil, 0); err != nil {
		return err
	}
	if flags&windows.FILE_PERSISTENT_ACLS == 0 {
		return fmt.Errorf("%w: volume does not support persistent ACLs", errPolicyStoreUnsafe)
	}
	return nil
}

func policyWindowsPath(h windows.Handle) (string, error) {
	const volumeNameGUID = 1
	var initial [260]uint16
	buf := initial[:]
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), volumeNameGUID)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		if n >= 32767 || len(buf) > len(initial) {
			return "", fmt.Errorf("%w: invalid Windows path length", errPolicyStoreUnsafe)
		}
		buf = make([]uint16, n+1)
	}
}

func createPolicyWindowsFile(parent windows.Handle, name string, identity policyWindowsIdentity, initialize func(*os.File) error) (result *os.File, err error) {
	dir, err := policyWindowsPath(parent)
	if err != nil {
		return nil, err
	}
	owner := identity.owner.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	stagingName := ".gvx-policy-" + hex.EncodeToString(nonce[:])
	stagingPath := filepath.Join(dir, stagingName)
	from, err := windows.UTF16PtrFromString(stagingPath)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, name)
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// MoveFileEx opens the source for delete. The retained descriptor and
	// its byte-range lock continue to refer to the same file after the move.
	h, err := openPolicyWindowsAt(parent, stagingName, policyWindowsFileAccess, policyWindowsShare|windows.FILE_SHARE_DELETE,
		windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE|windows.FILE_WRITE_THROUGH, sd)
	if err != nil {
		return nil, err
	}
	var published bool
	defer func() {
		if !published {
			err = errors.Join(err, windows.DeleteFile(from))
		}
	}()
	f, err := lockPolicyWindowsFile(h, path, identity)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result == nil {
			err = errors.Join(err, f.Close())
		}
	}()
	if err := initialize(f); err != nil {
		return nil, err
	}
	// A same-directory, write-through move publishes the name without
	// replacing an existing store or allowing a cross-volume copy.
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return nil, fmt.Errorf("publish policy store name: %w", err)
	}
	published = true
	if err := syncPolicyStoreFile(f); err != nil {
		return nil, fmt.Errorf("flush published policy store: %w", err)
	}
	return f, nil
}

func openPolicyWindowsAt(parent windows.Handle, name string, access, share, disposition, options uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory:      parent,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE,
		SecurityDescriptor: sd,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var h windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &attrs, &status, nil, windows.FILE_ATTRIBUTE_NORMAL,
		share, disposition, options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	if nt, ok := err.(windows.NTStatus); ok {
		err = nt.Errno()
	}
	return h, err
}

func lockPolicyWindowsFile(h windows.Handle, path string, identity policyWindowsIdentity) (*os.File, error) {
	if err := identity.validate(h, false, true); err != nil {
		return nil, errors.Join(err, windows.CloseHandle(h))
	}
	var offset windows.Overlapped
	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &offset); err != nil {
		return nil, errors.Join(fmt.Errorf("lock policy store: %w", err), windows.CloseHandle(h))
	}
	return os.NewFile(uintptr(h), path), nil
}

type policyWindowsIdentity struct {
	owner, trustedInstaller *windows.SID
}

func (i policyWindowsIdentity) trusted(sid *windows.SID) bool {
	return sid != nil && (sid.Equals(i.owner) || sid.Equals(i.trustedInstaller) || sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid))
}

func (i policyWindowsIdentity) validate(h windows.Handle, directory, private bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: path contains a reparse point", errPolicyStoreUnsafe)
	}
	isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != directory || (!directory && info.NumberOfLinks != 1) {
		return fmt.Errorf("%w: unexpected file type or link count", errPolicyStoreUnsafe)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if !i.trusted(owner) || (private && !owner.Equals(i.owner)) {
		return fmt.Errorf("%w: file or directory owner is not trusted", errPolicyStoreUnsafe)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%w: expected a non-null DACL", errPolicyStoreUnsafe)
	}
	return i.validateDACL(dacl, private)
}

func (i policyWindowsIdentity) validateDACL(dacl *windows.ACL, private bool) error {
	// FILE_APPEND_DATA adds a subdirectory on directories. It cannot replace
	// a verified child. FILE_WRITE_DATA also permits setting a reparse point.
	const ancestorRights = windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE | windows.GENERIC_READ |
		windows.GENERIC_EXECUTE | windows.FILE_APPEND_DATA
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("%w: unsupported Windows DACL entry", errPolicyStoreUnsafe)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !i.trusted(sid) && (private || ace.Mask&^ancestorRights != 0) {
			return fmt.Errorf("%w: unsafe Windows DACL grant", errPolicyStoreUnsafe)
		}
	}
	return nil
}

func syncPolicyStoreFile(f *os.File) error {
	return f.Sync()
}
