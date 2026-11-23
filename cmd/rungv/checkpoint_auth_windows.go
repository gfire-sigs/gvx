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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func readCheckpointControlToken(network, address string) (string, error) {
	path, err := controlTokenPath(network, address)
	if err != nil {
		return "", err
	}
	target, err := openWindowsControlTokenTarget(path, false, controlCheckpointAncestor)
	if err != nil {
		return "", err
	}
	token, err := readControlTokenFile(target.openToken(controlCheckpointToken))
	return token, errors.Join(err, target.close())
}

func validateUnixControlTokenPath(address string, create bool) error {
	if !validControlPathComponent(filepath.Base(address)) {
		return errInvalidControlPathComponent
	}
	target, err := openWindowsControlTokenTarget(address+".token", create, controlPolicyInput)
	if err != nil {
		return err
	}
	return target.close()
}

type windowsControlTokenTarget struct {
	dirs       []windows.Handle
	path, name string
	user       *windows.SID
}

func openPathControlTokenTarget(path string, create bool) (controlTokenTarget, func() error, error) {
	target, err := openWindowsControlTokenTarget(path, create, controlPolicyInput)
	if err != nil {
		return nil, nil, err
	}
	return target, target.close, nil
}

const (
	controlDirectoryAccess   = windows.FILE_TRAVERSE | windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL
	controlDirectoryShare    = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE
	controlFileShare         = windows.FILE_SHARE_READ | windows.FILE_SHARE_DELETE
	controlPathWithoutVolume = 4 // VOLUME_NAME_NONE
)

func openWindowsControlTokenTarget(path string, create bool, parentKind controlDACLKind) (_ *windowsControlTokenTarget, err error) {
	path, err = filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	volume := filepath.VolumeName(path)
	drive := strings.TrimPrefix(volume, `\\?\`)
	if len(drive) != 2 || drive[1] != ':' {
		return nil, errors.New("checkpoint token must be on a local drive")
	}
	root, err := windows.UTF16PtrFromString(volume + `\`)
	if err != nil {
		return nil, err
	}
	driveType := windows.GetDriveType(root)
	if driveType == windows.DRIVE_REMOTE || driveType == windows.DRIVE_UNKNOWN || driveType == windows.DRIVE_NO_ROOT_DIR {
		return nil, errors.New("checkpoint token must be on a local drive")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	parent, err := windows.CreateFile(root, controlDirectoryAccess, controlDirectoryShare, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	// Keep each directory bound until the token is open. Disallow delete sharing.
	target := &windowsControlTokenTarget{dirs: []windows.Handle{parent}, user: user.User.Sid}
	defer func() {
		if err != nil {
			err = errors.Join(err, target.close())
		}
	}()
	physicalRoot, err := controlFinalPath(parent, controlPathWithoutVolume)
	if err != nil {
		return nil, err
	}
	if physicalRoot != `\` {
		return nil, errors.New("checkpoint token drive must start at a physical volume root")
	}
	remaining := path[len(volume)+1:]
	for {
		component, tail, more := strings.Cut(remaining, `\`)
		kind := controlCheckpointAncestor
		if !more {
			kind = parentKind
		}
		if err := validateCheckpointTokenDirectory(parent, target.user, kind); err != nil {
			return nil, fmt.Errorf("control directory %q: %w", filepath.Dir(path), err)
		}
		if !more {
			if !validControlPathComponent(remaining) {
				return nil, errInvalidControlPathComponent
			}
			canonical, err := controlFinalPath(parent, 0)
			if err != nil {
				return nil, err
			}
			target.path, target.name = filepath.Join(canonical, remaining), remaining
			return target, nil
		}
		child, err := openRelativeControl(parent, component, controlDirectoryAccess, windows.FILE_DIRECTORY_FILE, controlDirectoryShare, windows.FILE_OPEN, nil)
		if errors.Is(err, os.ErrNotExist) && create {
			child, err = openRelativeControl(parent, component, controlDirectoryAccess, windows.FILE_DIRECTORY_FILE, controlDirectoryShare, windows.FILE_OPEN_IF, nil)
		}
		if err != nil {
			return nil, err
		}
		target.dirs = append(target.dirs, child)
		parent, remaining = child, tail
	}
}

func (t *windowsControlTokenTarget) close() error {
	var err error
	for _, dir := range t.dirs {
		err = errors.Join(err, windows.CloseHandle(dir))
	}
	return err
}

func (t *windowsControlTokenTarget) openToken(kind controlDACLKind) (*os.File, error) {
	h, err := openRelativeControl(t.dirs[len(t.dirs)-1], t.name, windows.FILE_GENERIC_READ, windows.FILE_NON_DIRECTORY_FILE,
		windows.FILE_SHARE_READ, windows.FILE_OPEN, nil)
	if err != nil {
		return nil, err
	}
	sd, err := controlFileSecurity(h)
	if err == nil {
		err = validateControlDACLFor(sd, t.user, kind)
	}
	if err != nil {
		return nil, errors.Join(err, windows.CloseHandle(h))
	}
	return os.NewFile(uintptr(h), t.path), nil
}

func (t *windowsControlTokenTarget) open() (*os.File, error) {
	return t.openToken(controlProtectedToken)
}

func (t *windowsControlTokenTarget) create() (*os.File, error) {
	sd, err := newControlTokenDACL(t.user)
	if err != nil {
		return nil, err
	}
	h, err := t.openHandle(windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_CREATE, sd)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(h), t.path)
	if err := validateControlInput(f, true); err != nil {
		return nil, errors.Join(err, t.removeIfSame(f), f.Close())
	}
	return f, nil
}

func (t *windowsControlTokenTarget) openHandle(access, disposition uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	return openRelativeControl(t.dirs[len(t.dirs)-1], t.name, access|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_NON_DIRECTORY_FILE, controlFileShare, disposition, sd)
}

func (t *windowsControlTokenTarget) verifyRegular() error {
	h, err := t.openHandle(windows.FILE_READ_ATTRIBUTES, windows.FILE_OPEN, nil)
	if err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(h, &info)
	if err == nil && info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		err = errors.New("control token is not a regular file")
	}
	return errors.Join(err, windows.CloseHandle(h))
}

func (t *windowsControlTokenTarget) remove() error {
	h, err := t.openHandle(windows.DELETE, windows.FILE_OPEN, nil)
	if err != nil {
		return err
	}
	return deleteControlTokenHandle(h)
}

func (t *windowsControlTokenTarget) removeIfSame(f *os.File) error {
	h, err := reopenTokenHandle(f, windows.DELETE)
	if err != nil {
		return err
	}
	return deleteControlTokenHandle(h)
}

func deleteControlTokenHandle(h windows.Handle) error {
	remove := byte(1)
	return errors.Join(windows.SetFileInformationByHandle(h, windows.FileDispositionInfo, &remove, 1), windows.CloseHandle(h))
}

var errInvalidControlPathComponent = errors.New("invalid Windows checkpoint token path component")

func validControlPathComponent(name string) bool {
	return name != "" && !strings.ContainsAny(name, `/:\`) && strings.TrimRight(name, ". ") == name
}

func openRelativeControl(parent windows.Handle, name string, access, options, share, disposition uint32, sd *windows.SECURITY_DESCRIPTOR) (windows.Handle, error) {
	if !validControlPathComponent(name) {
		return windows.InvalidHandle, errInvalidControlPathComponent
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory:      parent,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: sd,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE, &attrs, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, share, disposition,
		options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(attrs)
	if err != nil {
		var status windows.NTStatus
		if errors.As(err, &status) {
			err = status.Errno()
		}
		return windows.InvalidHandle, &os.PathError{Op: "open", Path: name, Err: err}
	}
	actual, err := controlFinalPath(h, controlPathWithoutVolume)
	if err == nil && !strings.EqualFold(filepath.Base(actual), name) {
		err = fmt.Errorf("ambiguous Windows control path component %q", name)
	}
	if err != nil {
		return windows.InvalidHandle, errors.Join(err, windows.CloseHandle(h))
	}
	return h, nil
}

func controlFinalPath(h windows.Handle, flags uint32) (string, error) {
	var initial [windows.MAX_PATH]uint16
	buf := initial[:]
	for {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), flags)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buf)) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, n+1)
	}
}

func validateCheckpointTokenDirectory(h windows.Handle, user *windows.SID, kind controlDACLKind) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != windows.FILE_ATTRIBUTE_DIRECTORY {
		return errors.New("not a trusted directory")
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, controlSecurityInfo)
	if err != nil {
		return err
	}
	return validateControlDACLFor(sd, user, kind)
}
