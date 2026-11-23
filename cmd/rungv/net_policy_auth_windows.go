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
	"net"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const controlSecurityInfo = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION

func controlConnectionRefused(err error) bool {
	return errors.Is(err, windows.WSAECONNREFUSED)
}

// Windows Unix sockets require a token and cannot use POSIX peer credentials.
func controlUnixPeerOwned(net.Conn) bool { return false }

func validateControlDirectory(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, controlSecurityInfo)
	if err != nil {
		return err
	}
	return validateControlDACL(sd, false)
}

func validatePolicySocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("control path is not a socket")
	}
	return nil
}

func openControlInput(path string, token bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	if err := validateControlInput(f, token); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func newControlTokenDACL(user *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	owner := user.String()
	sddl := "O:" + owner + "D:P(A;;FA;;;" + owner + ")"
	if !user.IsWellKnown(windows.WinLocalSystemSid) {
		sddl += "(A;;FA;;;SY)"
	}
	return windows.SecurityDescriptorFromString(sddl)
}

var reopenControlToken = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReOpenFile")

func pinControlTokenFile(_ controlTokenTarget, f *os.File) (*os.File, error) {
	// Reopen by handle so the retained identity does not keep a writer open.
	h, err := reopenTokenHandle(f, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(h), f.Name()), nil
}

func reopenTokenHandle(f *os.File, access uint32) (windows.Handle, error) {
	h, _, err := reopenControlToken.Call(f.Fd(), uintptr(access), windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, 0)
	runtime.KeepAlive(f)
	if windows.Handle(h) == windows.InvalidHandle {
		return windows.InvalidHandle, err
	}
	return windows.Handle(h), nil
}

func validateControlInput(f *os.File, token bool) error {
	sd, err := controlFileSecurity(windows.Handle(f.Fd()))
	runtime.KeepAlive(f)
	if err == nil {
		err = validateControlDACL(sd, token)
	}
	if err != nil {
		return fmt.Errorf("%q: %w", f.Name(), err)
	}
	return nil
}

func controlFileSecurity(h windows.Handle) (*windows.SECURITY_DESCRIPTOR, error) {
	kind, err := windows.GetFileType(h)
	if err != nil {
		return nil, err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return nil, err
	}
	if kind != windows.FILE_TYPE_DISK || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return nil, errors.New("not a trusted regular file")
	}
	return windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, controlSecurityInfo)
}

type controlDACLKind uint8

const (
	controlPolicyInput controlDACLKind = iota
	controlProtectedToken
	controlCheckpointToken
	controlCheckpointAncestor
)

func validateControlDACL(sd *windows.SECURITY_DESCRIPTOR, token bool) error {
	kind := controlPolicyInput
	if token {
		kind = controlProtectedToken
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	return validateControlDACLFor(sd, user.User.Sid, kind)
}

func validateControlDACLFor(sd *windows.SECURITY_DESCRIPTOR, user *windows.SID, kind controlDACLKind) error {
	if sd == nil {
		return errUnsafeControlDACL
	}
	token := kind == controlProtectedToken || kind == controlCheckpointToken
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !(owner.Equals(user) || !token && trustedControlSID(owner) ||
		kind == controlCheckpointAncestor && isWindowsServicingSID(owner)) {
		return errUnsafeControlDACL
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.Join(errUnsafeControlDACL, err)
	}
	if kind == controlProtectedToken {
		flags, _, err := sd.Control()
		if err != nil {
			return err
		}
		if flags&windows.SE_DACL_PROTECTED == 0 {
			return errUnsafeControlDACL
		}
	}
	const fileDeleteChild = 0x00000040
	mutationRights := windows.ACCESS_MASK(windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild)
	if kind == controlCheckpointAncestor {
		// Add-file and add-directory rights cannot replace an existing child.
		mutationRights &^= windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	}
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if kind == controlCheckpointAncestor && ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
				continue
			}
			if !token && ace.Mask&mutationRights == 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
				!token && sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
				kind == controlCheckpointAncestor && isWindowsServicingSID(sid) {
				continue
			}
		}
		return errUnsafeControlDACL
	}
	return nil
}

var errUnsafeControlDACL = errors.New("control path has an unsafe owner or DACL")

func trustedControlSID(sid *windows.SID) bool {
	return sid.IsWellKnown(windows.WinLocalSystemSid) || sid.IsWellKnown(windows.WinBuiltinAdministratorsSid)
}

func isWindowsServicingSID(sid *windows.SID) bool {
	// The Windows Modules Installer service can own system directories.
	const trustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	return sid.String() == trustedInstaller
}
