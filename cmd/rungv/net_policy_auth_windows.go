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

func createControlTokenFile(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	owner := user.User.Sid.String()
	sddl := "O:" + owner + "D:P(A;;FA;;;" + owner + ")"
	if owner != "S-1-5-18" {
		sddl += "(A;;FA;;;SY)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, err
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: sd}
	sa.Length = uint32(unsafe.Sizeof(sa))
	h, err := windows.CreateFile(name, windows.GENERIC_WRITE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ, &sa, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(h), path)
	if err := validateControlInput(f, true); err != nil {
		return nil, errors.Join(err, f.Close(), os.Remove(path))
	}
	return f, nil
}

func validateControlInput(f *os.File, token bool) error {
	h := windows.Handle(f.Fd())
	kind, err := windows.GetFileType(h)
	if err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	if kind != windows.FILE_TYPE_DISK || info.NumberOfLinks != 1 || info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
		return fmt.Errorf("%q is not a trusted regular file", f.Name())
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, controlSecurityInfo)
	if err != nil {
		return err
	}
	if err := validateControlDACL(sd, token); err != nil {
		return fmt.Errorf("%q: %w", f.Name(), err)
	}
	return nil
}

func validateControlDACL(sd *windows.SECURITY_DESCRIPTOR, token bool) error {
	if sd == nil {
		return errUnsafeControlDACL
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !(owner.Equals(user.User.Sid) || !token && trustedControlSID(owner)) {
		return errUnsafeControlDACL
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.Join(errUnsafeControlDACL, err)
	}
	if token {
		flags, _, err := sd.Control()
		if err != nil {
			return err
		}
		if flags&windows.SE_DACL_PROTECTED == 0 {
			return errUnsafeControlDACL
		}
	}
	const fileDeleteChild = 0x00000040
	const mutationRights = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild
	for i := range uint32(acl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, i, &ace); err != nil {
			return err
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			continue
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if !token && ace.Mask&mutationRights == 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			if sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinLocalSystemSid) || !token && sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
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
