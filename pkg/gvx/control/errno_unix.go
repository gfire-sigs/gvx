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
	"os"
	"syscall"
)

// HostErrorToLinuxErrno translates a host filesystem error into a canonical
// Linux errno constant for RPCFSResponse.Errno.
func HostErrorToLinuxErrno(err error) int {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, os.ErrNotExist), errors.Is(err, syscall.ENOENT):
		return LinuxENOENT
	case errors.Is(err, os.ErrExist), errors.Is(err, syscall.EEXIST):
		return LinuxEEXIST
	case errors.Is(err, os.ErrPermission), errors.Is(err, syscall.EACCES):
		return LinuxEACCES
	case errors.Is(err, syscall.EPERM):
		return LinuxEPERM
	case errors.Is(err, syscall.EBUSY):
		return LinuxEBUSY
	case errors.Is(err, syscall.EXDEV):
		return LinuxEXDEV
	case errors.Is(err, syscall.ENOTDIR):
		return LinuxENOTDIR
	case errors.Is(err, syscall.EISDIR):
		return LinuxEISDIR
	case errors.Is(err, syscall.ENAMETOOLONG):
		return LinuxENAMETOOLONG
	case errors.Is(err, syscall.ENOTEMPTY):
		return LinuxENOTEMPTY
	case errors.Is(err, syscall.ELOOP):
		return LinuxELOOP
	case errors.Is(err, syscall.EINVAL):
		return LinuxEINVAL
	case errors.Is(err, syscall.EROFS):
		return LinuxEROFS
	case errors.Is(err, syscall.ENOSPC):
		return LinuxENOSPC
	case errors.Is(err, syscall.EOPNOTSUPP), errors.Is(err, syscall.ENOTSUP):
		return LinuxEOPNOTSUPP
	default:
		return LinuxEIO
	}
}
