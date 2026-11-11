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

package erofs

import (
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// listXattr returns the extended attribute names visible to creds.
func (i *inode) listXattr(creds *auth.Credentials, size uint64) ([]string, error) {
	all, err := i.ListXattrs()
	if err != nil {
		return nil, err
	}
	// Linux fs/xattr.c:simple_xattr_list() hides the trusted namespace from
	// unprivileged callers.
	haveCap := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	names := all[:0]
	listSize := 0
	for _, n := range all {
		if !haveCap && strings.HasPrefix(n, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names = append(names, n)
		listSize += len(n) + 1
	}
	if size != 0 && uint64(listSize) > size {
		return nil, linuxerr.ERANGE
	}
	return names, nil
}

// getXattr returns the value of the extended attribute named by opts.Name.
func (i *inode) getXattr(creds *auth.Credentials, opts *vfs.GetXattrOptions) (string, error) {
	// Linux fs/xattr.c:xattr_permission() verifies read permission on the file
	// before namespace permissions.
	if vfs.XattrReadNeedsFilePermission(opts.Name) {
		if err := i.checkPermissions(creds, vfs.MayRead); err != nil {
			return "", err
		}
	}
	if err := vfs.CheckXattrPermissions(creds, vfs.MayRead, linux.FileMode(i.Mode()), auth.KUID(i.UID()), opts.Name); err != nil {
		return "", err
	}
	value, err := i.GetXattr(opts.Name)
	if err != nil {
		return "", err
	}
	if opts.Size != 0 && uint64(len(value)) > opts.Size {
		return "", linuxerr.ERANGE
	}
	if opts.Name == linux.XATTR_SECURITY_CAPABILITY {
		return auth.FixupVfsCapDataOnGet(creds, string(value))
	}
	return string(value), nil
}
