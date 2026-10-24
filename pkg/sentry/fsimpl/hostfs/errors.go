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

package hostfs

import (
	"errors"
	"io/fs"
	"os"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// translateHostError converts an error from the workspace or host layer into
// the Linux errno that guest code observes. An unrecognized error becomes EIO
// so that no host detail leaks to the guest.
func translateHostError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrReadOnly):
		return linuxerr.EROFS
	case errors.Is(err, ErrPathTraversal):
		return linuxerr.EACCES
	case errors.Is(err, errReservedName), errors.Is(err, errNotPermitted):
		return linuxerr.EPERM
	case errors.Is(err, errNotEmpty):
		return linuxerr.ENOTEMPTY
	case errors.Is(err, errNotDir):
		return linuxerr.ENOTDIR
	case errors.Is(err, errIsDir):
		return linuxerr.EISDIR
	case errors.Is(err, errInvalidMove), errors.Is(err, errInvalidHostName):
		return linuxerr.EINVAL
	case errors.Is(err, errNameTooLong):
		return linuxerr.ENAMETOOLONG
	case errors.Is(err, errHostUnsupported):
		return linuxerr.EOPNOTSUPP
	case errors.Is(err, os.ErrClosed):
		return linuxerr.EIO
	}
	if le, ok := hostErrno(err); ok {
		return le
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return linuxerr.ENOENT
	case errors.Is(err, fs.ErrExist):
		return linuxerr.EEXIST
	case errors.Is(err, fs.ErrPermission):
		return linuxerr.EACCES
	case errors.Is(err, fs.ErrInvalid):
		return linuxerr.EINVAL
	}
	return linuxerr.EIO
}

// translateLookupError is translateHostError for name lookups: a name that the
// host cannot store does not exist.
func translateLookupError(err error) error {
	if errors.Is(err, errInvalidHostName) {
		return linuxerr.ENOENT
	}
	return translateHostError(err)
}
