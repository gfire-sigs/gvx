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

package gvx

import (
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// readGuestFile returns the content of a file of the guest root, up to
// maxBytes. It returns nil and no error when the file does not exist, because
// an image does not need to have /etc/passwd. A longer file is truncated.
func readGuestFile(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, maxBytes int) ([]byte, error) {
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath), FollowFinalSymlink: true}
	fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			return nil, nil
		}
		return nil, fmt.Errorf("gvx: open guest file %s: %w", guestPath, err)
	}
	defer fd.DecRef(sctx)

	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for len(buf) < maxBytes {
		want := min(len(chunk), maxBytes-len(buf))
		n, err := fd.Read(sctx, usermem.BytesIOSequence(chunk[:want]), vfs.ReadOptions{})
		buf = append(buf, chunk[:n]...)
		if err != nil || n == 0 {
			break
		}
	}
	return buf, nil
}
