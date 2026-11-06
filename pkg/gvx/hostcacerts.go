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
	"path"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/gvx/hostcerts"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// maxGuestCABundle bounds the certificate bundle that the sandbox reads from
// the image. A bundle of the common distributions has about 200 KB.
const maxGuestCABundle = 16 << 20

// installHostCACerts copies the host roots into the guest, for
// Config.HostCACerts. It writes into the layer above the image, so the image
// stays unchanged. It runs before the user mounts exist, and it skips every
// path below a mount point.
func (s *Sandbox) installHostCACerts(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) error {
	if len(s.hostCARoots) == 0 {
		return nil
	}
	guest := &vfsGuestFS{sctx: sctx, vfsObj: vfsObj, creds: creds, root: root}
	if err := hostcerts.Install(guest, s.hostCARoots, coveredByMount(s.cfg.mountList())); err != nil {
		return fmt.Errorf("gvx: copy the host root certificates into the guest: %w", err)
	}
	return nil
}

// coveredByMount returns a function that reports whether a guest path is a
// mount point or is below one.
func coveredByMount(mounts []Mount) func(string) bool {
	points := make([]string, 0, len(mounts))
	for _, m := range mounts {
		points = append(points, path.Clean("/"+m.GuestPath))
	}
	return func(p string) bool {
		p = path.Clean(p)
		for _, point := range points {
			if p == point || strings.HasPrefix(p, strings.TrimSuffix(point, "/")+"/") {
				return true
			}
		}
		return false
	}
}

// vfsGuestFS is the hostcerts.GuestFS of the guest root.
type vfsGuestFS struct {
	sctx   gvcontext.Context
	vfsObj *vfs.VirtualFilesystem
	creds  *auth.Credentials
	root   vfs.VirtualDentry
}

func (g *vfsGuestFS) ReadFile(guestPath string) ([]byte, bool, error) {
	// readGuestFile returns nil for a missing file, and a non-nil slice for an
	// existing file that is empty.
	data, err := readGuestFile(g.sctx, g.vfsObj, g.creds, g.root, guestPath, maxGuestCABundle+1)
	if err != nil {
		return nil, false, err
	}
	if len(data) > maxGuestCABundle {
		return nil, false, fmt.Errorf("%s is larger than %d bytes", guestPath, maxGuestCABundle)
	}
	return data, data != nil, nil
}

func (g *vfsGuestFS) DirExists(guestPath string) (bool, error) {
	pop := vfs.PathOperation{Root: g.root, Start: g.root, Path: makeFPath(guestPath), FollowFinalSymlink: true}
	st, err := g.vfsObj.StatAt(g.sctx, g.creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENOTDIR, err) {
			return false, nil
		}
		return false, err
	}
	return st.Mode&linux.S_IFMT == linux.S_IFDIR, nil
}

func (g *vfsGuestFS) WriteFile(guestPath string, data []byte) error {
	return vfsWriteFileLinks(g.sctx, g.vfsObj, g.creds, g.root, guestPath, data, 0o644, true)
}
