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
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"io"
	"path"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/overlay"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func classifyStatMode(mode uint16) string {
	switch mode & linux.S_IFMT {
	case linux.S_IFREG:
		return "file"
	case linux.S_IFDIR:
		return "dir"
	case linux.S_IFLNK:
		return "symlink"
	default:
		return "other"
	}
}

func statGuestPath(sctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, guestPath string, follow bool) (control.FSStatResponse, error) {
	cleaned := path.Clean("/" + strings.TrimPrefix(guestPath, "/"))
	pop := vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               makeFPath(cleaned),
		FollowFinalSymlink: follow,
	}
	st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENOTDIR, err) {
			return control.FSStatResponse{Path: cleaned, Exists: false}, nil
		}
		return control.FSStatResponse{}, err
	}
	resp := control.FSStatResponse{
		Path:       cleaned,
		Exists:     true,
		Type:       classifyStatMode(st.Mode),
		Size:       int64(st.Size),
		Mode:       uint32(st.Mode),
		UID:        st.UID,
		GID:        st.GID,
		MtimeNanos: st.Mtime.ToNsec(),
	}
	if st.Mode&linux.S_IFMT == linux.S_IFLNK {
		if target, rlErr := vfsObj.ReadlinkAt(sctx, creds, &pop); rlErr == nil {
			resp.LinkTarget = target
		}
	}
	return resp, nil
}

func (s *Sandbox) handleFSStat(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.FSStatRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	if strings.TrimSpace(req.Path) == "" {
		return control.NewError(control.CodeInvalidArgument, "path is required")
	}
	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}
	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)

	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	st, err := statGuestPath(sctxWithRoot, k.VFS(), creds, root, req.Path, req.FollowLink)
	if err != nil {
		return control.NewErrorf(control.CodeInternal, "stat %q: %v", req.Path, err)
	}
	return stream.Reply(st)
}

type exportDirKey struct {
	devMajor uint32
	devMinor uint32
	ino      uint64
}

func (s *Sandbox) handleFSExport(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.FSExportRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	target := strings.TrimSpace(req.Path)
	if target == "" {
		target = "/"
	}
	target = path.Clean("/" + strings.TrimPrefix(target, "/"))

	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}
	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)

	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	exportRoot := root
	var upperRelease vfs.VirtualDentry
	skipPseudo := target == "/"
	if req.UpperOnly {
		upperVD, ok := overlay.UpperRoot(root.Mount().Filesystem())
		if !ok {
			return control.NewError(control.CodeUnsupported, "root filesystem is not an overlay with a writable upper layer")
		}
		upperRelease = upperVD
		defer upperRelease.DecRef(sctx)
		exportRoot = upperVD
		sctxWithRoot = withGuestVFS(sctx, exportRoot, mntns)
		skipPseudo = false
	}

	st, err := statGuestPath(sctxWithRoot, vfsObj, creds, exportRoot, target, req.FollowLink)
	if err != nil {
		return control.NewErrorf(control.CodeInternal, "stat %q: %v", target, err)
	}
	if !st.Exists {
		return control.NewErrorf(control.CodeNotFound, "guest path %q does not exist", target)
	}

	if err := stream.SendResponse(control.FSExportResponse{Stat: st}); err != nil {
		return err
	}

	cw := stream.ChannelWriter(ctx, control.ChannelGeneric, req.Compress)
	tw := tar.NewWriter(cw)

	var exportErr error
	if st.Type == "dir" {
		baseName := path.Base(target)
		if target == "/" {
			baseName = ""
		}
		var activeDirs map[exportDirKey]bool
		if req.FollowLink {
			activeDirs = make(map[exportDirKey]bool)
		}
		exportErr = exportDirToTar(ctx, sctxWithRoot, vfsObj, creds, exportRoot, target, baseName, req.FollowLink, skipPseudo, req.UpperOnly, activeDirs, tw)
	} else {
		exportErr = exportEntryToTar(ctx, sctxWithRoot, vfsObj, creds, exportRoot, target, path.Base(target), req.FollowLink, req.UpperOnly, tw)
	}
	if exportErr != nil {
		// Do not call tw.Close() so the client never observes valid tar EOF on a
		// truncated archive; dispatchStream cancels the stream on error return.
		return control.NewErrorf(control.CodeInternal, "export %q: %v", target, exportErr)
	}
	if err := tw.Close(); err != nil {
		_ = stream.CloseEvents()
		return err
	}
	err = cw.Close()
	_ = stream.CloseEvents()
	return err
}

func isPseudoRootSubdir(guestPath string) bool {
	return guestPath == "/proc" || guestPath == "/sys" || guestPath == "/dev"
}

func exportDirToTar(
	ctx context.Context,
	sctx gvcontext.Context,
	vfsObj *vfs.VirtualFilesystem,
	creds *auth.Credentials,
	root vfs.VirtualDentry,
	guestDir, tarPrefix string,
	followLink, skipPseudo, upperOnly bool,
	activeDirs map[exportDirKey]bool,
	tw *tar.Writer,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	dirPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestDir), FollowFinalSymlink: followLink}
	st, err := vfsObj.StatAt(sctx, creds, &dirPop, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		return err
	}
	if activeDirs != nil {
		key := exportDirKey{devMajor: st.DevMajor, devMinor: st.DevMinor, ino: st.Ino}
		if activeDirs[key] {
			return nil
		}
		activeDirs[key] = true
		defer delete(activeDirs, key)
	}
	if tarPrefix != "" {
		hdr := &tar.Header{
			Typeflag: tar.TypeDir,
			Name:     strings.TrimSuffix(tarPrefix, "/") + "/",
			Mode:     int64(st.Mode & 0o7777),
			Uid:      int(st.UID),
			Gid:      int(st.GID),
			ModTime:  time.Unix(0, st.Mtime.ToNsec()),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
	}
	if upperOnly {
		if val, xErr := vfsObj.GetXattrAt(sctx, creds, &dirPop, &vfs.GetXattrOptions{Name: "trusted.overlay.opaque", Size: 16}); xErr == nil && val == "y" {
			opqName := ".wh..wh..opq"
			if tarPrefix != "" {
				opqName = path.Join(tarPrefix, opqName)
			}
			if err := tw.WriteHeader(&tar.Header{
				Typeflag: tar.TypeReg,
				Name:     opqName,
				Mode:     0o644,
				Size:     0,
				ModTime:  time.Unix(0, st.Mtime.ToNsec()),
			}); err != nil {
				return err
			}
		}
	}

	fd, err := vfsObj.OpenAt(sctx, creds, &dirPop, &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	if err != nil {
		return err
	}
	var names []string
	iterErr := fd.IterDirents(sctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name == "." || d.Name == ".." {
			return nil
		}
		names = append(names, d.Name)
		return nil
	}))
	fd.DecRef(sctx)
	if iterErr != nil {
		return iterErr
	}

	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		childGuest := path.Join(guestDir, name)
		if skipPseudo && isPseudoRootSubdir(childGuest) {
			continue
		}
		childTar := name
		if tarPrefix != "" {
			childTar = path.Join(tarPrefix, name)
		}
		cPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(childGuest), FollowFinalSymlink: followLink}
		cst, err := vfsObj.StatAt(sctx, creds, &cPop, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
		if err != nil {
			if linuxerr.Equals(linuxerr.ENOENT, err) {
				continue
			}
			return err
		}
		if cst.Mode&linux.S_IFMT == linux.S_IFDIR {
			if err := exportDirToTar(ctx, sctx, vfsObj, creds, root, childGuest, childTar, followLink, false, upperOnly, activeDirs, tw); err != nil {
				return err
			}
			continue
		}
		if err := exportEntryToTar(ctx, sctx, vfsObj, creds, root, childGuest, childTar, followLink, upperOnly, tw); err != nil {
			return err
		}
	}
	return nil
}

func exportEntryToTar(
	ctx context.Context,
	sctx gvcontext.Context,
	vfsObj *vfs.VirtualFilesystem,
	creds *auth.Credentials,
	root vfs.VirtualDentry,
	guestPath, tarName string,
	followLink, upperOnly bool,
	tw *tar.Writer,
) error {
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(guestPath), FollowFinalSymlink: followLink}
	st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		return err
	}
	// Translate overlay whiteouts (char device 0:0) into OCI .wh.<name> entries.
	if upperOnly && st.Mode&linux.S_IFMT == linux.S_IFCHR && st.RdevMajor == 0 && st.RdevMinor == 0 {
		dir, base := path.Split(tarName)
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     dir + ".wh." + base,
			Mode:     0o644,
			Size:     0,
			ModTime:  time.Unix(0, st.Mtime.ToNsec()),
		})
	}
	switch st.Mode & linux.S_IFMT {
	case linux.S_IFLNK:
		target, err := vfsObj.ReadlinkAt(sctx, creds, &pop)
		if err != nil {
			return err
		}
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeSymlink,
			Name:     tarName,
			Linkname: target,
			Mode:     int64(st.Mode & 0o7777),
			Uid:      int(st.UID),
			Gid:      int(st.GID),
			ModTime:  time.Unix(0, st.Mtime.ToNsec()),
		})
	case linux.S_IFREG:
		fd, err := vfsObj.OpenAt(sctx, creds, &pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if err != nil {
			return err
		}
		defer fd.DecRef(sctx)
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg,
			Name:     tarName,
			Size:     int64(st.Size),
			Mode:     int64(st.Mode & 0o7777),
			Uid:      int(st.UID),
			Gid:      int(st.GID),
			ModTime:  time.Unix(0, st.Mtime.ToNsec()),
		}); err != nil {
			return err
		}
		var remaining int64 = int64(st.Size)
		buf := make([]byte, 64<<10)
		for remaining > 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
			want := min(remaining, int64(len(buf)))
			n, rErr := fd.Read(sctx, usermem.BytesIOSequence(buf[:want]), vfs.ReadOptions{})
			if n > 0 {
				if _, wErr := tw.Write(buf[:n]); wErr != nil {
					return wErr
				}
				remaining -= n
			}
			if rErr != nil {
				if errors.Is(rErr, io.EOF) {
					break
				}
				return rErr
			}
			if n == 0 {
				break
			}
		}
		// Pad with zeros if file shrank concurrently while reading.
		for remaining > 0 {
			step := min(remaining, int64(len(buf)))
			clear(buf[:step])
			if _, wErr := tw.Write(buf[:step]); wErr != nil {
				return wErr
			}
			remaining -= step
		}
		return nil
	default:
		// Skip sockets, FIFOs, and device nodes during normal copy/export.
		return nil
	}
}

func cleanRelativeTarName(raw string) (string, bool) {
	norm := strings.ReplaceAll(raw, `\`, "/")
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", false
		}
	}
	cleaned := path.Clean("/" + strings.TrimPrefix(norm, "/"))
	cleaned = strings.TrimPrefix(cleaned, "/")
	if cleaned == "" || cleaned == "." {
		return "", false
	}
	return cleaned, true
}

// resolveImportDirUnder walks relDir component by component beneath destVD
// without following symlinks, creating missing directories when create is true.
// The caller owns one reference on the returned VirtualDentry.
func resolveImportDirUnder(
	sctx gvcontext.Context,
	vfsObj *vfs.VirtualFilesystem,
	creds *auth.Credentials,
	destVD vfs.VirtualDentry,
	relDir string,
	create bool,
) (vfs.VirtualDentry, error) {
	cur := destVD
	cur.IncRef()
	if relDir == "" || relDir == "." {
		return cur, nil
	}
	for _, seg := range strings.Split(relDir, "/") {
		if seg == "" || seg == "." {
			continue
		}
		pop := vfs.PathOperation{
			Root:               destVD,
			Start:              cur,
			Path:               makeFPath(seg),
			FollowFinalSymlink: false,
		}
		st, err := vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
		if err != nil {
			if !create || !linuxerr.Equals(linuxerr.ENOENT, err) {
				cur.DecRef(sctx)
				return vfs.VirtualDentry{}, err
			}
			if mkErr := vfsObj.MkdirAt(sctx, creds, &pop, &vfs.MkdirOptions{Mode: 0o755}); mkErr != nil && !linuxerr.Equals(linuxerr.EEXIST, mkErr) {
				cur.DecRef(sctx)
				return vfs.VirtualDentry{}, mkErr
			}
			st, err = vfsObj.StatAt(sctx, creds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
			if err != nil {
				cur.DecRef(sctx)
				return vfs.VirtualDentry{}, err
			}
		}
		if st.Mode&linux.S_IFMT != linux.S_IFDIR {
			cur.DecRef(sctx)
			return vfs.VirtualDentry{}, control.NewErrorf(control.CodeInvalidArgument, "tar import refuses traversing non-directory component %q", seg)
		}
		next, err := vfsObj.GetDentryAt(sctx, creds, &pop, &vfs.GetDentryOptions{CheckSearchable: true})
		cur.DecRef(sctx)
		if err != nil {
			return vfs.VirtualDentry{}, err
		}
		cur = next
	}
	return cur, nil
}

func (s *Sandbox) handleFSImport(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.FSImportRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	dest := strings.TrimSpace(req.DestPath)
	if dest == "" {
		return control.NewError(control.CodeInvalidArgument, "dest_path is required")
	}
	dest = path.Clean("/" + strings.TrimPrefix(dest, "/"))

	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}
	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)

	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	rootCreds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	var overrideUID, overrideGID *uint32
	if req.User != "" {
		u, _, uErr := s.resolveExecCredentials(sctxWithRoot, vfsObj, rootCreds, root, req.User, nil)
		if uErr != nil {
			return uErr
		}
		uid, gid := u.UID, u.GID
		overrideUID, overrideGID = &uid, &gid
	}

	destPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(dest), FollowFinalSymlink: true}
	destSt, err := vfsObj.StatAt(sctxWithRoot, rootCreds, &destPop, &vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err != nil {
		if linuxerr.Equals(linuxerr.ENOENT, err) || linuxerr.Equals(linuxerr.ENOTDIR, err) {
			return control.NewErrorf(control.CodeNotFound, "destination directory %q does not exist", dest)
		}
		return control.NewErrorf(control.CodeInternal, "stat destination %q: %v", dest, err)
	}
	if destSt.Mode&linux.S_IFMT != linux.S_IFDIR {
		return control.NewErrorf(control.CodeInvalidArgument, "destination %q is not a directory", dest)
	}
	destVD, err := vfsObj.GetDentryAt(sctxWithRoot, rootCreds, &destPop, &vfs.GetDentryOptions{CheckSearchable: true})
	if err != nil {
		return control.NewErrorf(control.CodeInternal, "resolve destination %q: %v", dest, err)
	}
	defer destVD.DecRef(sctxWithRoot)

	tr := tar.NewReader(stream.ChannelReader(ctx, control.ChannelGeneric))
	var (
		filesWritten int
		bytesWritten int64
		buf          = make([]byte, 64<<10)
	)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return control.NewErrorf(control.CodeInvalidArgument, "read tar stream: %v", err)
		}
		rel, ok := cleanRelativeTarName(hdr.Name)
		if !ok {
			if strings.Contains(hdr.Name, "..") {
				return control.NewErrorf(control.CodeInvalidArgument, "unsafe tar path %q escapes destination", hdr.Name)
			}
			continue
		}
		parentRel := path.Dir(rel)
		baseName := path.Base(rel)
		fullPath := path.Join(dest, rel)

		parentVD, pErr := resolveImportDirUnder(sctxWithRoot, vfsObj, rootCreds, destVD, parentRel, true)
		if pErr != nil {
			var pe *control.ProtoError
			if errors.As(pErr, &pe) {
				return pe
			}
			return control.NewErrorf(control.CodeInternal, "create parent dir %q: %v", path.Join(dest, parentRel), pErr)
		}

		pop := vfs.PathOperation{
			Root:               destVD,
			Start:              parentVD,
			Path:               makeFPath(baseName),
			FollowFinalSymlink: false,
		}
		applyOwnerAndTime := func(isSymlink bool) {
			var stat linux.Statx
			if overrideUID != nil {
				stat.Mask |= linux.STATX_UID | linux.STATX_GID
				stat.UID = *overrideUID
				stat.GID = *overrideGID
			} else if req.Archive {
				stat.Mask |= linux.STATX_UID | linux.STATX_GID
				stat.UID = uint32(max(hdr.Uid, 0))
				stat.GID = uint32(max(hdr.Gid, 0))
			}
			if !isSymlink && !hdr.ModTime.IsZero() {
				stat.Mask |= linux.STATX_MTIME
				stat.Mtime = linux.NsecToStatxTimestamp(hdr.ModTime.UnixNano())
			}
			if !isSymlink {
				stat.Mask |= linux.STATX_MODE
				stat.Mode = uint16(hdr.Mode & 0o7777)
			}
			if stat.Mask == 0 {
				return
			}
			_ = vfsObj.SetStatAt(sctxWithRoot, rootCreds, &pop, &vfs.SetStatOptions{Stat: stat})
		}

		var entryErr error
		switch hdr.Typeflag {
		case tar.TypeDir:
			if existing, stErr := vfsObj.StatAt(sctxWithRoot, rootCreds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE}); stErr == nil {
				if existing.Mode&linux.S_IFMT != linux.S_IFDIR {
					if req.NoOverwriteDir {
						entryErr = control.NewErrorf(control.CodeAlreadyExists, "cannot overwrite non-directory %q with directory", fullPath)
						break
					}
					_ = vfsObj.UnlinkAt(sctxWithRoot, rootCreds, &pop)
					mode := linux.FileMode(hdr.Mode & 0o7777)
					if mode == 0 {
						mode = 0o755
					}
					if err := vfsObj.MkdirAt(sctxWithRoot, rootCreds, &pop, &vfs.MkdirOptions{Mode: mode}); err != nil {
						entryErr = control.NewErrorf(control.CodeInternal, "mkdir %q: %v", fullPath, err)
						break
					}
				}
			} else {
				mode := linux.FileMode(hdr.Mode & 0o7777)
				if mode == 0 {
					mode = 0o755
				}
				if err := vfsObj.MkdirAt(sctxWithRoot, rootCreds, &pop, &vfs.MkdirOptions{Mode: mode}); err != nil && !linuxerr.Equals(linuxerr.EEXIST, err) {
					entryErr = control.NewErrorf(control.CodeInternal, "mkdir %q: %v", fullPath, err)
					break
				}
			}
			applyOwnerAndTime(false)
			filesWritten++

		case tar.TypeSymlink:
			_ = vfsObj.UnlinkAt(sctxWithRoot, rootCreds, &pop)
			if err := vfsObj.SymlinkAt(sctxWithRoot, rootCreds, &pop, hdr.Linkname); err != nil {
				entryErr = control.NewErrorf(control.CodeInternal, "symlink %q: %v", fullPath, err)
				break
			}
			applyOwnerAndTime(true)
			filesWritten++

		case tar.TypeLink:
			linkRel, linkOK := cleanRelativeTarName(hdr.Linkname)
			if !linkOK {
				entryErr = control.NewErrorf(control.CodeInvalidArgument, "unsafe hard link target %q", hdr.Linkname)
				break
			}
			targetParentVD, tpErr := resolveImportDirUnder(sctxWithRoot, vfsObj, rootCreds, destVD, path.Dir(linkRel), false)
			if tpErr != nil {
				var pe *control.ProtoError
				if errors.As(tpErr, &pe) {
					entryErr = pe
				} else {
					entryErr = control.NewErrorf(control.CodeInvalidArgument, "resolve hard link target %q: %v", linkRel, tpErr)
				}
				break
			}
			targetPop := vfs.PathOperation{
				Root:               destVD,
				Start:              targetParentVD,
				Path:               makeFPath(path.Base(linkRel)),
				FollowFinalSymlink: false,
			}
			_ = vfsObj.UnlinkAt(sctxWithRoot, rootCreds, &pop)
			if err := vfsObj.LinkAt(sctxWithRoot, rootCreds, &targetPop, &pop); err != nil {
				targetParentVD.DecRef(sctxWithRoot)
				entryErr = control.NewErrorf(control.CodeInternal, "link %q -> %q: %v", fullPath, linkRel, err)
				break
			}
			targetParentVD.DecRef(sctxWithRoot)
			filesWritten++

		case tar.TypeReg, tar.TypeRegA:
			if existing, stErr := vfsObj.StatAt(sctxWithRoot, rootCreds, &pop, &vfs.StatOptions{Mask: linux.STATX_TYPE}); stErr == nil {
				switch existing.Mode & linux.S_IFMT {
				case linux.S_IFDIR:
					if req.NoOverwriteDir {
						entryErr = control.NewErrorf(control.CodeAlreadyExists, "cannot overwrite directory %q with file", fullPath)
					} else {
						entryErr = control.NewErrorf(control.CodeInvalidArgument, "cannot overwrite directory %q with regular file", fullPath)
					}
				case linux.S_IFREG:
				default:
					// Replace symlinks, FIFOs, sockets, and device nodes rather
					// than following or blocking on them.
					_ = vfsObj.UnlinkAt(sctxWithRoot, rootCreds, &pop)
				}
				if entryErr != nil {
					break
				}
			}
			mode := linux.FileMode(hdr.Mode & 0o7777)
			if mode == 0 {
				mode = 0o644
			}
			fd, err := vfsObj.OpenAt(sctxWithRoot, rootCreds, &pop, &vfs.OpenOptions{
				Flags: linux.O_WRONLY | linux.O_CREAT | linux.O_TRUNC | linux.O_NOFOLLOW,
				Mode:  mode,
			})
			if err != nil {
				entryErr = control.NewErrorf(control.CodeInternal, "open %q: %v", fullPath, err)
				break
			}
			for {
				n, rErr := tr.Read(buf)
				if n > 0 {
					w, wErr := fd.Write(sctxWithRoot, usermem.BytesIOSequence(buf[:n]), vfs.WriteOptions{})
					bytesWritten += w
					if wErr != nil {
						entryErr = control.NewErrorf(control.CodeInternal, "write %q: %v", fullPath, wErr)
						break
					}
				}
				if errors.Is(rErr, io.EOF) {
					break
				}
				if rErr != nil {
					entryErr = control.NewErrorf(control.CodeInvalidArgument, "read tar entry %q: %v", fullPath, rErr)
					break
				}
			}
			fd.DecRef(sctxWithRoot)
			if entryErr == nil {
				applyOwnerAndTime(false)
				filesWritten++
			}
		}
		parentVD.DecRef(sctxWithRoot)
		if entryErr != nil {
			return entryErr
		}
	}

	return stream.Reply(control.FSImportResponse{
		FilesWritten: filesWritten,
		BytesWritten: bytesWritten,
	})
}
