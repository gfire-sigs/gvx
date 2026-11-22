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
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "cp",
		summary: "Copy files or directories between the host and a running sandbox.",
		usage: []string{
			"rungv cp [-S <socket>|-n <name>] [-a] [-L] [-z] [--no-overwrite-dir] [--user U:G] SRC_HOST :DST_GUEST",
			"rungv cp [-S <socket>|-n <name>] [-a] [-L] [-z] :SRC_GUEST DST_HOST",
		},
		run: cpSubcommand,
	})
	register(command{
		name:    "export",
		summary: "Export a sandbox filesystem or overlay upper layer as a tar archive.",
		usage: []string{
			"rungv export -S <socket>|-n <name> [--upper-only] [-z] [-o FILE|-] [GUEST_PATH]",
		},
		run: exportSubcommand,
	})
}

type cpEndpoint struct {
	isGuest     bool
	isPipe      bool
	sandboxName string
	path        string
}

func isASCIIAlpha(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func hasWindowsDrivePrefix(s string) bool {
	return len(s) >= 2 && isASCIIAlpha(s[0]) && s[1] == ':' && (len(s) == 2 || s[2] == '\\' || s[2] == '/')
}

func parseCPEndpoint(raw string) cpEndpoint {
	if raw == "-" {
		return cpEndpoint{isPipe: true, path: "-"}
	}
	if strings.HasPrefix(raw, ":") {
		return cpEndpoint{isGuest: true, path: raw[1:]}
	}
	if !hasWindowsDrivePrefix(raw) {
		if idx := strings.IndexByte(raw, ':'); idx > 0 {
			prefix := raw[:idx]
			if !strings.ContainsAny(prefix, `/\`) {
				return cpEndpoint{
					isGuest:     true,
					sandboxName: prefix,
					path:        raw[idx+1:],
				}
			}
		}
	}
	return cpEndpoint{path: raw}
}

func cpSubcommand(ctx context.Context, args []string, streams cliIO) int {
	const cmdName = "cp"
	fs := newImageFlagSet(cmdName, streams.stderr)
	target := addControlFlags(fs, 0)

	var archive, followLink, compress, noOverwriteDir, quiet bool
	var user string
	registerAlias([]string{"a", "archive"}, func(n string) {
		fs.BoolVar(&archive, n, false, "Preserve mode, ownership, and timestamps")
	})
	registerAlias([]string{"L", "follow-link"}, func(n string) {
		fs.BoolVar(&followLink, n, false, "Always follow symbol link in SRC_PATH")
	})
	registerAlias([]string{"z", "compress"}, func(n string) {
		fs.BoolVar(&compress, n, false, "Compress transfer frames with zstd")
	})
	fs.BoolVar(&noOverwriteDir, "no-overwrite-dir", false, "Do not overwrite an existing non-directory with a directory")
	fs.StringVar(&user, "user", "", "Default owner UID[:GID] for host-to-guest copy without -a")
	registerAlias([]string{"q", "quiet"}, func(n string) {
		fs.BoolVar(&quiet, n, false, "Suppress non-fatal copy warnings")
	})

	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 2 {
		return controlUsageError(streams.stderr, cmdName, "want exactly 2 arguments: SRC DST")
	}

	src := parseCPEndpoint(fs.Arg(0))
	dst := parseCPEndpoint(fs.Arg(1))
	if src.isGuest == dst.isGuest {
		return controlUsageError(streams.stderr, cmdName, "exactly one of SRC or DST must be a guest path (:PATH or NAME:PATH)")
	}

	inlineName := src.sandboxName
	if inlineName == "" {
		inlineName = dst.sandboxName
	}
	client, err := target.dial(ctx, inlineName)
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer client.Close()

	if src.isGuest {
		return cpGuestToHost(ctx, client, src.path, dst, followLink, compress, quiet, streams)
	}
	return cpHostToGuest(ctx, client, src, dst.path, archive, followLink, compress, noOverwriteDir, strings.TrimSpace(user), streams)
}

func cpGuestToHost(ctx context.Context, client *control.Client, guestSrc string, dst cpEndpoint, followLink, compress, quiet bool, streams cliIO) int {
	const cmdName = "cp"
	stream, err := client.OpenStream(ctx, control.MethodFSExport, control.FSExportRequest{
		Path:       guestSrc,
		FollowLink: followLink,
		Compress:   compress,
	})
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer stream.Close()

	var resp control.FSExportResponse
	if err := stream.WaitResponse(ctx, &resp); err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}

	warnCtx, warnCancel := context.WithCancel(ctx)
	warnDone := make(chan struct{})
	go func() {
		defer close(warnDone)
		for {
			ev, err := stream.RecvEvent(warnCtx)
			if err != nil {
				return
			}
			if ev.Type == "warning" && !quiet {
				var msg map[string]string
				if json.Unmarshal(ev.Data, &msg) == nil && msg["message"] != "" {
					_, _ = fmt.Fprintf(streams.stderr, "rungv cp: warning: %s\n", msg["message"])
				}
			}
		}
	}()
	defer func() {
		warnCancel()
		<-warnDone
	}()

	tarReader := stream.ChannelReader(ctx, control.ChannelGeneric)
	if dst.isPipe {
		if _, err := io.Copy(streams.stdout, tarReader); err != nil {
			return controlFail(streams.stderr, cmdName, err)
		}
		return 0
	}

	extractOpts := hostExtractOptions{}
	// Docker semantics: copying a single file to a non-directory path renames it.
	if resp.Stat.Type == "file" || resp.Stat.Type == "symlink" {
		if st, statErr := os.Stat(dst.path); statErr == nil && st.IsDir() {
			if err := extractTarToHostDir(tarReader, dst.path, extractOpts); err != nil {
				return controlFail(streams.stderr, cmdName, err)
			}
		} else {
			parent := filepath.Dir(dst.path)
			extractOpts.renameSingleTo = filepath.Base(dst.path)
			if err := extractTarToHostDir(tarReader, parent, extractOpts); err != nil {
				return controlFail(streams.stderr, cmdName, err)
			}
		}
	} else {
		// Directory export: if dst exists and is a dir, extract inside it;
		// otherwise create dst and strip the single leading component.
		if st, statErr := os.Stat(dst.path); statErr == nil && st.IsDir() {
			if err := extractTarToHostDir(tarReader, dst.path, extractOpts); err != nil {
				return controlFail(streams.stderr, cmdName, err)
			}
		} else {
			extractOpts.stripTopDir = true
			if err := extractTarToHostDir(tarReader, dst.path, extractOpts); err != nil {
				return controlFail(streams.stderr, cmdName, err)
			}
		}
	}
	return 0
}

func cpHostToGuest(ctx context.Context, client *control.Client, src cpEndpoint, guestDst string, archive, followLink, compress, noOverwriteDir bool, user string, streams cliIO) int {
	const cmdName = "cp"
	if guestDst == "" {
		return controlUsageError(streams.stderr, cmdName, "destination guest path must not be empty")
	}

	destDir := guestDst
	var renameSingle string
	if !src.isPipe {
		info, err := statHostSource(src.path, followLink)
		if err != nil {
			return controlFail(streams.stderr, cmdName, err)
		}
		var dstStat control.FSStatResponse
		if err := client.Call(ctx, control.MethodFSStat, control.FSStatRequest{
			Path:       guestDst,
			FollowLink: true,
		}, &dstStat); err != nil {
			return controlFail(streams.stderr, cmdName, err)
		}
		if !info.IsDir() {
			if !dstStat.Exists || dstStat.Type != "dir" {
				destDir = path.Dir(path.Clean(guestDst))
				renameSingle = path.Base(path.Clean(guestDst))
			}
		} else if !dstStat.Exists {
			destDir = path.Dir(path.Clean(guestDst))
			renameSingle = path.Base(path.Clean(guestDst))
		}
	}

	stream, err := client.OpenStream(ctx, control.MethodFSImport, control.FSImportRequest{
		DestPath:       destDir,
		Archive:        archive,
		NoOverwriteDir: noOverwriteDir,
		User:           user,
		Compress:       compress,
	})
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer stream.Close()

	writeErrCh := make(chan error, 1)
	go func() {
		w := stream.ChannelWriter(ctx, control.ChannelGeneric, compress)
		var sendErr error
		if src.isPipe {
			if streams.stdin != nil {
				_, sendErr = io.Copy(w, streams.stdin)
			}
		} else {
			sendErr = packHostToTar(w, src.path, renameSingle, followLink)
		}
		closeErr := w.Close()
		writeErrCh <- errors.Join(sendErr, closeErr)
	}()

	var resp control.FSImportResponse
	respErr := stream.WaitResponse(ctx, &resp)
	sendErr := <-writeErrCh
	if respErr != nil {
		return controlFail(streams.stderr, cmdName, respErr)
	}
	if sendErr != nil {
		return controlFail(streams.stderr, cmdName, sendErr)
	}
	return 0
}

func statHostSource(p string, followLink bool) (os.FileInfo, error) {
	if followLink {
		return os.Stat(p)
	}
	return os.Lstat(p)
}

func packHostToTar(w io.Writer, srcPath, renameTop string, followLink bool) error {
	clean := filepath.Clean(srcPath)
	contentsOnly := strings.HasSuffix(srcPath, "/.") || strings.HasSuffix(srcPath, `\.`)
	info, err := statHostSource(clean, followLink)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	defer func() { _ = tw.Close() }()

	if !info.IsDir() {
		name := filepath.Base(clean)
		if renameTop != "" {
			name = renameTop
		}
		if err := writeHostEntryToTar(tw, clean, name, info, followLink); err != nil {
			return err
		}
		return tw.Close()
	}

	topPrefix := filepath.Base(clean)
	if renameTop != "" {
		topPrefix = renameTop
	}
	if contentsOnly {
		topPrefix = ""
	}
	err = filepath.WalkDir(clean, func(cur string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(clean, cur)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		var tarName string
		if rel == "." {
			if topPrefix == "" {
				return nil
			}
			tarName = topPrefix
		} else if topPrefix == "" {
			tarName = rel
		} else {
			tarName = path.Join(topPrefix, rel)
		}
		fi, err := statHostSource(cur, followLink)
		if err != nil {
			return err
		}
		return writeHostEntryToTar(tw, cur, tarName, fi, followLink)
	})
	if err != nil {
		return err
	}
	return tw.Close()
}

func writeHostEntryToTar(tw *tar.Writer, hostPath, tarName string, info os.FileInfo, followLink bool) error {
	var linkTarget string
	if info.Mode()&os.ModeSymlink != 0 && !followLink {
		var err error
		linkTarget, err = os.Readlink(hostPath)
		if err != nil {
			return err
		}
	}
	hdr, err := tar.FileInfoHeader(info, linkTarget)
	if err != nil {
		return err
	}
	hdr.Name = tarName
	if info.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
		hdr.Name += "/"
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if hdr.Typeflag == tar.TypeReg {
		f, err := os.Open(hostPath)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		closeErr := f.Close()
		return errors.Join(copyErr, closeErr)
	}
	return nil
}

type hostExtractOptions struct {
	renameSingleTo string
	stripTopDir    bool
}

// extractTarToHostDir safely extracts a tar stream into destDir pinned by os.Root.
func extractTarToHostDir(r io.Reader, destDir string, opts hostExtractOptions) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("create destination directory %q: %w", destDir, err)
	}
	root, err := os.OpenRoot(destDir)
	if err != nil {
		return fmt.Errorf("open destination root %q: %w", destDir, err)
	}
	defer root.Close()

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		rel, skip, err := sanitizeHostTarPath(hdr.Name, opts)
		if err != nil {
			return err
		}
		if skip {
			continue
		}
		if err := validateHostFilename(rel); err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAllInRoot(root, rel); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if parent := path.Dir(rel); parent != "." && parent != "" {
				if err := mkdirAllInRoot(root, parent); err != nil {
					return err
				}
			}
			perm := os.FileMode(hdr.Mode & 0o777)
			if perm == 0 {
				perm = 0o644
			}
			f, err := root.OpenFile(rel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
			if err != nil {
				return fmt.Errorf("create %q: %w", rel, err)
			}
			_, copyErr := io.Copy(f, tr)
			closeErr := f.Close()
			if err := errors.Join(copyErr, closeErr); err != nil {
				return fmt.Errorf("write %q: %w", rel, err)
			}
			_ = os.Chtimes(filepath.Join(destDir, filepath.FromSlash(rel)), time.Now(), hdr.ModTime)
		case tar.TypeSymlink:
			if path.IsAbs(hdr.Linkname) {
				return fmt.Errorf("refuse absolute symlink target %q -> %q", rel, hdr.Linkname)
			}
			resolved := path.Clean(path.Join(path.Dir(rel), hdr.Linkname))
			if resolved == ".." || strings.HasPrefix(resolved, "../") {
				return fmt.Errorf("refuse symlink escaping destination root: %q -> %q", rel, hdr.Linkname)
			}
			if parent := path.Dir(rel); parent != "." && parent != "" {
				if err := mkdirAllInRoot(root, parent); err != nil {
					return err
				}
			}
			_ = root.Remove(rel)
			if err := root.Symlink(hdr.Linkname, rel); err != nil {
				return fmt.Errorf("symlink %q: %w", rel, err)
			}
		case tar.TypeLink:
			linkRel, linkSkip, err := sanitizeHostTarPath(hdr.Linkname, opts)
			if err != nil || linkSkip {
				return fmt.Errorf("invalid hard link target %q", hdr.Linkname)
			}
			if parent := path.Dir(rel); parent != "." && parent != "" {
				if err := mkdirAllInRoot(root, parent); err != nil {
					return err
				}
			}
			_ = root.Remove(rel)
			if err := root.Link(linkRel, rel); err != nil {
				return fmt.Errorf("hardlink %q -> %q: %w", rel, linkRel, err)
			}
		}
	}
}

func sanitizeHostTarPath(raw string, opts hostExtractOptions) (string, bool, error) {
	p := strings.TrimPrefix(strings.ReplaceAll(raw, `\`, "/"), "/")
	p = path.Clean(p)
	if p == "." || p == "" {
		return "", true, nil
	}
	if p == ".." || strings.HasPrefix(p, "../") {
		return "", false, fmt.Errorf("unsafe tar path %q escapes destination", raw)
	}
	if opts.renameSingleTo != "" {
		return opts.renameSingleTo, false, nil
	}
	if opts.stripTopDir {
		if idx := strings.IndexByte(p, '/'); idx >= 0 {
			p = p[idx+1:]
			if p == "" || p == "." {
				return "", true, nil
			}
		} else {
			return "", true, nil
		}
	}
	return p, false, nil
}

func mkdirAllInRoot(root *os.Root, rel string) error {
	parts := strings.Split(rel, "/")
	cur := ""
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		if cur == "" {
			cur = part
		} else {
			cur += "/" + part
		}
		if err := root.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("mkdir %q: %w", cur, err)
		}
	}
	return nil
}

var windowsReservedNames = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true, "COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true, "LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func validateHostFilename(rel string) error {
	if runtime.GOOS != "windows" {
		return nil
	}
	for _, seg := range strings.Split(rel, "/") {
		if strings.ContainsAny(seg, `<>:"|?*`) {
			return fmt.Errorf("tar entry %q contains a character forbidden on Windows (use '-' stdout tar for lossless export)", rel)
		}
		base := seg
		if dot := strings.IndexByte(base, '.'); dot >= 0 {
			base = base[:dot]
		}
		if windowsReservedNames[strings.ToUpper(base)] {
			return fmt.Errorf("tar entry %q uses a Windows reserved device name (use '-' stdout tar for lossless export)", rel)
		}
	}
	return nil
}

func exportSubcommand(ctx context.Context, args []string, streams cliIO) int {
	const cmdName = "export"
	fs := newImageFlagSet(cmdName, streams.stderr)
	target := addControlFlags(fs, 0)
	var outPath string
	var upperOnly, compress bool
	registerAlias([]string{"o", "output"}, func(n string) {
		fs.StringVar(&outPath, n, "-", "Output tar file path (default '-' stdout)")
	})
	fs.BoolVar(&upperOnly, "upper-only", false, "Export only modified files from the root overlay upper layer")
	registerAlias([]string{"z", "compress"}, func(n string) {
		fs.BoolVar(&compress, n, false, "Compress transfer frames with zstd")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	guestPath := "/"
	if fs.NArg() == 1 {
		guestPath = fs.Arg(0)
	} else if fs.NArg() > 1 {
		return controlUsageError(streams.stderr, cmdName, "at most one GUEST_PATH argument")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer client.Close()

	stream, err := client.OpenStream(ctx, control.MethodFSExport, control.FSExportRequest{
		Path:      guestPath,
		UpperOnly: upperOnly,
		Compress:  compress,
	})
	if err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	defer stream.Close()

	if err := stream.WaitResponse(ctx, nil); err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}

	var dst io.Writer = streams.stdout
	var outFile *os.File
	if outPath != "" && outPath != "-" {
		f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
		if err != nil {
			return controlFail(streams.stderr, cmdName, err)
		}
		outFile = f
		dst = f
	}

	_, copyErr := io.Copy(dst, stream.ChannelReader(ctx, control.ChannelGeneric))
	var closeErr error
	if outFile != nil {
		closeErr = outFile.Close()
	}
	if err := errors.Join(copyErr, closeErr); err != nil {
		return controlFail(streams.stderr, cmdName, err)
	}
	return 0
}
