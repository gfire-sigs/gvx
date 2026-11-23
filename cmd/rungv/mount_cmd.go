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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func init() {
	register(command{
		name:    "mount",
		summary: "Manage runtime mounts of a running sandbox (ls, add, remount, rm, serve).",
		usage:   []string{"rungv mount <ls|add|remount|rm|serve> -S <socket>|-n <name> [flags] [args...]"},
		run:     mountGroupSubcommand,
	})
}

func mountGroupSubcommand(ctx context.Context, args []string, streams cliIO) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		w := streams.stdout
		code := 0
		if len(args) == 0 {
			w = streams.stderr
			code = 2
		}
		_, _ = fmt.Fprintln(w, "Usage: rungv mount <ls|add|remount|rm|serve> -S <socket>|-n <name> [flags] [args...]")
		return code
	}
	switch args[0] {
	case "ls", "list":
		return mountListSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	case "add":
		return mountAddSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	case "remount":
		return mountRemountSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	case "rm", "remove":
		return mountRemoveSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	case "serve":
		return mountServeSubcommand(ctx, args[1:], streams.stdout, streams.stderr)
	default:
		return controlUsageError(streams.stderr, "mount", "unknown subcommand %q (want ls, add, remount, rm, or serve)", args[0])
	}
}

func mountListSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "mount ls"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	var quiet bool
	var format string
	registerAlias([]string{"q", "quiet"}, func(n string) {
		fs.BoolVar(&quiet, n, false, "Print only mount target paths")
	})
	registerAlias([]string{"f", "format"}, func(n string) {
		fs.StringVar(&format, n, "", "Format output using table (default), json, or a Go template")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var resp control.MountListResponse
	if err := client.Call(callCtx, control.MethodMountList, nil, &resp); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	if quiet {
		for _, m := range resp.Mounts {
			_, _ = fmt.Fprintln(stdout, m.Target)
		}
		return 0
	}
	usageErr, writeErr := renderListFormat(stdout, format, resp.Mounts, func(w io.Writer) error {
		tw := tabwriter.NewWriter(w, 10, 1, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "TARGET\tTYPE\tMODE\tSOURCE")
		for _, m := range resp.Mounts {
			mode := "rw"
			if m.ReadOnly {
				mode = "ro"
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", m.Target, m.Type, mode, m.Source)
		}
		return tw.Flush()
	})
	if usageErr != nil {
		return controlUsageError(stderr, cmdName, "%v", usageErr)
	}
	if writeErr != nil {
		return controlFail(stderr, cmdName, writeErr)
	}
	return 0
}

func mountAddSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "mount add"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)

	var mountType, src, dst, sizeStr, cacheDir string
	var readOnly bool
	fs.StringVar(&mountType, "type", "", "Mount type: tmpfs, volume, or bind")
	registerAlias([]string{"src", "source"}, func(n string) {
		fs.StringVar(&src, n, "", "Source host directory, named volume, or .ext4 image path")
	})
	registerAlias([]string{"dst", "target"}, func(n string) {
		fs.StringVar(&dst, n, "", "Guest mount destination path")
	})
	registerAlias([]string{"ro", "readonly"}, func(n string) {
		fs.BoolVar(&readOnly, n, false, "Mount read-only")
	})
	registerAlias([]string{"size", "tmpfs-size"}, func(n string) {
		fs.StringVar(&sizeStr, n, "", "Maximum tmpfs size (e.g. 64m)")
	})
	fs.StringVar(&cacheDir, "cache-dir", "", "EROFS cache parent directory for resolving named volumes")

	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() > 0 {
		return controlUsageError(stderr, cmdName, "unexpected argument %q", fs.Arg(0))
	}

	kind := strings.ToLower(strings.TrimSpace(mountType))
	dst = strings.TrimSpace(dst)
	src = strings.TrimSpace(src)
	if kind == "" || dst == "" {
		return controlUsageError(stderr, cmdName, "specify --type=<tmpfs|volume|bind> and --dst=<guest-path>")
	}

	req := control.MountAddRequest{
		Type:     kind,
		Source:   src,
		Target:   dst,
		ReadOnly: readOnly,
	}
	if strings.TrimSpace(sizeStr) != "" {
		tmpMnt, err := gvx.ParseTmpfs("/x:size=" + strings.TrimSpace(sizeStr))
		if err != nil {
			return controlUsageError(stderr, cmdName, "--size: %v", err)
		}
		req.TmpfsSizeBytes = tmpMnt.TmpfsSizeBytes
	}

	var sendFDs []int
	var volFile *os.File
	if kind == "volume" {
		if src == "" {
			return controlUsageError(stderr, cmdName, "--type=volume requires --src=<volume-name-or-.ext4-path>")
		}
		if runtime.GOOS == "windows" {
			return controlFail(stderr, cmdName, control.NewError(control.CodeUnsupported, "volume FD attach via SCM_RIGHTS is unsupported on Windows; use `rungv mount serve` instead"))
		}
		volPath := src
		if !strings.ContainsAny(src, `/\`) && !strings.HasSuffix(strings.ToLower(src), ".ext4") {
			volDir, err := gvx.VolumeDir(cacheDir)
			if err != nil {
				return controlFail(stderr, cmdName, err)
			}
			volPath = filepath.Join(volDir, src+".ext4")
		}
		flags := os.O_RDWR
		if readOnly {
			flags = os.O_RDONLY
		}
		f, err := os.OpenFile(volPath, flags, 0)
		if err != nil {
			return controlFail(stderr, cmdName, fmt.Errorf("open volume %q: %w", volPath, err))
		}
		volFile = f
		defer volFile.Close()
		sendFDs = []int{int(f.Fd())}
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var info control.MountInfo
	if err := client.Call(callCtx, control.MethodMountAdd, req, &info, sendFDs...); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	mode := "rw"
	if info.ReadOnly {
		mode = "ro"
	}
	_, _ = fmt.Fprintf(stdout, "mounted %s (%s, %s)\n", info.Target, info.Type, mode)
	return 0
}

func mountRemountSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "mount remount"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	var ro, rw bool
	registerAlias([]string{"ro", "readonly"}, func(n string) {
		fs.BoolVar(&ro, n, false, "Remount read-only")
	})
	fs.BoolVar(&rw, "rw", false, "Remount read-write")
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if ro == rw {
		return controlUsageError(stderr, cmdName, "specify exactly one of --ro or --rw")
	}
	if fs.NArg() != 1 {
		return controlUsageError(stderr, cmdName, "specify exactly one TARGET mount path")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	var info control.MountInfo
	if err := client.Call(callCtx, control.MethodMountRemount, control.MountRemountRequest{
		Target:   fs.Arg(0),
		ReadOnly: ro,
	}, &info); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	mode := "rw"
	if info.ReadOnly {
		mode = "ro"
	}
	_, _ = fmt.Fprintf(stdout, "remounted %s (%s)\n", info.Target, mode)
	return 0
}

func mountRemoveSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "mount rm"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 10*time.Second)
	var detach bool
	registerAlias([]string{"l", "detach"}, func(n string) {
		fs.BoolVar(&detach, n, false, "Lazy unmount (MNT_DETACH)")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() == 0 {
		return controlUsageError(stderr, cmdName, "specify at least one TARGET mount path")
	}

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()
	callCtx, cancel := target.callContext(ctx)
	defer cancel()

	for _, dst := range fs.Args() {
		if err := client.Call(callCtx, control.MethodMountRemove, control.MountRemoveRequest{
			Target: dst,
			Detach: detach,
		}, nil); err != nil {
			return controlFail(stderr, cmdName, err)
		}
		_, _ = fmt.Fprintf(stdout, "unmounted %s\n", dst)
	}
	return 0
}

func parseServeMountSpec(raw string) (hostDir, guestTarget string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", errors.New("empty mount specification (want HOST_PATH:GUEST_PATH)")
	}
	searchStart := 0
	if hasWindowsDrivePrefix(s) {
		searchStart = 2
	}
	idx := strings.IndexByte(s[searchStart:], ':')
	if idx < 0 {
		return "", "", fmt.Errorf("invalid mount spec %q (want HOST_PATH:GUEST_PATH)", raw)
	}
	split := searchStart + idx
	hostDir = strings.TrimSpace(s[:split])
	guestTarget = strings.TrimSpace(s[split+1:])
	if hostDir == "" || guestTarget == "" {
		return "", "", fmt.Errorf("invalid mount spec %q (want HOST_PATH:GUEST_PATH)", raw)
	}
	return hostDir, guestTarget, nil
}

func openRPCFSServeRoot(absHost string) (root *os.Root, singleFile bool, leafName string, err error) {
	fi, err := os.Stat(absHost)
	if err != nil {
		return nil, false, "", fmt.Errorf("open host path %q: %w", absHost, err)
	}
	if fi.IsDir() {
		root, err := os.OpenRoot(absHost)
		if err != nil {
			return nil, false, "", fmt.Errorf("open host directory %q: %w", absHost, err)
		}
		return root, false, "", nil
	}
	if !fi.Mode().IsRegular() {
		return nil, false, "", fmt.Errorf("open host path %q: must be a directory or regular file", absHost)
	}
	resolved, err := filepath.EvalSymlinks(absHost)
	if err != nil {
		return nil, false, "", fmt.Errorf("resolve host file %q: %w", absHost, err)
	}
	parentDir := filepath.Dir(resolved)
	leafName = filepath.Base(resolved)
	root, err = os.OpenRoot(parentDir)
	if err != nil {
		return nil, false, "", fmt.Errorf("open host parent directory %q: %w", parentDir, err)
	}
	return root, true, leafName, nil
}

func sendRPCFSResponse(ctx context.Context, stream *control.Stream, resp control.RPCFSResponse) error {
	err := stream.SendEvent(ctx, "rpcfs.resp", resp)
	if err == nil {
		return nil
	}
	if errors.Is(err, control.ErrFrameTooLarge) {
		return stream.SendEvent(ctx, "rpcfs.resp", control.RPCFSResponse{
			ID:    resp.ID,
			Errno: control.LinuxEIO,
			Error: "response exceeds max_frame_bytes",
		})
	}
	return err
}

func mountServeSubcommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	const cmdName = "mount serve"
	fs := newImageFlagSet(cmdName, stderr)
	target := addControlFlags(fs, 0)
	var readOnly bool
	registerAlias([]string{"ro", "readonly"}, func(n string) {
		fs.BoolVar(&readOnly, n, false, "Serve the host path read-only")
	})
	if code, stop := parseImageFlags(fs, args); stop {
		return code
	}
	if fs.NArg() != 1 {
		return controlUsageError(stderr, cmdName, "specify HOST_PATH:GUEST_PATH")
	}

	hostPath, guestTarget, err := parseServeMountSpec(fs.Arg(0))
	if err != nil {
		return controlUsageError(stderr, cmdName, "%v", err)
	}
	absHost, err := filepath.Abs(hostPath)
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	root, singleFile, leafName, err := openRPCFSServeRoot(absHost)
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer root.Close()

	client, err := target.dial(ctx, "")
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer client.Close()

	stream, err := client.OpenStream(ctx, control.MethodMountServe, control.MountServeRequest{
		Target:     guestTarget,
		ReadOnly:   readOnly,
		Label:      absHost,
		SingleFile: singleFile,
	})
	if err != nil {
		return controlFail(stderr, cmdName, err)
	}
	defer stream.Close()

	var resp control.MountServeResponse
	if err := stream.WaitResponse(ctx, &resp); err != nil {
		return controlFail(stderr, cmdName, err)
	}
	mode := "rw"
	if readOnly {
		mode = "ro"
	}
	_, _ = fmt.Fprintf(stdout, "Serving %s at %s (%s)\n", absHost, resp.Target, mode)

	maxFrameBytes := client.MaxFrameBytes()
	if maxFrameBytes <= 0 {
		maxFrameBytes = control.DefaultMaxFrameBytes
	}
	overhead := min(4096, maxFrameBytes/4)
	// Bound raw read payload so base64 + JSON envelope stays below max_frame_bytes.
	maxReadBytes := int64(max(512, ((maxFrameBytes-overhead)*3)/4))
	maxEventBytes := max(512, maxFrameBytes-overhead)

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()

	watcher := newRPCFSHostWatcher(root, singleFile, leafName, defaultRPCFSWatchInterval, defaultRPCFSMaxWatches, func(ev control.RPCFSNotifyEvent) {
		_ = stream.SendEvent(serveCtx, "rpcfs.notify", ev)
	})
	defer watcher.Close()

	cfg := rpcfsServeConfig{
		root:          root,
		singleFile:    singleFile,
		leafName:      leafName,
		readOnly:      readOnly,
		maxReadBytes:  maxReadBytes,
		maxEventBytes: maxEventBytes,
		watcher:       watcher,
	}

	workerLimit := min(max(runtime.GOMAXPROCS(0), 4), 16)
	sem := make(chan struct{}, workerLimit)
	var (
		wg        sync.WaitGroup
		sendErrMu sync.Mutex
		sendErr   error
	)
	recordSendErr := func(err error) {
		if err == nil || serveCtx.Err() != nil {
			return
		}
		sendErrMu.Lock()
		if sendErr == nil {
			sendErr = err
		}
		sendErrMu.Unlock()
		serveCancel()
	}

	var recvErr error
	for {
		ev, err := stream.RecvEvent(serveCtx)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
				recvErr = err
			}
			break
		}
		if ev.Type != "rpcfs.req" {
			continue
		}
		var req control.RPCFSRequest
		if err := json.Unmarshal(ev.Data, &req); err != nil {
			continue
		}
		select {
		case sem <- struct{}{}:
		case <-serveCtx.Done():
		}
		if serveCtx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(r control.RPCFSRequest) {
			defer wg.Done()
			defer func() { <-sem }()
			rpcResp := serveRPCFSRequestWithConfig(cfg, r)
			if err := sendRPCFSResponse(serveCtx, stream, rpcResp); err != nil {
				recordSendErr(err)
			}
		}(req)
	}
	serveCancel()
	wg.Wait()
	watcher.Close()

	sendErrMu.Lock()
	sErr := sendErr
	sendErrMu.Unlock()
	if sErr != nil {
		return controlFail(stderr, cmdName, sErr)
	}
	if recvErr != nil {
		return controlFail(stderr, cmdName, recvErr)
	}
	return 0
}

func cleanRPCFSRelPath(raw string) (string, bool) {
	if strings.ContainsRune(raw, 0) {
		return "", false
	}
	norm := strings.ReplaceAll(raw, `\`, "/")
	if hasWindowsDriveDesignator(norm) {
		return "", false
	}
	for _, seg := range strings.Split(norm, "/") {
		if seg == ".." {
			return "", false
		}
	}
	p := path.Clean("/" + norm)
	rel := strings.TrimPrefix(p, "/")
	if rel == "" {
		return ".", true
	}
	return rel, true
}

func lstatRegularInRoot(root *os.Root, rel string) int {
	fi, err := root.Lstat(rel)
	if err != nil {
		return control.HostErrorToLinuxErrno(err)
	}
	switch {
	case fi.Mode()&os.ModeSymlink != 0:
		return control.LinuxELOOP
	case fi.IsDir():
		return control.LinuxEISDIR
	case !fi.Mode().IsRegular():
		return control.LinuxEOPNOTSUPP
	default:
		return 0
	}
}

func rpcfsRelDepth(rel string) int {
	if rel == "." || rel == "" {
		return 0
	}
	return len(strings.Split(rel, "/"))
}

// verifySubtreeSymlinksAtDest verifies that moving srcRel to dstRel does not
// cause any symlink inside srcRel (either srcRel itself or any descendant) to
// escape root at its new shallower depth.
func verifySubtreeSymlinksAtDest(root *os.Root, srcRel, dstRel string) error {
	fi, err := root.Lstat(srcRel)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := root.Readlink(srcRel)
		if err != nil {
			return err
		}
		return validateSafeSymlinkTarget(dstRel, target)
	}
	if !fi.IsDir() {
		return nil
	}
	f, err := root.Open(srcRel)
	if err != nil {
		return err
	}
	des, err := f.ReadDir(-1)
	_ = f.Close()
	if err != nil {
		return err
	}
	for _, de := range des {
		childSrc := path.Join(srcRel, de.Name())
		childDst := path.Join(dstRel, de.Name())
		if err := verifySubtreeSymlinksAtDest(root, childSrc, childDst); err != nil {
			return err
		}
	}
	return nil
}

func stablePathIno(rel string) uint64 {
	if rel == "." || rel == "" {
		return 1
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(rel))
	v := h.Sum64()
	if v <= 1 {
		return 2
	}
	return v
}

func osModeToLinuxMode(m os.FileMode) uint32 {
	perm := uint32(m.Perm())
	if m&os.ModeSetuid != 0 {
		perm |= 0o4000
	}
	if m&os.ModeSetgid != 0 {
		perm |= 0o2000
	}
	if m&os.ModeSticky != 0 {
		perm |= 0o1000
	}
	switch {
	case m.IsDir():
		return control.LinuxSIFDIR | perm
	case m&os.ModeSymlink != 0:
		return control.LinuxSIFLNK | perm
	default:
		return control.LinuxSIFREG | perm
	}
}

func entryFromFileInfo(rel, name string, fi os.FileInfo, root *os.Root) control.RPCFSEntry {
	nlink := uint32(1)
	if fi.IsDir() {
		nlink = 2
	}
	var linkTarget string
	if fi.Mode()&os.ModeSymlink != 0 && root != nil {
		if target, err := root.Readlink(rel); err == nil {
			linkTarget = target
		}
	}
	mtime := fi.ModTime().UnixNano()
	return control.RPCFSEntry{
		Name:       name,
		Ino:        stablePathIno(rel),
		Mode:       osModeToLinuxMode(fi.Mode()),
		Size:       fi.Size(),
		Nlink:      nlink,
		AtimeNS:    mtime,
		MtimeNS:    mtime,
		CtimeNS:    mtime,
		LinkTarget: linkTarget,
	}
}

type rpcfsServeConfig struct {
	root          *os.Root
	singleFile    bool
	leafName      string
	readOnly      bool
	maxReadBytes  int64
	maxEventBytes int
	watcher       *rpcfsHostWatcher
}

func serveRPCFSRequest(root *os.Root, readOnly bool, maxReadBytes int64, req control.RPCFSRequest) control.RPCFSResponse {
	return serveRPCFSRequestWithConfig(rpcfsServeConfig{
		root:          root,
		readOnly:      readOnly,
		maxReadBytes:  maxReadBytes,
		maxEventBytes: control.DefaultMaxFrameBytes - 4096,
	}, req)
}

func serveRPCFSRequestWithConfig(cfg rpcfsServeConfig, req control.RPCFSRequest) control.RPCFSResponse {
	resp := control.RPCFSResponse{ID: req.ID}
	rel, ok := cleanRPCFSRelPath(req.Path)
	if !ok {
		resp.Errno = control.LinuxEINVAL
		return resp
	}
	root := cfg.root
	readOnly := cfg.readOnly
	maxReadBytes := cfg.maxReadBytes
	if maxReadBytes <= 0 {
		maxReadBytes = 128 << 10
	}
	maxEventBytes := cfg.maxEventBytes
	if maxEventBytes <= 0 {
		maxEventBytes = control.DefaultMaxFrameBytes - 4096
	}

	hostRel := rel
	if cfg.singleFile {
		if rel != "." {
			resp.Errno = control.LinuxENOTDIR
			return resp
		}
		switch req.Op {
		case "readdir", "create", "mkdir", "symlink":
			resp.Errno = control.LinuxENOTDIR
			return resp
		case "unlink", "rmdir", "rename":
			resp.Errno = control.LinuxEBUSY
			return resp
		case "readlink":
			resp.Errno = control.LinuxEINVAL
			return resp
		}
		hostRel = cfg.leafName
	}

	beginMut := func(paths ...string) func() {
		if cfg.watcher == nil {
			return func() {}
		}
		targets := cfg.watcher.BeginMutation(paths...)
		return func() {
			cfg.watcher.EndMutation(targets)
		}
	}

	switch req.Op {
	case "stat":
		fi, err := root.Lstat(hostRel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		name := path.Base(rel)
		statRoot := root
		if cfg.singleFile {
			name = ""
			statRoot = nil
		}
		entry := entryFromFileInfo(hostRel, name, fi, statRoot)
		if cfg.singleFile {
			entry.Ino = 1
		} else {
			entry.Ino = stablePathIno(rel)
		}
		resp.Entry = &entry
		return resp

	case "readdir":
		if req.Offset < 0 {
			resp.Errno = control.LinuxEINVAL
			return resp
		}
		f, err := root.Open(hostRel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		des, err := f.ReadDir(-1)
		_ = f.Close()
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		sortDirEntriesByName(des)
		if req.Offset >= int64(len(des)) {
			return resp
		}
		budget := maxEventBytes - 256
		if budget < 1024 {
			budget = 1024
		}
		var (
			entries []control.RPCFSEntry
			used    int
		)
		for i := int(req.Offset); i < len(des); i++ {
			de := des[i]
			childRel := de.Name()
			if rel != "." {
				childRel = rel + "/" + de.Name()
			}
			fi, err := root.Lstat(childRel)
			if err != nil {
				continue
			}
			entry := entryFromFileInfo(childRel, de.Name(), fi, root)
			encoded, mErr := json.Marshal(entry)
			if mErr != nil {
				continue
			}
			entrySize := len(encoded) + 1
			if used+entrySize > budget {
				if len(entries) == 0 {
					resp.Errno = control.LinuxEIO
					resp.Error = "directory entry exceeds max_frame_bytes"
					return resp
				}
				resp.HasMore = true
				resp.NextOffset = int64(i)
				break
			}
			entries = append(entries, entry)
			used += entrySize
		}
		resp.Entries = entries
		return resp

	case "read":
		if req.Offset < 0 {
			resp.Errno = control.LinuxEINVAL
			return resp
		}
		if errno := lstatRegularInRoot(root, hostRel); errno != 0 {
			resp.Errno = errno
			return resp
		}
		length := req.Length
		if length <= 0 {
			return resp
		}
		if length > maxReadBytes {
			length = maxReadBytes
		}
		f, err := root.Open(hostRel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		buf := make([]byte, length)
		n, err := f.ReadAt(buf, req.Offset)
		_ = f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		resp.Data = buf[:n]
		resp.EOF = errors.Is(err, io.EOF)
		return resp

	case "write":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		if req.Offset < 0 {
			resp.Errno = control.LinuxEINVAL
			return resp
		}
		if errno := lstatRegularInRoot(root, hostRel); errno != 0 {
			resp.Errno = errno
			return resp
		}
		defer beginMut(rel)()
		f, err := root.OpenFile(hostRel, os.O_WRONLY, 0)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		n, err := f.WriteAt(req.Data, req.Offset)
		closeErr := f.Close()
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		if closeErr != nil {
			resp.Errno = control.HostErrorToLinuxErrno(closeErr)
			return resp
		}
		resp.Written = int64(n)
		return resp

	case "create":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		defer beginMut(rel)()
		perm := os.FileMode(req.Mode & 0o777)
		flags := os.O_CREATE | os.O_RDWR
		if req.Flags&control.LinuxOExcl != 0 {
			flags |= os.O_EXCL
		}
		f, err := root.OpenFile(rel, flags, perm)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		_ = f.Close()
		fi, err := root.Lstat(rel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		entry := entryFromFileInfo(rel, path.Base(rel), fi, root)
		resp.Entry = &entry
		return resp

	case "mkdir":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		defer beginMut(rel)()
		perm := os.FileMode(req.Mode & 0o777)
		if err := root.Mkdir(rel, perm); err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		fi, err := root.Lstat(rel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		entry := entryFromFileInfo(rel, path.Base(rel), fi, root)
		resp.Entry = &entry
		return resp

	case "unlink":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		fi, err := root.Lstat(rel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		if fi.IsDir() {
			resp.Errno = control.LinuxEISDIR
			return resp
		}
		defer beginMut(rel)()
		if err := root.Remove(rel); err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		}
		return resp

	case "rmdir":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		fi, err := root.Lstat(rel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		if !fi.IsDir() {
			resp.Errno = control.LinuxENOTDIR
			return resp
		}
		defer beginMut(rel)()
		if err := root.Remove(rel); err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		}
		return resp

	case "rename":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		newRel, ok := cleanRPCFSRelPath(req.NewPath)
		if !ok {
			resp.Errno = control.LinuxEINVAL
			return resp
		}
		if err := verifyExistingAncestorsInRoot(root, path.Dir(rel)); err != nil {
			resp.Errno = control.LinuxEPERM
			return resp
		}
		if err := verifyExistingAncestorsInRoot(root, path.Dir(newRel)); err != nil {
			resp.Errno = control.LinuxEPERM
			return resp
		}
		if rpcfsRelDepth(newRel) < rpcfsRelDepth(rel) {
			if err := verifySubtreeSymlinksAtDest(root, rel, newRel); err != nil {
				if os.IsNotExist(err) {
					resp.Errno = control.LinuxENOENT
				} else {
					resp.Errno = control.LinuxEPERM
				}
				return resp
			}
		}
		defer beginMut(rel, newRel)()
		if err := root.Rename(rel, newRel); err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		}
		return resp

	case "truncate":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		if errno := lstatRegularInRoot(root, hostRel); errno != 0 {
			resp.Errno = errno
			return resp
		}
		defer beginMut(rel)()
		f, err := root.OpenFile(hostRel, os.O_WRONLY, 0)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		err = f.Truncate(req.Size)
		closeErr := f.Close()
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		} else if closeErr != nil {
			resp.Errno = control.HostErrorToLinuxErrno(closeErr)
		}
		return resp

	case "chmod":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		if cfg.singleFile {
			if errno := lstatRegularInRoot(root, hostRel); errno != 0 {
				resp.Errno = errno
				return resp
			}
		}
		defer beginMut(rel)()
		if err := root.Chmod(hostRel, os.FileMode(req.Mode&0o777)); err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		}
		return resp

	case "utimens":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		if cfg.singleFile {
			if errno := lstatRegularInRoot(root, hostRel); errno != 0 {
				resp.Errno = errno
				return resp
			}
		}
		var atime, mtime time.Time
		if req.SetAtime {
			atime = time.Unix(0, req.AtimeNS)
		}
		if req.SetMtime {
			mtime = time.Unix(0, req.MtimeNS)
		}
		defer beginMut(rel)()
		if err := root.Chtimes(hostRel, atime, mtime); err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		}
		return resp

	case "readlink":
		target, err := root.Readlink(rel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		resp.Entry = &control.RPCFSEntry{LinkTarget: target}
		return resp

	case "symlink":
		if readOnly {
			resp.Errno = control.LinuxEROFS
			return resp
		}
		if err := validateSafeSymlinkTarget(rel, req.Target); err != nil {
			resp.Errno = control.LinuxEPERM
			return resp
		}
		// Reject any ".." segment in rpcfs symlinks so neither chained symlinks
		// nor later directory renames can ever escape the served host root.
		for _, seg := range strings.Split(req.Target, "/") {
			if seg == ".." {
				resp.Errno = control.LinuxEPERM
				return resp
			}
		}
		if err := verifyExistingAncestorsInRoot(root, path.Dir(rel)); err != nil {
			resp.Errno = control.LinuxEPERM
			return resp
		}
		defer beginMut(rel)()
		if err := root.Symlink(req.Target, rel); err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		}
		return resp

	case "watch":
		if cfg.watcher == nil {
			resp.Errno = control.LinuxEOPNOTSUPP
			return resp
		}
		resp.Errno = cfg.watcher.Add(rel)
		return resp

	case "unwatch":
		if cfg.watcher != nil {
			cfg.watcher.Remove(rel)
		}
		return resp

	default:
		resp.Errno = control.LinuxEOPNOTSUPP
		return resp
	}
}
