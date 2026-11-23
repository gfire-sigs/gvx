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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func TestParseControlRunFlags(t *testing.T) {
	rc, code, done, stderr := parse(t,
		"--name", "web1",
		"--control",
		"--control-policy", "readonly",
		"--control-disable", "exec,net.dial",
		"--dynamic-ports",
		"--dynamic-ports-addr", "0.0.0.0",
		"--dynamic-ports-addr", "127.0.0.1",
		"--auto-publish",
		"--auto-publish-addr", "0.0.0.0",
		"--allow-volume-attach",
		"--allow-bind-attach",
		"--pids-limit", "64",
		"alpine:3.20",
	)
	if done || code != 0 {
		t.Fatalf("parseRunArgs failed: code=%d done=%v stderr=%q", code, done, stderr)
	}
	if !strings.HasSuffix(rc.controlSocket, "web1.sock") {
		t.Errorf("controlSocket = %q, want suffix web1.sock", rc.controlSocket)
	}
	if rc.cfg.ControlPolicy != control.PolicyReadOnly {
		t.Errorf("ControlPolicy = %q, want readonly", rc.cfg.ControlPolicy)
	}
	if len(rc.cfg.ControlDisable) != 2 || rc.cfg.ControlDisable[0] != "exec" || rc.cfg.ControlDisable[1] != "net.dial" {
		t.Errorf("ControlDisable = %v", rc.cfg.ControlDisable)
	}
	if !rc.cfg.DynamicPorts || !rc.cfg.AutoPublishPorts || rc.cfg.AutoPublishAddr != "0.0.0.0" || !rc.cfg.AllowVolumeAttach || !rc.cfg.AllowBindAttach || rc.cfg.Resources.PidsLimit != 64 {
		t.Errorf("flags mismatch: dyn=%v auto=%v autoAddr=%q vol=%v bind=%v pids=%d", rc.cfg.DynamicPorts, rc.cfg.AutoPublishPorts, rc.cfg.AutoPublishAddr, rc.cfg.AllowVolumeAttach, rc.cfg.AllowBindAttach, rc.cfg.Resources.PidsLimit)
	}
	if len(rc.cfg.DynamicPortAddrs) != 2 || rc.cfg.DynamicPortAddrs[0] != "0.0.0.0" || rc.cfg.DynamicPortAddrs[1] != "127.0.0.1" {
		t.Errorf("DynamicPortAddrs = %v, want [0.0.0.0 127.0.0.1]", rc.cfg.DynamicPortAddrs)
	}

	// --control without --name must return exit code 2.
	_, badCode, badDone, badErr := parse(t, "--control", "alpine:3.20")
	if !badDone || badCode != 2 || !strings.Contains(badErr, "--control requires --name") {
		t.Fatalf("--control without --name = (code=%d done=%v stderr=%q)", badCode, badDone, badErr)
	}

	// Unknown --control-disable capability typo must fail with exit code 2.
	_, typoCode, typoDone, typoErr := parse(t, "--name", "web1", "--control", "--control-disable", "exce", "alpine:3.20")
	if !typoDone || typoCode != 2 || !strings.Contains(typoErr, "unknown") {
		t.Fatalf("--control-disable=exce = (code=%d done=%v stderr=%q), want exit 2", typoCode, typoDone, typoErr)
	}
}

func TestControlUsageErrorFormatting(t *testing.T) {
	var buf bytes.Buffer
	if code := controlUsageError(&buf, "exec", "specify a command to execute"); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if got := buf.String(); got != "rungv exec: specify a command to execute\n" {
		t.Fatalf("formatted = %q, want %q", got, "rungv exec: specify a command to execute\n")
	}

	buf.Reset()
	if code := controlUsageError(&buf, "pause", "unexpected argument %q", "foo"); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if got := buf.String(); got != "rungv pause: unexpected argument \"foo\"\n" {
		t.Fatalf("formatted = %q, want %q", got, "rungv pause: unexpected argument \"foo\"\n")
	}
}

func TestParseCPEndpointAndWindowsDriveSafety(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		isGuest  bool
		isPipe   bool
		sandbox  string
		wantPath string
	}{
		{raw: "-", isPipe: true, wantPath: "-"},
		{raw: ":/etc/hosts", isGuest: true, wantPath: "/etc/hosts"},
		{raw: "web1:/var/log/app.log", isGuest: true, sandbox: "web1", wantPath: "/var/log/app.log"},
		{raw: `C:\Users\dev\file.txt`, isGuest: false, wantPath: `C:\Users\dev\file.txt`},
		{raw: `D:/work/app`, isGuest: false, wantPath: `D:/work/app`},
		{raw: "./local/file.txt", isGuest: false, wantPath: "./local/file.txt"},
	} {
		got := parseCPEndpoint(tc.raw)
		if got.isGuest != tc.isGuest || got.isPipe != tc.isPipe || got.sandboxName != tc.sandbox || got.path != tc.wantPath {
			t.Errorf("parseCPEndpoint(%q) = %+v, want guest=%v pipe=%v sb=%q path=%q",
				tc.raw, got, tc.isGuest, tc.isPipe, tc.sandbox, tc.wantPath)
		}
	}
}

func TestParseDetachKeysAndCopyWithDetach(t *testing.T) {
	seq, err := parseDetachKeys("ctrl-p,ctrl-q")
	if err != nil {
		t.Fatalf("parseDetachKeys: %v", err)
	}
	if !bytes.Equal(seq, []byte{0x10, 0x11}) {
		t.Fatalf("seq = %x, want 1011", seq)
	}
	var out bytes.Buffer
	detached := copyWithDetach(&out, bytes.NewReader([]byte{'a', 0x10, 'b', 0x10, 0x11, 'c'}), seq)
	if !detached {
		t.Fatal("copyWithDetach returned false, want true")
	}
	if !bytes.Equal(out.Bytes(), []byte{'a', 0x10, 'b'}) {
		t.Fatalf("forwarded bytes = %x, want 611062", out.Bytes())
	}

	// Single uppercase character must preserve case.
	upperSeq, err := parseDetachKeys("Q")
	if err != nil || !bytes.Equal(upperSeq, []byte{'Q'}) {
		t.Fatalf("parseDetachKeys(Q) = (%x, %v), want 51", upperSeq, err)
	}

	// Repeating prefix (a,a,b on "aaab") requires KMP prefix fallback.
	repSeq, err := parseDetachKeys("a,a,b")
	if err != nil {
		t.Fatalf("parseDetachKeys(a,a,b): %v", err)
	}
	out.Reset()
	if !copyWithDetach(&out, strings.NewReader("aaabZ"), repSeq) {
		t.Fatal("copyWithDetach missed repeating prefix a,a,b in aaab")
	}
	if out.String() != "a" {
		t.Fatalf("forwarded bytes = %q, want \"a\"", out.String())
	}
}

func TestParseTunnelAndServeMountSpecs(t *testing.T) {
	ts, err := parseTunnelSpec("8080:80", "127.0.0.1", "")
	if err != nil || ts.listenAddr != "127.0.0.1:8080" || ts.guestPort != 80 {
		t.Fatalf("parseTunnelSpec(8080:80) = (%+v, %v)", ts, err)
	}
	ts2, err := parseTunnelSpec("0.0.0.0:9090:172.17.0.2:8080", "127.0.0.1", "")
	if err != nil || ts2.listenAddr != "0.0.0.0:9090" || ts2.guestIP != "172.17.0.2" || ts2.guestPort != 8080 {
		t.Fatalf("parseTunnelSpec(4-part) = (%+v, %v)", ts2, err)
	}
	ts6, err := parseTunnelSpec("[::1]:8080:80", "127.0.0.1", "")
	if err != nil || ts6.listenAddr != "[::1]:8080" || ts6.guestPort != 80 {
		t.Fatalf("parseTunnelSpec(ipv6 3-part) = (%+v, %v)", ts6, err)
	}
	ts6Four, err := parseTunnelSpec("[::1]:8080:[::1]:9090", "127.0.0.1", "")
	if err != nil || ts6Four.listenAddr != "[::1]:8080" || ts6Four.guestIP != "::1" || ts6Four.guestPort != 9090 {
		t.Fatalf("parseTunnelSpec(ipv6 4-part) = (%+v, %v)", ts6Four, err)
	}
	hostDir, guestTarget, err := parseServeMountSpec(`C:\src\proj:/mnt/proj`)
	if err != nil || hostDir != `C:\src\proj` || guestTarget != "/mnt/proj" {
		t.Fatalf("parseServeMountSpec(win) = (%q, %q, %v)", hostDir, guestTarget, err)
	}
}

func TestExtractTarToHostDirSecurity(t *testing.T) {
	makeTar := func(entries ...tar.Header) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for _, h := range entries {
			if err := tw.WriteHeader(&h); err != nil {
				t.Fatal(err)
			}
			if h.Typeflag == tar.TypeReg && h.Size > 0 {
				if _, err := tw.Write(bytes.Repeat([]byte("x"), int(h.Size))); err != nil {
					t.Fatal(err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	// 1. Classic ../ traversal rejected.
	if err := extractTarToHostDir(bytes.NewReader(makeTar(
		tar.Header{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3},
	)), t.TempDir(), hostExtractOptions{}); err == nil {
		t.Fatal("accepted ../escape.txt")
	}

	// 2. Chained relative symlink escapes rejected (both parent-traversal and non-leading '..').
	if runtime.GOOS != "windows" {
		chained := makeTar(
			tar.Header{Name: "a/b/", Typeflag: tar.TypeDir, Mode: 0o755},
			tar.Header{Name: "a/b/up", Typeflag: tar.TypeSymlink, Linkname: "../.."},
			tar.Header{Name: "a/b/up/escape", Typeflag: tar.TypeSymlink, Linkname: "../../outside"},
		)
		if err := extractTarToHostDir(bytes.NewReader(chained), t.TempDir(), hostExtractOptions{}); err == nil {
			t.Fatal("accepted chained relative symlink escape via parent traversal")
		}
		nonLeadingUp := makeTar(
			tar.Header{Name: "a/b/", Typeflag: tar.TypeDir, Mode: 0o755},
			tar.Header{Name: "a/b/up", Typeflag: tar.TypeSymlink, Linkname: "../.."},
			tar.Header{Name: "a/c", Typeflag: tar.TypeSymlink, Linkname: "b/up/../../../etc/passwd"},
		)
		if err := extractTarToHostDir(bytes.NewReader(nonLeadingUp), t.TempDir(), hostExtractOptions{}); err == nil {
			t.Fatal("accepted chained relative symlink escape via non-leading '..'")
		}
		// Hardlinking a valid deep '..' symlink to root depth must be rejected.
		elevateLink := makeTar(
			tar.Header{Name: "a/b/c/d/", Typeflag: tar.TypeDir, Mode: 0o755},
			tar.Header{Name: "a/b/c/d/link", Typeflag: tar.TypeSymlink, Linkname: "../../../../etc/passwd"},
			tar.Header{Name: "escape", Typeflag: tar.TypeLink, Linkname: "a/b/c/d/link"},
		)
		if err := extractTarToHostDir(bytes.NewReader(elevateLink), t.TempDir(), hostExtractOptions{}); err == nil {
			t.Fatal("accepted TypeLink elevating deep symlink to root depth")
		}
	}

	// 3. Windows drive / drive-relative / UNC / backslash symlink targets rejected on all OSes.
	for _, badTarget := range []string{`C:\Windows\win.ini`, `C:secret.txt`, `\\server\share\x`, `..\..\outside`, `sub/../outside`} {
		badTar := makeTar(tar.Header{Name: "sub/link", Typeflag: tar.TypeSymlink, Linkname: badTarget})
		if err := extractTarToHostDir(bytes.NewReader(badTar), t.TempDir(), hostExtractOptions{}); err == nil {
			t.Fatalf("accepted unsafe symlink target %q", badTarget)
		}
	}

	// 4. Symlink clobber on TypeReg: replacing symlink "a -> b" with regular file "a" must not clobber "b".
	if runtime.GOOS != "windows" {
		dest := t.TempDir()
		if err := os.WriteFile(filepath.Join(dest, "b"), []byte("keep-me"), 0o600); err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		_ = tw.WriteHeader(&tar.Header{Name: "a", Typeflag: tar.TypeSymlink, Linkname: "b"})
		_ = tw.WriteHeader(&tar.Header{Name: "a", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
		_, _ = tw.Write([]byte("new"))
		_ = tw.Close()
		if err := extractTarToHostDir(&buf, dest, hostExtractOptions{}); err != nil {
			t.Fatalf("extract symlink replace: %v", err)
		}
		gotB, err := os.ReadFile(filepath.Join(dest, "b"))
		if err != nil || string(gotB) != "keep-me" {
			t.Fatalf("file b was clobbered via symlink: (%q, %v)", gotB, err)
		}
		gotA, err := os.ReadFile(filepath.Join(dest, "a"))
		if err != nil || string(gotA) != "new" {
			t.Fatalf("file a = (%q, %v), want new", gotA, err)
		}
	}

	// 5. renameSingleTo rejects multi-entry tar, TypeLink, and invalid names.
	multiTar := makeTar(
		tar.Header{Name: "one.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
		tar.Header{Name: "two.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1},
	)
	if err := extractTarToHostDir(bytes.NewReader(multiTar), t.TempDir(), hostExtractOptions{renameSingleTo: "out.txt"}); err == nil {
		t.Fatal("renameSingleTo accepted multi-entry tar")
	}
	linkTar := makeTar(tar.Header{Name: "h", Typeflag: tar.TypeLink, Linkname: "target"})
	if err := extractTarToHostDir(bytes.NewReader(linkTar), t.TempDir(), hostExtractOptions{renameSingleTo: "out.txt"}); err == nil {
		t.Fatal("renameSingleTo accepted TypeLink")
	}
	if err := extractTarToHostDir(bytes.NewReader(makeTar(tar.Header{Name: "a", Typeflag: tar.TypeReg, Size: 1})), t.TempDir(), hostExtractOptions{renameSingleTo: "../bad"}); err == nil {
		t.Fatal("renameSingleTo accepted ../bad")
	}

	// 6. Regular file preserves non-zero ModTime via root.Chtimes.
	wantTime := time.Date(2024, 3, 14, 15, 9, 26, 0, time.UTC)
	dest := t.TempDir()
	singleTar := makeTar(tar.Header{Name: "ts.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2, ModTime: wantTime})
	if err := extractTarToHostDir(bytes.NewReader(singleTar), dest, hostExtractOptions{}); err != nil {
		t.Fatalf("extract ts.txt: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dest, "ts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Unix() != wantTime.Unix() {
		t.Fatalf("ModTime = %v, want %v", fi.ModTime(), wantTime)
	}
}

func TestServeRPCFSRequestSecurityAndSemantics(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	// 1. Path traversal rejected with EINVAL.
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "stat", Path: "../../etc/passwd"}); resp.Errno != control.LinuxEINVAL {
		t.Fatalf("stat ../../etc/passwd errno = %d, want EINVAL (%d)", resp.Errno, control.LinuxEINVAL)
	}

	// 2. Escaping / absolute / drive-relative / '..' / backslash symlink targets rejected with EPERM.
	for _, target := range []string{"/etc/passwd", "../secret", "a/../b", `C:\win.ini`, `C:secret.txt`, `a\b`} {
		resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "symlink", Path: "/sub/badlink", Target: target})
		if resp.Errno != control.LinuxEPERM {
			t.Fatalf("symlink %q errno = %d, want EPERM (%d)", target, resp.Errno, control.LinuxEPERM)
		}
	}
	// Drive-prefixed path rejected cleanly in cleanRPCFSRelPath.
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "stat", Path: "C:secret.txt"}); resp.Errno != control.LinuxEINVAL {
		t.Fatalf("stat C:secret.txt errno = %d, want EINVAL (%d)", resp.Errno, control.LinuxEINVAL)
	}

	// 3. Create dir + file, verify unlink rejects dir (EISDIR) and rmdir rejects file (ENOTDIR).
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "mkdir", Path: "/sub", Mode: 0o755}); resp.Errno != 0 {
		t.Fatalf("mkdir /sub errno = %d", resp.Errno)
	}
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "create", Path: "/f.txt", Mode: 0o644}); resp.Errno != 0 {
		t.Fatalf("create /f.txt errno = %d", resp.Errno)
	}
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "unlink", Path: "/sub"}); resp.Errno != control.LinuxEISDIR {
		t.Fatalf("unlink dir errno = %d, want EISDIR (%d)", resp.Errno, control.LinuxEISDIR)
	}
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "rmdir", Path: "/f.txt"}); resp.Errno != control.LinuxENOTDIR {
		t.Fatalf("rmdir file errno = %d, want ENOTDIR (%d)", resp.Errno, control.LinuxENOTDIR)
	}
	// read/write/truncate on directories return EISDIR.
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "read", Path: "/sub", Length: 4}); resp.Errno != control.LinuxEISDIR {
		t.Fatalf("read dir errno = %d, want EISDIR", resp.Errno)
	}
	// Symlink read/write/truncate return ELOOP without touching target; pre-existing deep '..' symlink cannot be elevated via rename.
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(filepath.Join(dir, "target.txt"), []byte("keep-intact"), 0o600); err != nil {
			t.Fatal(err)
		}
		if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "symlink", Path: "/goodlink", Target: "target.txt"}); resp.Errno != 0 {
			t.Fatalf("create safe sibling symlink errno = %d", resp.Errno)
		}
		for _, op := range []string{"read", "write", "truncate"} {
			resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: op, Path: "/goodlink", Length: 4, Data: []byte("bad"), Size: 0})
			if resp.Errno != control.LinuxELOOP {
				t.Fatalf("%s on symlink errno = %d, want ELOOP (%d)", op, resp.Errno, control.LinuxELOOP)
			}
		}
		if got, err := os.ReadFile(filepath.Join(dir, "target.txt")); err != nil || string(got) != "keep-intact" {
			t.Fatalf("symlink op modified target.txt: (%q, %v)", got, err)
		}
		// Pre-existing host deep '..' symlink inside a/b/deep cannot be renamed to a shallower depth directly or via its parent dir.
		if err := os.MkdirAll(filepath.Join(dir, "a", "b"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../../target.txt", filepath.Join(dir, "a", "b", "deep")); err != nil {
			t.Fatal(err)
		}
		if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "rename", Path: "/a/b/deep", NewPath: "/deep"}); resp.Errno != control.LinuxEPERM {
			t.Fatalf("direct rename elevating deep '..' symlink errno = %d, want EPERM", resp.Errno)
		}
		if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "rename", Path: "/a/b", NewPath: "/b"}); resp.Errno != control.LinuxEPERM {
			t.Fatalf("parent dir rename elevating deep '..' symlink errno = %d, want EPERM", resp.Errno)
		}
	}

	// 4. Negative read offset rejected; oversized read length capped to maxReadBytes.
	if resp := serveRPCFSRequest(root, false, 16, control.RPCFSRequest{Op: "write", Path: "/f.txt", Offset: 0, Data: bytes.Repeat([]byte("A"), 64)}); resp.Errno != 0 {
		t.Fatalf("write /f.txt errno = %d", resp.Errno)
	}
	if resp := serveRPCFSRequest(root, false, 16, control.RPCFSRequest{Op: "read", Path: "/f.txt", Offset: -1, Length: 4}); resp.Errno != control.LinuxEINVAL {
		t.Fatalf("read negative offset errno = %d, want EINVAL", resp.Errno)
	}
	if resp := serveRPCFSRequest(root, false, 16, control.RPCFSRequest{Op: "read", Path: "/f.txt", Offset: 0, Length: 100}); resp.Errno != 0 || len(resp.Data) != 16 {
		t.Fatalf("bounded read = (errno=%d, len=%d), want (0, 16)", resp.Errno, len(resp.Data))
	}

	// 5. utimens preserves omitted mtime instead of overwriting with time.Now().
	oldMtime := time.Date(2022, 1, 2, 3, 4, 5, 0, time.UTC)
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{
		Op: "utimens", Path: "/f.txt", SetMtime: true, MtimeNS: oldMtime.UnixNano(),
	}); resp.Errno != 0 {
		t.Fatalf("utimens set mtime errno = %d", resp.Errno)
	}
	newAtime := time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)
	if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{
		Op: "utimens", Path: "/f.txt", SetAtime: true, AtimeNS: newAtime.UnixNano(), SetMtime: false,
	}); resp.Errno != 0 {
		t.Fatalf("utimens set atime only errno = %d", resp.Errno)
	}
	fi, err := os.Stat(filepath.Join(dir, "f.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Unix() != oldMtime.Unix() {
		t.Fatalf("mtime after atime-only utimens = %v, want preserved %v", fi.ModTime(), oldMtime)
	}

	// 6. Mode 0000 is preserved rather than widened to 0644 on Unix.
	if runtime.GOOS != "windows" {
		if resp := serveRPCFSRequest(root, false, 1024, control.RPCFSRequest{Op: "create", Path: "/zero.txt", Mode: 0o000}); resp.Errno != 0 {
			t.Fatalf("create mode 0000 errno = %d", resp.Errno)
		}
		zfi, err := os.Lstat(filepath.Join(dir, "zero.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if zfi.Mode().Perm() != 0o000 {
			t.Fatalf("mode 0000 file got perm %#o, want 0000", zfi.Mode().Perm())
		}
		_ = os.Chmod(filepath.Join(dir, "zero.txt"), 0o600)
	}
}

type mockCLIControlHandler struct {
	onStream func(ctx context.Context, stream *control.Stream, req control.RequestEnvelope) error
}

func (m *mockCLIControlHandler) HandleStream(ctx context.Context, stream *control.Stream, req control.RequestEnvelope, fds []int) error {
	for _, fd := range fds {
		_ = os.NewFile(uintptr(fd), "unused").Close()
	}
	return m.onStream(ctx, stream, req)
}

func (m *mockCLIControlHandler) HandleLegacyCheckpoint(context.Context, control.LegacyCheckpointRequest) error {
	return nil
}

func startMockCLIServer(t *testing.T, caps []string, fn func(ctx context.Context, stream *control.Stream, req control.RequestEnvelope) error, features ...string) *control.Endpoint {
	t.Helper()
	isolateControlTokenDir(t)
	addr := freeLoopbackAddr(t)
	ep, err := control.Listen("tcp://"+addr, control.ListenOptions{})
	if err != nil {
		t.Fatalf("control.Listen: %v", err)
	}
	t.Cleanup(ep.Cleanup)
	srv := control.NewServer(ep.Listener, control.ServerConfig{
		SandboxID:    "mock-sbx",
		Token:        ep.Token,
		Capabilities: caps,
		Features:     features,
		Handler:      &mockCLIControlHandler{onStream: fn},
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-done
	})
	return ep
}

func TestCPHostToGuestEarlyRejectionLargeUploadNoDeadlock(t *testing.T) {
	ep := startMockCLIServer(t, []string{control.CapFSExport, control.CapFSImport}, func(_ context.Context, stream *control.Stream, req control.RequestEnvelope) error {
		if req.Method == control.MethodFSStat {
			return stream.Reply(control.FSStatResponse{Exists: true, Type: "dir"})
		}
		// Immediately reject fs.import without consuming any channel data.
		return control.NewError(control.CodeForbiddenByPolicy, "upload denied")
	})

	bigFile := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(bigFile, bytes.Repeat([]byte("X"), 1536<<10), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var outB, errB bytes.Buffer
	code := executeCLI(ctx, []string{"cp", "-S", "tcp://" + ep.Address, bigFile, ":/tmp/"}, nil, &outB, &errB)
	if ctx.Err() != nil {
		t.Fatalf("cp deadlocked on rejected >1 MiB upload (stderr=%q)", errB.String())
	}
	if code != 126 {
		t.Fatalf("cp exit code = %d (stderr=%q), want 126", code, errB.String())
	}
}

func TestPortForwardCancelAndUnixSocketSafety(t *testing.T) {
	dialed := make(chan struct{}, 1)
	ep := startMockCLIServer(t, []string{control.CapNetDial}, func(ctx context.Context, stream *control.Stream, req control.RequestEnvelope) error {
		if err := stream.SendResponse(control.NetDialResponse{RemoteAddr: "127.0.0.1:80"}); err != nil {
			return err
		}
		select {
		case dialed <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	})

	// 1. Refuses to delete an existing regular host file when given unix:<file>:80.
	if runtime.GOOS != "windows" {
		regFile := filepath.Join(t.TempDir(), "important.db")
		if err := os.WriteFile(regFile, []byte("precious"), 0o600); err != nil {
			t.Fatal(err)
		}
		var outB, errB bytes.Buffer
		code := executeCLI(context.Background(), []string{"port-forward", "-S", "tcp://" + ep.Address, "unix:" + regFile + ":80"}, nil, &outB, &errB)
		if code == 0 {
			t.Fatal("port-forward unix: succeeded on existing regular file, want failure")
		}
		got, err := os.ReadFile(regFile)
		if err != nil || string(got) != "precious" {
			t.Fatalf("regular file was damaged/deleted: (%q, %v)", got, err)
		}
	}

	// 2. Canceling port-forward while an idle TCP client is connected must exit promptly.
	localPort := func() int {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		return p
	}()

	pfCtx, pfCancel := context.WithCancel(context.Background())
	pfOut := newSyncNotifyBuffer()
	pfErr := newSyncNotifyBuffer()
	pfDone := make(chan int, 1)
	go func() {
		pfDone <- executeCLI(pfCtx, []string{
			"port-forward", "-S", "tcp://" + ep.Address,
			"127.0.0.1:" + strconv.Itoa(localPort) + ":80",
		}, nil, pfOut, pfErr)
	}()
	t.Cleanup(func() {
		pfCancel()
		select {
		case <-pfDone:
		case <-time.After(3 * time.Second):
		}
	})
	pfOut.waitForSubstring(t, "Forwarding ", 5*time.Second)

	idleConn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(localPort), 3*time.Second)
	if err != nil {
		t.Fatalf("dial port-forward listener: %v", err)
	}
	defer idleConn.Close()
	select {
	case <-dialed:
	case <-time.After(3 * time.Second):
		t.Fatal("port-forward did not establish tunnel stream")
	}

	pfCancel()
	select {
	case <-pfDone:
	case <-time.After(3 * time.Second):
		t.Fatal("port-forward hung on cancel while an idle TCP connection was open")
	}
}

func TestControlCLIFlagValidationAndV1Fallback(t *testing.T) {
	var gotStopTimeout atomic.Int64
	gotStopTimeout.Store(-999)
	var gotCPUQuota atomic.Int64
	gotCPUQuota.Store(-999)

	ep := startMockCLIServer(t, []string{control.CapStop, control.CapResourceMemory, control.CapResourceCPU, control.CapResourceNetwork, control.CapPing}, func(_ context.Context, stream *control.Stream, req control.RequestEnvelope) error {
		switch req.Method {
		case control.MethodStop:
			var p control.StopRequest
			_ = json.Unmarshal(req.Params, &p)
			if p.TimeoutMS != nil {
				gotStopTimeout.Store(*p.TimeoutMS)
			}
			return stream.Reply(control.StopResponse{Signaled: "SIGKILL", Killed: true})
		case control.MethodResourceUpdate:
			var p control.ResourceUpdateRequest
			_ = json.Unmarshal(req.Params, &p)
			if p.CPUQuotaUSec != nil {
				gotCPUQuota.Store(*p.CPUQuotaUSec)
			}
			return stream.Reply(control.ResourceSnapshot{})
		}
		return stream.Reply(control.PingResponse{Version: control.ProtocolVersion, SandboxID: "mock", State: "running"})
	})

	runCLI := func(args ...string) (int, string, string) {
		var outB, errB bytes.Buffer
		c := executeCLI(context.Background(), args, nil, &outB, &errB)
		return c, outB.String(), errB.String()
	}

	// stop -t 0 sends TimeoutMS == 0; -t -1 returns exit 2.
	if code, _, errS := runCLI("stop", "-S", "tcp://"+ep.Address, "-t", "0"); code != 0 || gotStopTimeout.Load() != 0 {
		t.Fatalf("stop -t 0 = (code=%d, timeout=%d, stderr=%q), want (0, 0)", code, gotStopTimeout.Load(), errS)
	}
	if code, _, _ := runCLI("stop", "-S", "tcp://"+ep.Address, "-t", "-1"); code != 2 {
		t.Fatalf("stop -t -1 exit = %d, want 2", code)
	}

	// update --cpu-quota=max sends CPUQuotaUSec == 0.
	if code, _, errS := runCLI("update", "-S", "tcp://"+ep.Address, "--cpu-quota=max"); code != 0 || gotCPUQuota.Load() != 0 {
		t.Fatalf("update --cpu-quota=max = (code=%d, quota=%d, stderr=%q), want (0, 0)", code, gotCPUQuota.Load(), errS)
	}

	if code, _, errS := runCLI("update", "-S", "tcp://"+ep.Address, "--cpu-quota=40000", "--net-tx-bps=0"); code != 1 ||
		!strings.Contains(errS, string(control.CodeUnsupported)) || gotCPUQuota.Load() != 0 {
		t.Fatalf("mixed update against old control server = (code=%d, quota=%d, stderr=%q), want unsupported and no CPU change", code, gotCPUQuota.Load(), errS)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	legacyClient, err := control.Dial(ctx, control.DialOptions{Endpoint: ep.Address, Token: ep.Token})
	if err != nil {
		t.Fatal(err)
	}
	defer legacyClient.Close()
	rawUpdate := json.RawMessage(`{"cpu_quota_usec":45000,"net_rx_bps":0}`)
	if err := legacyClient.Call(ctx, control.MethodResourceUpdate, rawUpdate, nil); !control.IsCode(err, control.CodeUnsupported) || gotCPUQuota.Load() != 0 {
		t.Fatalf("raw mixed update = %v, CPU quota = %d; want unsupported and unchanged CPU quota", err, gotCPUQuota.Load())
	}

	// kill --pid 5 --all and --pid -1 return exit 2.
	if code, _, _ := runCLI("kill", "-S", "tcp://"+ep.Address, "--pid", "5", "--all"); code != 2 {
		t.Fatalf("kill --pid 5 --all exit = %d, want 2", code)
	}
	if code, _, _ := runCLI("kill", "-S", "tcp://"+ep.Address, "--pid", "-1"); code != 2 {
		t.Fatalf("kill --pid -1 exit = %d, want 2", code)
	}

	// dmesg --level 9 and --tail -1 return exit 2.
	if code, _, _ := runCLI("dmesg", "-S", "tcp://"+ep.Address, "--level", "9"); code != 2 {
		t.Fatalf("dmesg --level 9 exit = %d, want 2", code)
	}
	if code, _, _ := runCLI("dmesg", "-S", "tcp://"+ep.Address, "--tail", "-1"); code != 2 {
		t.Fatalf("dmesg --tail -1 exit = %d, want 2", code)
	}

	// checkpoint -z without -o returns exit 2.
	if code, _, _ := runCLI("checkpoint", "-S", "tcp://"+ep.Address, "-z"); code != 2 {
		t.Fatalf("checkpoint -z without -o exit = %d, want 2", code)
	}

	// ping --wait 5s without -S/-n fails immediately (<1s) with exit 2.
	start := time.Now()
	if code, _, _ := runCLI("ping", "--wait", "5s"); code != 2 || time.Since(start) > time.Second {
		t.Fatalf("ping --wait 5s without target = (code=%d, elapsed=%v), want exit 2 immediately", code, time.Since(start))
	}

	// Real legacy v1-only TCP server: checkpoint falls back to v1 cleanly when v2 preface fails.
	v1Ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer v1Ln.Close()
	var v1Hits atomic.Int32
	v1Done := make(chan struct{})
	go func() {
		defer close(v1Done)
		for {
			c, err := v1Ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				var req control.LegacyCheckpointRequest
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					// v2 client wrote "GVX2..." -> fail JSON decode and close so client falls back.
					return
				}
				v1Hits.Add(1)
				_ = json.NewEncoder(conn).Encode(control.LegacyCheckpointResponse{OK: true})
			}(c)
		}
	}()
	t.Cleanup(func() {
		_ = v1Ln.Close()
		<-v1Done
	})

	// Passing a nonexistent --token-file must NOT fall back to v1.
	if code, _, _ := runCLI("checkpoint", "-S", "tcp://"+v1Ln.Addr().String(), "--token-file", filepath.Join(t.TempDir(), "missing.token"), "-checkpoint-dir=ckpt"); code == 0 || v1Hits.Load() != 0 {
		t.Fatalf("checkpoint with missing token-file = (code=%d, v1Hits=%d), want non-zero and 0", code, v1Hits.Load())
	}

	// With explicit token (no local error), v2 handshake fails on wire and falls back to v1.
	if code, _, errS := runCLI("checkpoint", "-S", "tcp://"+v1Ln.Addr().String(), "--token", "tok123", "-checkpoint-dir=ckpt"); code != 0 || v1Hits.Load() != 1 {
		t.Fatalf("checkpoint v1 fallback = (code=%d, v1Hits=%d, stderr=%q), want (0, 1)", code, v1Hits.Load(), errS)
	}
}

func TestCLIUpdateClearsOnlySpecifiedNATRate(t *testing.T) {
	ep := startMockCLIServer(t, []string{control.CapResourceNetwork}, func(_ context.Context, stream *control.Stream, req control.RequestEnvelope) error {
		var params control.ResourceUpdateRequest
		if err := json.Unmarshal(req.Params, &params); err != nil {
			return err
		}
		if params.NetTXBPS == nil || *params.NetTXBPS != 0 || params.NetRXBPS != nil {
			return control.NewErrorf(control.CodeInvalidArgument, "expected explicit TX zero and omitted RX, got %s", req.Params)
		}
		return stream.Reply(control.ResourceSnapshot{NetRXBPS: 10_000})
	}, control.FeatureNetQoS)
	var stdout, stderr bytes.Buffer
	if code := executeCLI(t.Context(), []string{"update", "-S", "tcp://" + ep.Address, "--net-tx-bps=0", "-f", "json"}, nil, &stdout, &stderr); code != 0 {
		t.Fatalf("update TX bandwidth returned %d: %s", code, &stderr)
	}
	var snapshot control.ResourceSnapshot
	if err := json.Unmarshal(stdout.Bytes(), &snapshot); err != nil || snapshot.NetTXBPS != 0 || snapshot.NetRXBPS != 10_000 {
		t.Fatalf("update snapshot = %s (err=%v), want TX 0, RX 10000 bps", &stdout, err)
	}
}

func TestCLIControlSubcommandsEndToEnd(t *testing.T) {
	platform := requireCheckpointCLIPlatform(t)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	helloELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "cli-exec-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64: %v", err)
	}
	exit7ELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 7, "")
	if err != nil {
		t.Fatalf("BuildGuestELF64(7): %v", err)
	}

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/hello", Data: helloELF, Mode: 0o755},
		testimage.File{Name: "bin/exit7", Data: exit7ELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("cli-ready\n"), Mode: 0o644},
		testimage.File{Name: "tmp/", Type: tar.TypeDir, Mode: 0o1777},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/dyn/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/srv/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "clictrl", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	cacheDir := t.TempDir()
	sockPath := filepath.Join(shortSocketDir(t), "cli.sock")
	stdinR, stdinW := net.Pipe()
	t.Cleanup(func() {
		_ = stdinW.Close()
		_ = stdinR.Close()
	})
	stdout := newSyncNotifyBuffer()
	stderr := newSyncNotifyBuffer()

	runCtx, runCancel := context.WithCancel(context.Background())
	runDone := make(chan int, 1)
	go func() {
		runDone <- executeCLI(runCtx, []string{
			"run",
			"-lockdown=false",
			"-platform=" + platform,
			"-net=none",
			"-cache-dir=" + cacheDir,
			"-registry-url=" + regURL,
			"--name=cli-box",
			"-S", sockPath,
			"clictrl:latest",
		}, stdinR, stdout, stderr)
	}()
	var runJoined atomic.Bool
	t.Cleanup(func() {
		_ = stdinW.Close()
		runCancel()
		if !runJoined.Load() {
			select {
			case <-runDone:
			case <-time.After(10 * time.Second):
				t.Errorf("rungv run goroutine did not exit within 10s during cleanup")
			}
		}
	})
	stdout.waitForSubstring(t, "cli-ready\n", 15*time.Second)

	runCmd := func(stdin io.Reader, args ...string) (int, string, string) {
		var outB, errB bytes.Buffer
		c := executeCLI(context.Background(), args, stdin, &outB, &errB)
		return c, outB.String(), errB.String()
	}

	// ping & status & top & stats
	if code, out, errS := runCmd(nil, "ping", "-S", sockPath, "-f", "json"); code != 0 || !strings.Contains(out, `"cli-box"`) {
		t.Fatalf("ping = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(nil, "status", "-S", sockPath, "-f", "json"); code != 0 || !strings.Contains(out, `"running"`) {
		t.Fatalf("status = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(nil, "top", "-S", sockPath, "-f", "json"); code != 0 || !strings.Contains(out, `"pid":1`) {
		t.Fatalf("top = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(nil, "stats", "-S", sockPath, "--no-stream", "-f", "json"); code != 0 || !strings.Contains(out, `"pids"`) {
		t.Fatalf("stats = (%d, %q, %q)", code, out, errS)
	}

	// pause & unpause
	if code, _, errS := runCmd(nil, "pause", "-S", sockPath); code != 0 {
		t.Fatalf("pause = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "unpause", "-S", sockPath); code != 0 {
		t.Fatalf("unpause = (%d, %q)", code, errS)
	}

	// exec (stdout, closed stdin, -i piped stdin, -t -i PTY, --pid-file, exit code)
	if code, out, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/hello"); code != 0 || out != "cli-exec-ok\n" {
		t.Fatalf("exec hello = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(strings.NewReader("from-host\n"), "exec", "-S", sockPath, "-i", "--", "/bin/cat", "/proc/self/fd/0"); code != 0 || out != "from-host\n" {
		t.Fatalf("exec -i = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(strings.NewReader("tty-line\r"), "exec", "-S", sockPath, "-t", "-i", "--", "/bin/cat", "/proc/self/fd/0"); code != 0 || !strings.Contains(out, "tty-line\r\n") {
		t.Fatalf("exec -t -i = (%d, %q, %q)", code, out, errS)
	}
	pidFile := filepath.Join(t.TempDir(), "exec.pid")
	if code, out, errS := runCmd(nil, "exec", "-S", sockPath, "--pid-file", pidFile, "--", "/bin/hello"); code != 0 || out != "cli-exec-ok\n" {
		t.Fatalf("exec --pid-file = (%d, %q, %q)", code, out, errS)
	}
	if pidBytes, err := os.ReadFile(pidFile); err != nil {
		t.Fatalf("read --pid-file: %v", err)
	} else if pidVal, err := strconv.Atoi(strings.TrimSpace(string(pidBytes))); err != nil || pidVal <= 1 {
		t.Fatalf("--pid-file content = %q (err=%v), want guest PID > 1", pidBytes, err)
	}
	if code, _, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/exit7"); code != 7 {
		t.Fatalf("exec exit7 = (%d, %q), want 7", code, errS)
	}

	// Blocking exec -i with --pid-file + kill --pid <PID> leaves PID 1 alive.
	{
		bgInR, bgInW := io.Pipe()
		bgPidFile := filepath.Join(t.TempDir(), "bg.pid")
		bgDone := make(chan int, 1)
		var bgOut, bgErr bytes.Buffer
		go func() {
			bgDone <- executeCLI(context.Background(), []string{
				"exec", "-S", sockPath, "-i", "--pid-file", bgPidFile, "--", "/bin/cat", "/proc/self/fd/0",
			}, bgInR, &bgOut, &bgErr)
		}()
		var bgJoined atomic.Bool
		t.Cleanup(func() {
			_ = bgInW.Close()
			_ = bgInR.Close()
			if !bgJoined.Load() {
				select {
				case <-bgDone:
				case <-time.After(5 * time.Second):
				}
			}
		})
		var bgPID string
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if raw, err := os.ReadFile(bgPidFile); err == nil && strings.Contains(string(raw), "\n") {
				bgPID = strings.TrimSpace(string(raw))
				break
			}
			time.Sleep(15 * time.Millisecond)
		}
		if bgPID == "" {
			t.Fatal("blocking exec -i did not write --pid-file within 5s")
		}
		if kCode, _, kErr := runCmd(nil, "kill", "-S", sockPath, "--pid", bgPID, "-s", "SIGTERM"); kCode != 0 {
			t.Fatalf("kill --pid %s = (%d, %q)", bgPID, kCode, kErr)
		}
		select {
		case exitC := <-bgDone:
			bgJoined.Store(true)
			if exitC != 143 {
				t.Fatalf("killed exec -i exit code = %d (stderr=%q), want 143", exitC, bgErr.String())
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("blocking exec -i (pid %s) did not exit after kill --pid SIGTERM", bgPID)
		}
		_ = bgInW.Close()
		_ = bgInR.Close()
		if pCode, pOut, pErr := runCmd(nil, "ping", "-S", sockPath); pCode != 0 || !strings.Contains(pOut, "state=running") {
			t.Fatalf("ping after kill --pid = (%d, %q, %q)", pCode, pOut, pErr)
		}
	}

	// dmesg --tail & --clear
	if code, _, errS := runCmd(nil, "dmesg", "-S", sockPath, "--tail", "5"); code != 0 {
		t.Fatalf("dmesg --tail 5 = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "dmesg", "-S", sockPath, "--clear"); code != 0 {
		t.Fatalf("dmesg --clear = (%d, %q)", code, errS)
	}
	if code, out, errS := runCmd(nil, "dmesg", "-S", sockPath); code != 0 || strings.TrimSpace(out) != "" {
		t.Fatalf("dmesg after clear = (%d, %q, %q), want empty", code, out, errS)
	}

	// events --filter with multiple same-key types (OR semantics) in JSON format.
	{
		evCtx, evCancel := context.WithCancel(context.Background())
		evOut := newSyncNotifyBuffer()
		evErr := newSyncNotifyBuffer()
		evDone := make(chan int, 1)
		go func() {
			evDone <- executeCLI(evCtx, []string{
				"events", "-S", sockPath,
				"--filter", "type=resource",
				"--filter", "type=lifecycle",
				"-f", "json",
			}, nil, evOut, evErr)
		}()
		var evJoined atomic.Bool
		t.Cleanup(func() {
			evCancel()
			if !evJoined.Load() {
				select {
				case <-evDone:
				case <-time.After(3 * time.Second):
				}
			}
		})
		// Synchronize deterministically on subscription using per-sandbox resource.update.
		subscribed := false
		subDeadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(subDeadline) {
			if code, _, errS := runCmd(nil, "update", "-S", sockPath, "--pids-limit", "64"); code != 0 {
				t.Fatalf("update --pids-limit 64 = (%d, %q)", code, errS)
			}
			if strings.Contains(evOut.String(), `"action":"update"`) {
				subscribed = true
				break
			}
			time.Sleep(25 * time.Millisecond)
		}
		if !subscribed {
			t.Fatalf("events CLI did not receive resource event within 5s (out=%q err=%q)", evOut.String(), evErr.String())
		}
		if code, _, errS := runCmd(nil, "pause", "-S", sockPath); code != 0 {
			t.Fatalf("pause for cli events = (%d, %q)", code, errS)
		}
		if code, _, errS := runCmd(nil, "unpause", "-S", sockPath); code != 0 {
			t.Fatalf("unpause for cli events = (%d, %q)", code, errS)
		}
		evOut.waitForSubstring(t, `"action":"unpause"`, 5*time.Second)
		evCancel()
		<-evDone
		evJoined.Store(true)
	}

	// cp roundtrips between host and guest (regular, '-' tar pipe, ./dir/., -L symlink following, and :/ root).
	srcFile := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(srcFile, []byte("hello-cp-roundtrip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errS := runCmd(nil, "cp", "-S", sockPath, "-z", srcFile, ":/tmp/in.txt"); code != 0 {
		t.Fatalf("cp host to guest = (%d, %q)", code, errS)
	}
	dstFile := filepath.Join(t.TempDir(), "out.txt")
	if code, _, errS := runCmd(nil, "cp", "-S", sockPath, "-z", ":/tmp/in.txt", dstFile); code != 0 {
		t.Fatalf("cp guest to host = (%d, %q)", code, errS)
	}
	gotCP, err := os.ReadFile(dstFile)
	if err != nil || string(gotCP) != "hello-cp-roundtrip\n" {
		t.Fatalf("cp roundtrip content = (%q, %v)", gotCP, err)
	}

	// cp :/ full root export into a non-existing host dir before creating guest symlinks
	// so unprivileged Windows hosts do not hit CreateSymbolicLinkW privilege errors.
	{
		rootDst := filepath.Join(t.TempDir(), "rootcopy")
		if code, _, errS := runCmd(nil, "cp", "-S", sockPath, ":/", rootDst); code != 0 {
			t.Fatalf("cp :/ = (%d, %q)", code, errS)
		}
		if got, err := os.ReadFile(filepath.Join(rootDst, "etc", "ready.txt")); err != nil || string(got) != "cli-ready\n" {
			t.Fatalf("cp :/ etc/ready.txt = (%q, %v), want cli-ready", got, err)
		}
	}

	// cp '-' stdin tar pipe into :/tmp and :/tmp/piped.txt into '-' stdout tar pipe.
	{
		var inTar bytes.Buffer
		tw := tar.NewWriter(&inTar)
		payload := []byte("piped-tar-body\n")
		_ = tw.WriteHeader(&tar.Header{Name: "piped.txt", Mode: 0o644, Size: int64(len(payload))})
		_, _ = tw.Write(payload)
		_ = tw.WriteHeader(&tar.Header{Name: "glink.txt", Typeflag: tar.TypeSymlink, Linkname: "piped.txt"})
		_ = tw.Close()
		if code, _, errS := runCmd(&inTar, "cp", "-S", sockPath, "-", ":/tmp"); code != 0 {
			t.Fatalf("cp stdin pipe = (%d, %q)", code, errS)
		}
		var outTar bytes.Buffer
		var errB bytes.Buffer
		if code := executeCLI(context.Background(), []string{"cp", "-S", sockPath, ":/tmp/piped.txt", "-"}, nil, &outTar, &errB); code != 0 {
			t.Fatalf("cp stdout pipe = (%d, %q)", code, errB.String())
		}
		tr := tar.NewReader(&outTar)
		hdr, err := tr.Next()
		body, rErr := io.ReadAll(tr)
		if err != nil || rErr != nil || hdr.Name != "piped.txt" || string(body) != string(payload) {
			t.Fatalf("cp stdout tar = (%+v, %q, %v, %v)", hdr, body, err, rErr)
		}
		// cp -L from guest symlink follows link to regular file content on all OSes.
		followOut := filepath.Join(t.TempDir(), "followed.txt")
		if code, _, errS := runCmd(nil, "cp", "-S", sockPath, "-L", ":/tmp/glink.txt", followOut); code != 0 {
			t.Fatalf("cp -L guest to host = (%d, %q)", code, errS)
		}
		if got, err := os.ReadFile(followOut); err != nil || string(got) != string(payload) {
			t.Fatalf("cp -L guest symlink content = (%q, %v), want %q", got, err, payload)
		}
	}

	// cp ./dir/. contents-only into non-existing guest dir, plus host -L symlink + cycle on Unix.
	{
		srcDir := filepath.Join(t.TempDir(), "srcdir")
		if err := os.MkdirAll(filepath.Join(srcDir, "sub"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(srcDir, "sub", "item.txt"), []byte("dot-item\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, _, errS := runCmd(nil, "cp", "-S", sockPath, srcDir+string(os.PathSeparator)+".", ":/tmp/dotdest"); code != 0 {
			t.Fatalf("cp ./dir/. = (%d, %q)", code, errS)
		}
		if code, out, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/cat", "/tmp/dotdest/sub/item.txt"); code != 0 || out != "dot-item\n" {
			t.Fatalf("exec cat /tmp/dotdest/sub/item.txt = (%d, %q, %q)", code, out, errS)
		}
		if runtime.GOOS != "windows" {
			symSrc := filepath.Join(t.TempDir(), "symsrc")
			if err := os.MkdirAll(symSrc, 0o755); err != nil {
				t.Fatal(err)
			}
			extFile := filepath.Join(t.TempDir(), "ext.txt")
			if err := os.WriteFile(extFile, []byte("followed-host\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(extFile, filepath.Join(symSrc, "link.txt")); err != nil {
				t.Fatal(err)
			}
			// Self-referential directory symlink must terminate cleanly under -L.
			if err := os.Symlink(symSrc, filepath.Join(symSrc, "loop")); err != nil {
				t.Fatal(err)
			}
			if code, _, errS := runCmd(nil, "cp", "-S", sockPath, "-L", symSrc, ":/tmp/symdest"); code != 0 {
				t.Fatalf("cp -L host to guest = (%d, %q)", code, errS)
			}
			if code, out, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/cat", "/tmp/symdest/link.txt"); code != 0 || out != "followed-host\n" {
				t.Fatalf("exec cat /tmp/symdest/link.txt = (%d, %q, %q)", code, out, errS)
			}
		}
	}

	// export CLI (-z -o file and --upper-only -o -)
	{
		expFile := filepath.Join(t.TempDir(), "export.tar")
		if code, _, errS := runCmd(nil, "export", "-S", sockPath, "-z", "-o", expFile, "/tmp/in.txt"); code != 0 {
			t.Fatalf("export -z -o = (%d, %q)", code, errS)
		}
		f, err := os.Open(expFile)
		if err != nil {
			t.Fatalf("open export.tar: %v", err)
		}
		tr := tar.NewReader(f)
		hdr, hErr := tr.Next()
		_ = f.Close()
		if hErr != nil || hdr.Name != "in.txt" {
			t.Fatalf("export.tar header = (%+v, %v), want in.txt", hdr, hErr)
		}

		var upBuf, upErr bytes.Buffer
		if code := executeCLI(context.Background(), []string{"export", "-S", sockPath, "--upper-only", "-o", "-"}, nil, &upBuf, &upErr); code != 0 {
			t.Fatalf("export --upper-only -o - = (%d, %q)", code, upErr.String())
		}
		upTR := tar.NewReader(&upBuf)
		var sawIn, sawLower bool
		for {
			h, err := upTR.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("export --upper-only tar read: %v", err)
			}
			if strings.HasSuffix(h.Name, "in.txt") {
				sawIn = true
			}
			if strings.HasSuffix(h.Name, "ready.txt") {
				sawLower = true
			}
		}
		if !sawIn || sawLower {
			t.Fatalf("export --upper-only: sawIn=%v sawLower=%v, want true/false", sawIn, sawLower)
		}
	}

	// update live limits (and --cpu-quota=max reset)
	if code, out, errS := runCmd(nil, "update", "-S", sockPath, "-m", "300m", "--cpus", "0.5", "--pids-limit", "40", "-f", "json"); code != 0 {
		t.Fatalf("update = (%d, %q, %q)", code, out, errS)
	} else {
		var snap control.ResourceSnapshot
		if err := json.Unmarshal([]byte(out), &snap); err != nil || snap.PidsLimit != 40 || snap.CPUQuotaUSec != 50000 {
			t.Fatalf("update snap = (%+v, %v)", snap, err)
		}
	}
	if code, out, errS := runCmd(nil, "update", "-S", sockPath, "--cpu-quota=max", "-f", "json"); code != 0 {
		t.Fatalf("update --cpu-quota=max = (%d, %q, %q)", code, out, errS)
	} else {
		var snap control.ResourceSnapshot
		if err := json.Unmarshal([]byte(out), &snap); err != nil || snap.CPUQuotaUSec != 0 {
			t.Fatalf("update --cpu-quota=max snap = (%+v, %v)", snap, err)
		}
	}
	if code, _, errS := runCmd(nil, "update", "-S", sockPath, "--net-rx-bps=0"); code != 1 || !strings.Contains(errS, string(control.CodeUnsupported)) {
		t.Fatalf("clear bandwidth in non-NAT mode = (%d, %q), want UNSUPPORTED", code, errS)
	}

	// mount add tmpfs (small size < 6m allowed!) -> remount ro -> rw -> rm
	if code, _, errS := runCmd(nil, "mount", "add", "-S", sockPath, "--type", "tmpfs", "--dst", "/mnt/dyn", "--size", "1m"); code != 0 {
		t.Fatalf("mount add 1m = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "mount", "remount", "-S", sockPath, "--ro", "/mnt/dyn"); code != 0 {
		t.Fatalf("mount remount ro = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "mount", "remount", "-S", sockPath, "--rw", "/mnt/dyn"); code != 0 {
		t.Fatalf("mount remount rw = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "mount", "rm", "-S", sockPath, "/mnt/dyn"); code != 0 {
		t.Fatalf("mount rm = (%d, %q)", code, errS)
	}

	// mount serve host dir -> read inside guest via exec
	serveHostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serveHostDir, "msg.txt"), []byte("served-by-cli\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveOut := newSyncNotifyBuffer()
	serveErr := newSyncNotifyBuffer()
	serveDone := make(chan int, 1)
	go func() {
		serveDone <- executeCLI(serveCtx, []string{"mount", "serve", "-S", sockPath, serveHostDir + ":/mnt/srv"}, nil, serveOut, serveErr)
	}()
	var serveJoined atomic.Bool
	t.Cleanup(func() {
		serveCancel()
		if !serveJoined.Load() {
			select {
			case <-serveDone:
			case <-time.After(5 * time.Second):
				t.Errorf("mount serve goroutine did not exit within 5s during cleanup")
			}
		}
	})
	serveOut.waitForSubstring(t, "Serving ", 10*time.Second)

	if code, out, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/srv/msg.txt"); code != 0 || out != "served-by-cli\n" {
		t.Fatalf("exec read served mount = (%d, %q, %q)", code, out, errS)
	}
	serveCancel()
	<-serveDone
	serveJoined.Store(true)

	// Wait for the server to finish auto-unmounting /mnt/srv after client disconnect.
	unmounted := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if code, out, _ := runCmd(nil, "mount", "ls", "-S", sockPath, "-q"); code == 0 && !strings.Contains(out, "/mnt/srv") {
			unmounted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !unmounted {
		t.Fatal("/mnt/srv was not unmounted within 5s after mount serve stopped")
	}

	// checkpoint -o streaming bundle (no -checkpoint-dir on run!) -> stop sandbox -> restore
	ckptOutDir := filepath.Join(t.TempDir(), "streamed-bundle")
	if code, _, errS := runCmd(nil, "checkpoint", "-S", sockPath, "-z", "-o", ckptOutDir); code != 0 {
		t.Fatalf("checkpoint -o = (%d, %q)", code, errS)
	}
	exitCode := <-runDone
	runJoined.Store(true)
	if exitCode != 0 {
		t.Fatalf("run exited with %d (stderr=%q)", exitCode, stderr.String())
	}

	var resOut, resErr bytes.Buffer
	resCode := executeCLI(context.Background(), []string{
		"restore",
		"-lockdown=false",
		"-platform=" + platform,
		"-net=none",
		"-cache-dir=" + cacheDir,
		"-registry-url=" + regURL,
		"-checkpoint-dir=" + ckptOutDir,
	}, strings.NewReader("resumed-from-stream\n"), &resOut, &resErr)
	if resCode != 0 || resOut.String() != "resumed-from-stream\n" {
		t.Fatalf("restore from streamed checkpoint = (code=%d out=%q err=%q)", resCode, resOut.String(), resErr.String())
	}
}

func TestUnixForwardHelperOverflowAndFastEOFExit(t *testing.T) {
	c2hR, c2hW := io.Pipe()
	h2cR, h2cW := io.Pipe()
	helperDone := make(chan int, 1)
	go func() {
		helperDone <- runUnixForwardHelper(context.Background(), []string{"/tmp/nonexistent.sock"}, c2hR, h2cW)
	}()

	pc := &pipeConn{r: h2cR, w: c2hW}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client, err := control.DialConn(ctx, pc, control.DialOptions{
		ClientName:       "test-helper-client",
		HandshakeTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("DialConn helper: %v", err)
	}

	// ConnID = ^uint64(0) must return INVALID_ARGUMENT without panicking.
	st, err := client.OpenStream(ctx, control.MethodUnixAccept, control.UnixAcceptRequest{ConnID: ^uint64(0)})
	if err != nil {
		t.Fatalf("OpenStream overflow conn_id: %v", err)
	}
	err = st.WaitResponse(ctx, nil)
	st.Close()
	var pe *control.ProtoError
	if !errors.As(err, &pe) || pe.Code != control.CodeInvalidArgument {
		t.Fatalf("overflow conn_id err = %v, want INVALID_ARGUMENT", err)
	}

	// Closing the client pipe must make runUnixForwardHelper exit promptly.
	start := time.Now()
	_ = client.Close()
	_ = pc.Close()
	select {
	case code := <-helperDone:
		if code != 0 {
			t.Fatalf("helper exit code = %d, want 0", code)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("helper took %v to exit after pipe EOF, want <500ms", elapsed)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runUnixForwardHelper hung after pipe EOF")
	}
}
