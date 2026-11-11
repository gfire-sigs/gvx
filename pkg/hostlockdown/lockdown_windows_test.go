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

//go:build windows

package hostlockdown

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	childModeEnv   = "GVX_HOSTLOCKDOWN_CHILD_MODE"
	childWSEnv     = "GVX_HOSTLOCKDOWN_WORKSPACE"
	childOutEnv    = "GVX_HOSTLOCKDOWN_OUTSIDE"
	childROEnv     = "GVX_HOSTLOCKDOWN_READONLY"
	childFileEnv   = "GVX_HOSTLOCKDOWN_FILE"
	childDialEnv   = "GVX_HOSTLOCKDOWN_DIAL"
	childResultEnv = "GVX_HOSTLOCKDOWN_RESULT"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(childModeEnv); mode != "" {
		// Open the result file before the lockdown, because the lockdown can
		// refuse a write to the pipes of the parent.
		var result *os.File
		if path := os.Getenv(childResultEnv); path != "" {
			result, _ = os.Create(path)
		}
		if err := runLockedChild(mode); err != nil {
			msg := fmt.Sprintf("child %s: %v\n", mode, err)
			if result != nil {
				_, _ = result.WriteString(msg)
				_ = result.Sync()
			}
			fmt.Fprint(os.Stderr, msg)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func mustSID(t *testing.T, s string) *windows.SID {
	t.Helper()
	sid, err := windows.StringToSid(s)
	if err != nil {
		t.Fatalf("StringToSid(%q): %v", s, err)
	}
	return sid
}

func TestFindLogonSID(t *testing.T) {
	logon := mustSID(t, "S-1-5-5-0-123456")
	users := mustSID(t, "S-1-5-32-545")
	got, err := findLogonSID([]windows.SIDAndAttributes{
		{Sid: users, Attributes: windows.SE_GROUP_ENABLED},
		{Sid: logon, Attributes: windows.SE_GROUP_LOGON_ID | windows.SE_GROUP_ENABLED | windows.SE_GROUP_MANDATORY},
	})
	if err != nil || !got.Equals(logon) {
		t.Fatalf("findLogonSID = %v, %v; want %v", got, err, logon)
	}
	if _, err := findLogonSID([]windows.SIDAndAttributes{{Sid: users, Attributes: windows.SE_GROUP_ENABLED}}); err == nil {
		t.Fatal("findLogonSID without a logon group = nil error, want error")
	}
}

func TestDenyOnlySIDs(t *testing.T) {
	user := mustSID(t, "S-1-5-21-1-2-3-1001")
	everyone := mustSID(t, "S-1-1-0")
	admins := mustSID(t, "S-1-5-32-544")
	logon := mustSID(t, "S-1-5-5-0-123456")
	integrity := mustSID(t, "S-1-16-8192")
	alreadyDeny := mustSID(t, "S-1-5-32-559")
	disabled := mustSID(t, "S-1-5-32-545")

	groups := []windows.SIDAndAttributes{
		{Sid: everyone, Attributes: windows.SE_GROUP_ENABLED | windows.SE_GROUP_MANDATORY},
		{Sid: logon, Attributes: windows.SE_GROUP_LOGON_ID | windows.SE_GROUP_ENABLED | windows.SE_GROUP_MANDATORY},
		{Sid: integrity, Attributes: windows.SE_GROUP_INTEGRITY | windows.SE_GROUP_INTEGRITY_ENABLED},
		{Sid: alreadyDeny, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY},
		{Sid: disabled, Attributes: 0},
		{Sid: admins, Attributes: windows.SE_GROUP_ENABLED | windows.SE_GROUP_OWNER},
	}
	got := denyOnlySIDs(user, groups)
	want := []*windows.SID{user, everyone, admins}
	if len(got) != len(want) {
		t.Fatalf("denyOnlySIDs returned %d entries, want %d", len(got), len(want))
	}
	for i, sid := range want {
		if !got[i].Sid.Equals(sid) {
			t.Errorf("entry %d = %v, want %v", i, got[i].Sid, sid)
		}
		if got[i].Attributes != windows.SE_GROUP_USE_FOR_DENY_ONLY {
			t.Errorf("entry %d attributes = %#x, want SE_GROUP_USE_FOR_DENY_ONLY", i, got[i].Attributes)
		}
	}

	netBrokerDeny := buildDenyOnlySIDs(user, groups, true)
	wantNet := []*windows.SID{user, admins}
	if len(netBrokerDeny) != len(wantNet) {
		t.Fatalf("buildDenyOnlySIDs(keepEveryone=true) returned %d entries, want %d", len(netBrokerDeny), len(wantNet))
	}
	for i, sid := range wantNet {
		if !netBrokerDeny[i].Sid.Equals(sid) {
			t.Errorf("netBrokerDeny[%d] = %v, want %v", i, netBrokerDeny[i].Sid, sid)
		}
	}
}

func TestIsLowIntegritySID(t *testing.T) {
	tests := []struct {
		sid  string
		want bool
	}{
		{"S-1-16-4096", true},
		{"S-1-16-8192", false},
		{"S-1-16-0", false},
		{"S-1-5-32-544", false},
		{"S-1-5-5-0-4096", false},
	}
	for _, tt := range tests {
		if got := isLowIntegritySID(mustSID(t, tt.sid)); got != tt.want {
			t.Errorf("isLowIntegritySID(%s) = %v, want %v", tt.sid, got, tt.want)
		}
	}
	if isLowIntegritySID(nil) {
		t.Error("isLowIntegritySID(nil) = true")
	}
}

func TestIsUntrustedIntegritySID(t *testing.T) {
	tests := []struct {
		sid  string
		want bool
	}{
		{"S-1-16-0", true},
		{"S-1-16-4096", false},
		{"S-1-16-8192", false},
		{"S-1-5-32-544", false},
		{"S-1-5-5-0-0", false},
	}
	for _, tt := range tests {
		if got := isUntrustedIntegritySID(mustSID(t, tt.sid)); got != tt.want {
			t.Errorf("isUntrustedIntegritySID(%s) = %v, want %v", tt.sid, got, tt.want)
		}
	}
	if isUntrustedIntegritySID(nil) {
		t.Error("isUntrustedIntegritySID(nil) = true")
	}
}

func TestBrokerParameterAllowlists(t *testing.T) {
	const (
		fileOpenByFileID  = 0x2000
		fileDeleteOnClose = 0x1000
	)
	for _, tc := range []struct {
		name        string
		access      uint32
		fileAttrs   uint32
		disposition uint32
		options     uint32
		wantErr     bool
	}{
		{"valid regular read", windows.FILE_GENERIC_READ, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE, false},
		{"valid dir open", windows.FILE_LIST_DIRECTORY, 0, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE, false},
		{"valid create readonly", windows.FILE_GENERIC_WRITE, windows.FILE_ATTRIBUTE_READONLY, windows.FILE_CREATE, windows.FILE_NON_DIRECTORY_FILE, false},
		{"reject FILE_OPEN_BY_FILE_ID", windows.FILE_GENERIC_READ, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, fileOpenByFileID, true},
		{"reject FILE_DELETE_ON_CLOSE", windows.FILE_GENERIC_READ, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, fileDeleteOnClose, true},
		{"reject conflicting dir and nondir", windows.FILE_GENERIC_READ, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE | windows.FILE_NON_DIRECTORY_FILE, true},
		{"reject system attribute", windows.FILE_GENERIC_WRITE, windows.FILE_ATTRIBUTE_SYSTEM, windows.FILE_OPEN_IF, windows.FILE_NON_DIRECTORY_FILE, true},
		{"reject FILE_SUPERSEDE", windows.FILE_GENERIC_WRITE, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SUPERSEDE, windows.FILE_NON_DIRECTORY_FILE, true},
		{"reject WRITE_DAC", windows.WRITE_DAC, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateBrokerOpenParams(tc.access, tc.fileAttrs, tc.disposition, tc.options)
			if tc.wantErr && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("validateBrokerOpenParams = %v, want ERROR_ACCESS_DENIED", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateBrokerOpenParams = %v, want nil", err)
			}
		})
	}

	for _, tc := range []struct {
		name      string
		access    uint32
		flags     uint32
		infoClass uint32
		wantErr   bool
	}{
		{"valid posix rename", windows.DELETE | windows.FILE_READ_ATTRIBUTES, windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS, fileRenameInformationExClass, false},
		{"valid hard link", windows.FILE_WRITE_ATTRIBUTES, 0, fileLinkInformationClass, false},
		{"reject zero access", 0, 0, fileLinkInformationClass, true},
		{"reject data write access", windows.FILE_WRITE_DATA, 0, fileLinkInformationClass, true},
		{"reject nonzero link flags", windows.FILE_WRITE_ATTRIBUTES, windows.FILE_RENAME_REPLACE_IF_EXISTS, fileLinkInformationClass, true},
		{"reject unknown rename flag", windows.DELETE | windows.FILE_READ_ATTRIBUTES, 0x80, fileRenameInformationExClass, true},
		{"reject unknown info class", windows.DELETE, 0, 99, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateBrokerTargetParams(tc.access, tc.flags, tc.infoClass)
			if tc.wantErr && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("validateBrokerTargetParams = %v, want ERROR_ACCESS_DENIED", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("validateBrokerTargetParams = %v, want nil", err)
			}
		})
	}
}

func TestValidateBrokerName(t *testing.T) {
	valid := []string{"file.txt", ".gvx_meta", "~gvx~tmp.1", "COM10", "normal-dir_2"}
	for _, name := range valid {
		if err := validateBrokerName(name); err != nil {
			t.Errorf("validateBrokerName(%q) = %v, want nil", name, err)
		}
	}
	invalid := []string{
		"",
		".",
		"..",
		`sub\file`,
		"sub/file",
		"file:ads",
		"bad\x00name",
		"bad\x1fname",
		"trailing.",
		"trailing ",
		"CON",
		"nul.txt",
		"Aux .log",
		"COM1",
		"LPT\u00b9",
		"CONIN$",
	}
	for _, name := range invalid {
		if err := validateBrokerName(name); err == nil {
			t.Errorf("validateBrokerName(%q) = nil, want error", name)
		}
	}
}

func TestNTPathAtOrBelow(t *testing.T) {
	root := `\Device\HarddiskVolume3\Users\alice\ws`
	cases := []struct {
		path string
		want bool
	}{
		{`\Device\HarddiskVolume3\Users\alice\ws`, true},
		{`\Device\HarddiskVolume3\Users\alice\ws\`, true},
		{`\Device\HarddiskVolume3\Users\alice\ws\sub\file.txt`, true},
		{`\device\harddiskvolume3\users\ALICE\WS\sub`, true},
		{`\Device\HarddiskVolume3\Users\alice\ws2`, false},
		{`\Device\HarddiskVolume3\Users\alice`, false},
		{"", false},
	}
	for _, tc := range cases {
		if got := ntPathAtOrBelow(tc.path, root); got != tc.want {
			t.Errorf("ntPathAtOrBelow(%q, %q) = %v, want %v", tc.path, root, got, tc.want)
		}
	}
}

// TestMitigationPolicyOrdinal pins the winnt.h PROCESS_MITIGATION_POLICY order:
// DEP 0, ASLR 1, DynamicCode 2, StrictHandleCheck 3, SystemCallDisable 4.
func TestMitigationPolicyOrdinal(t *testing.T) {
	if processSystemCallDisablePolicy != 4 {
		t.Fatalf("processSystemCallDisablePolicy = %d, want 4", processSystemCallDisablePolicy)
	}
}

func TestBindThreadBeforeApply(t *testing.T) {
	if IsLockedDown() {
		t.Skip("process is locked down")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := BindThread(); !errors.Is(err, ErrNotLockedDown) {
		t.Fatalf("BindThread before Apply = %v, want ErrNotLockedDown", err)
	}
}

func readPathSDDL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%q): %v", path, err)
	}
	return sd.String()
}

func openPreLockdownDir(path string) (windows.Handle, func(), error) {
	utf16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, nil, err
	}
	h, err := windows.CreateFile(
		utf16,
		windows.FILE_TRAVERSE|windows.FILE_READ_ATTRIBUTES,
		brokerShareAll,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return 0, nil, err
	}
	return h, func() { _ = windows.CloseHandle(h) }, nil
}

func brokerWriteFile(b WindowsFileBroker, dir windows.Handle, name, data string) error {
	h, err := b.OpenAt(
		dir,
		name,
		windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE,
	)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(h), name)
	_, werr := f.WriteString(data)
	cerr := f.Close()
	return errors.Join(werr, cerr)
}

func brokerReadFile(b WindowsFileBroker, dir windows.Handle, name string) (string, error) {
	h, err := b.OpenAt(
		dir,
		name,
		windows.FILE_GENERIC_READ,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_OPEN,
		windows.FILE_NON_DIRECTORY_FILE,
	)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(h), name)
	buf := make([]byte, 256)
	n, rerr := f.Read(buf)
	_ = f.Close()
	if rerr != nil {
		return "", rerr
	}
	return string(buf[:n]), nil
}

func TestApplyLockdownWindows(t *testing.T) {
	ws, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	outside, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("host-secret"), 0o600); err != nil {
		t.Fatalf("WriteFile secret: %v", err)
	}
	result := filepath.Join(t.TempDir(), "result.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childModeEnv+"=files", childWSEnv+"="+ws, childOutEnv+"="+outside, childResultEnv+"="+result)
	if out, err := cmd.CombinedOutput(); err != nil {
		reported, _ := os.ReadFile(result)
		t.Fatalf("lockdown child failed: %v\n%s\nreported: %s", err, out, reported)
	}
}

// TestApplyPreservesHostSecurityDescriptors proves that Apply mutates neither
// the DACL nor the mandatory integrity label on workspace directories, nested
// subdirectories, read-only mounts, single-file mounts, siblings, or parents.
func TestApplyPreservesHostSecurityDescriptors(t *testing.T) {
	evalTemp := func() string {
		p, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		return p
	}
	ws, ro, fileDir := evalTemp(), evalTemp(), evalTemp()
	subDir := filepath.Join(ws, "sub")
	if err := os.MkdirAll(subDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	subFile := filepath.Join(subDir, "item.txt")
	roFile := filepath.Join(ro, "existing.txt")
	targetFile := filepath.Join(fileDir, "target.txt")
	siblingFile := filepath.Join(fileDir, "sibling.txt")
	for path, body := range map[string]string{
		subFile:     "sub-item",
		roFile:      "ro-item",
		targetFile:  "target-item",
		siblingFile: "sibling-item",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatalf("WriteFile(%q): %v", path, err)
		}
	}

	watchedPaths := []string{ws, subDir, subFile, ro, roFile, fileDir, targetFile, siblingFile}
	before := make(map[string]string, len(watchedPaths))
	for _, p := range watchedPaths {
		before[p] = readPathSDDL(t, p)
	}

	result := filepath.Join(t.TempDir(), "result.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(
		os.Environ(),
		childModeEnv+"=preserve-acl",
		childWSEnv+"="+ws,
		childROEnv+"="+ro,
		childFileEnv+"="+targetFile,
		childResultEnv+"="+result,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		reported, _ := os.ReadFile(result)
		t.Fatalf("preserve-acl child failed: %v\n%s\nreported: %s", err, out, reported)
	}

	for _, p := range watchedPaths {
		after := readPathSDDL(t, p)
		if after != before[p] {
			t.Errorf("security descriptor mutated on %q:\nbefore: %s\nafter:  %s", p, before[p], after)
		}
	}
}

// TestCrossSandboxLogonIsolationAndManyThreads proves:
//  1. A sandbox with AllowOutboundNet=true still blocks Everyone-readable host
//     files on both pre-warmed and newly spawned Go runtime OS threads (#129+),
//     while outbound dials through DialContext succeed.
//  2. A second locked-down sandbox in the same Windows logon session cannot open
//     or modify files inside the first sandbox's workspace.
func TestCrossSandboxLogonIsolationAndManyThreads(t *testing.T) {
	evalTemp := func() string {
		p, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		return p
	}
	wsA, outside := evalTemp(), evalTemp()
	everyoneFile := filepath.Join(outside, "everyone.txt")
	if err := os.WriteFile(everyoneFile, []byte("world-readable-secret"), 0o644); err != nil {
		t.Fatalf("WriteFile everyone: %v", err)
	}
	// Grant Everyone (WD) explicit read access so any token with Everyone
	// enabled in RestrictedSids would read the file.
	sd, err := windows.SecurityDescriptorFromString("D:(A;;FA;;;BA)(A;;FA;;;SY)(A;;FR;;;WD)")
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("sd.DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		everyoneFile,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(everyoneFile): %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen loopback: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = c.Close()
		}
	}()

	resA := filepath.Join(t.TempDir(), "resA.txt")
	cmdA := exec.Command(os.Args[0], "-test.run=^$")
	cmdA.Env = append(
		os.Environ(),
		childModeEnv+"=sandbox-a",
		childWSEnv+"="+wsA,
		childOutEnv+"="+everyoneFile,
		childDialEnv+"="+ln.Addr().String(),
		childResultEnv+"="+resA,
	)
	if out, err := cmdA.CombinedOutput(); err != nil {
		reported, _ := os.ReadFile(resA)
		t.Fatalf("sandbox-a child failed: %v\n%s\nreported: %s", err, out, reported)
	}

	resB := filepath.Join(t.TempDir(), "resB.txt")
	cmdB := exec.Command(os.Args[0], "-test.run=^$")
	cmdB.Env = append(
		os.Environ(),
		childModeEnv+"=sandbox-b",
		childWSEnv+"="+wsA,
		childResultEnv+"="+resB,
	)
	if out, err := cmdB.CombinedOutput(); err != nil {
		reported, _ := os.ReadFile(resB)
		t.Fatalf("sandbox-b child failed: %v\n%s\nreported: %s", err, out, reported)
	}
}

func runLockedChild(mode string) error {
	switch mode {
	case "files":
	case "cpu":
		return runCPUChild()
	case "mounts":
		return runMountsChild()
	case "file-mount":
		return runFileMountChild()
	case "preserve-acl":
		return runPreserveACLChild()
	case "sandbox-a":
		return runSandboxAChild()
	case "sandbox-b":
		return runSandboxBChild()
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	ws, outside := os.Getenv(childWSEnv), os.Getenv(childOutEnv)
	secret := filepath.Join(outside, "secret.txt")

	wsDir, closeWSDir, err := openPreLockdownDir(ws)
	if err != nil {
		return err
	}
	defer closeWSDir()
	root, err := os.OpenRoot(ws)
	if err != nil {
		return err
	}
	defer root.Close()
	pre, err := os.OpenFile(filepath.Join(ws, "pre.txt"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer pre.Close()
	secretHandle, err := os.Open(secret)
	if err != nil {
		return err
	}
	defer secretHandle.Close()
	var queryTok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &queryTok); err != nil {
		return fmt.Errorf("pre-open query token: %w", err)
	}
	defer queryTok.Close()

	st, err := Apply(Options{Mounts: []HostMount{{Path: ws}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	var errs []error
	expect := func(ok bool, format string, args ...any) {
		if !ok {
			errs = append(errs, fmt.Errorf(format, args...))
		}
	}
	expect(st.Applied && st.SubprocessBlocked && st.UnboundFileOpenBlocked && st.IntegrityDowngraded && st.Win32kBlocked && st.NetworkOutboundBlocked, "status = %+v", st)
	expect(IsLockedDown(), "IsLockedDown = false after Apply")

	_, err = pre.WriteString("pre-opened")
	expect(err == nil, "write pre-opened handle: %v", err)
	buf := make([]byte, 16)
	n, err := secretHandle.Read(buf)
	expect(err == nil && string(buf[:n]) == "host-secret", "read pre-opened outside handle = %q, %v", buf[:n], err)

	broker := ActiveWindowsFileBroker()
	if broker == nil {
		return errors.New("ActiveWindowsFileBroker() = nil after Apply")
	}

	var procTok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &procTok); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		if err == nil {
			_ = procTok.Close()
		}
		errs = append(errs, fmt.Errorf("OpenProcessToken after Apply = %v, want ERROR_ACCESS_DENIED", err))
	}
	if tmlBuf, tmlErr := tokenInformation(queryTok, windows.TokenIntegrityLevel); tmlErr != nil {
		errs = append(errs, fmt.Errorf("query primary TokenIntegrityLevel: %w", tmlErr))
	} else {
		tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&tmlBuf[0]))
		expect(isUntrustedIntegritySID(tml.Label.Sid), "primary token integrity = %v, want Untrusted (%s)", tml.Label.Sid, untrustedIntegritySID)
	}

	for _, badOpt := range []uint32{0x2000, 0x1000} {
		if h, openErr := broker.OpenAt(wsDir, "bound.txt", windows.FILE_GENERIC_READ, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, badOpt); !errors.Is(openErr, windows.ERROR_ACCESS_DENIED) {
			if openErr == nil {
				_ = windows.CloseHandle(h)
			}
			errs = append(errs, fmt.Errorf("OpenAt with disallowed option %#x = %v, want ERROR_ACCESS_DENIED", badOpt, openErr))
		}
	}

	// A restricted thread opens workspace files exclusively through the sealed
	// file broker and fails direct unbrokered opens.
	done := make(chan []error, 1)
	go func() {
		runtime.LockOSThread()
		var threadErrs []error
		if err := BindThread(); err != nil {
			done <- []error{fmt.Errorf("BindThread: %w", err)}
			return
		}
		if err := brokerWriteFile(broker, wsDir, "bound.txt", "bound"); err != nil {
			threadErrs = append(threadErrs, fmt.Errorf("broker write in workspace: %w", err))
		}
		if f, err := root.OpenFile("direct.txt", os.O_CREATE|os.O_RDWR, 0o600); err == nil {
			_ = f.Close()
			threadErrs = append(threadErrs, errors.New("direct unbrokered root.OpenFile succeeded on restricted thread"))
		} else if !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("direct unbrokered root.OpenFile = %v, want permission error", err))
		}
		if _, err := os.ReadFile(secret); !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("read outside path on bound thread = %v, want permission error", err))
		}
		done <- threadErrs
	}()
	errs = append(errs, <-done...)

	// Spawn and exit locked OS threads in sequence so the Go runtime terminates
	// each OS thread and Windows reuses its TID. Every newly created OS thread
	// must still attach the restricted impersonation token on BindThread.
	for i := range 32 {
		iterDone := make(chan error, 1)
		go func(iter int) {
			runtime.LockOSThread()
			if err := BindThread(); err != nil {
				iterDone <- fmt.Errorf("iter %d first BindThread: %w", iter, err)
				return
			}
			if err := BindThread(); err != nil {
				iterDone <- fmt.Errorf("iter %d second BindThread: %w", iter, err)
				return
			}
			var tok windows.Token
			if err := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok); err != nil {
				iterDone <- fmt.Errorf("iter %d OpenThreadToken after BindThread: %w", iter, err)
				return
			}
			_ = tok.Close()
			if _, err := os.ReadFile(secret); !errors.Is(err, fs.ErrPermission) {
				iterDone <- fmt.Errorf("iter %d read outside path = %v, want permission error", iter, err)
				return
			}
			iterDone <- nil
		}(i)
		if err := <-iterDone; err != nil {
			errs = append(errs, err)
			break
		}
	}

	// The job limit of one active process rejects child processes.
	if err := exec.Command("cmd.exe", "/c", "echo", "forbidden").Run(); err == nil {
		errs = append(errs, errors.New("cmd.exe ran after Apply"))
	}
	return errors.Join(errs...)
}

func runPreserveACLChild() error {
	ws, ro, target := os.Getenv(childWSEnv), os.Getenv(childROEnv), os.Getenv(childFileEnv)
	fileDir, leaf := filepath.Split(target)
	fileDir = filepath.Clean(fileDir)

	wsDir, closeWS, err := openPreLockdownDir(ws)
	if err != nil {
		return err
	}
	defer closeWS()
	roDir, closeRO, err := openPreLockdownDir(ro)
	if err != nil {
		return err
	}
	defer closeRO()
	parentDir, closeParent, err := openPreLockdownDir(fileDir)
	if err != nil {
		return err
	}
	defer closeParent()

	if _, err := Apply(Options{
		Mounts: []HostMount{
			{Path: ws},
			{Path: ro, ReadOnly: true},
			{Path: target, File: true},
		},
	}); err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	b := ActiveWindowsFileBroker()
	if b == nil {
		return errors.New("broker is nil")
	}
	if err := brokerWriteFile(b, wsDir, "created.txt", "created"); err != nil {
		return fmt.Errorf("broker write ws: %w", err)
	}
	if got, err := brokerReadFile(b, roDir, "existing.txt"); err != nil || got != "ro-item" {
		return fmt.Errorf("broker read ro = %q, %v", got, err)
	}
	h, err := b.OpenAt(parentDir, leaf, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return fmt.Errorf("broker open file mount: %w", err)
	}
	_ = windows.CloseHandle(h)
	return nil
}

func runSandboxAChild() error {
	wsA := os.Getenv(childWSEnv)
	everyoneFile := os.Getenv(childOutEnv)
	dialAddr := os.Getenv(childDialEnv)

	wsDir, closeWS, err := openPreLockdownDir(wsA)
	if err != nil {
		return err
	}
	defer closeWS()

	st, err := Apply(Options{
		Mounts:           []HostMount{{Path: wsA}},
		AllowOutboundNet: true,
	})
	if err != nil {
		return fmt.Errorf("Apply(sandbox-a): %w", err)
	}
	if !st.Applied || st.NetworkOutboundBlocked {
		return fmt.Errorf("unexpected sandbox-a status: %+v", st)
	}
	b := ActiveWindowsFileBroker()
	if b == nil {
		return errors.New("broker is nil")
	}
	insidePath := filepath.Join(wsA, "inside.txt")
	if err := brokerWriteFile(b, wsDir, "inside.txt", "sandbox-a-secret"); err != nil {
		return fmt.Errorf("brokerWriteFile: %w", err)
	}

	// Outbound TCP through DialContext must succeed when AllowOutboundNet=true.
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := DialContext(dialCtx, "tcp", dialAddr)
	cancel()
	if err != nil {
		return fmt.Errorf("DialContext(%q) under AllowOutboundNet=true: %w", dialAddr, err)
	}
	_ = conn.Close()

	// Park 160 OS threads concurrently (exceeding minPrewarmedThreads=128)
	// without calling BindThread() directly. After the background sweeper runs,
	// every OS thread must hold an impersonation token and fail reads of both
	// Everyone-readable host files and unbrokered workspace paths.
	const totalThreads = 160
	var parked sync.WaitGroup
	var finished sync.WaitGroup
	parked.Add(totalThreads)
	finished.Add(totalThreads)
	checkNow := make(chan struct{})
	errCh := make(chan error, totalThreads)

	for i := range totalThreads {
		go func(idx int) {
			runtime.LockOSThread()
			defer finished.Done()
			parked.Done()
			<-checkNow

			var tok windows.Token
			deadline := time.Now().Add(2 * time.Second)
			for {
				tokErr := windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &tok)
				if tokErr == nil {
					break
				}
				if time.Now().After(deadline) {
					errCh <- fmt.Errorf("thread %d has no impersonation token before deadline: %w", idx, tokErr)
					return
				}
				runtime.Gosched()
			}
			_ = tok.Close()
			if _, rerr := os.ReadFile(everyoneFile); !errors.Is(rerr, fs.ErrPermission) {
				errCh <- fmt.Errorf("thread %d read Everyone file = %v, want permission error", idx, rerr)
				return
			}
			if _, rerr := os.ReadFile(insidePath); !errors.Is(rerr, fs.ErrPermission) {
				errCh <- fmt.Errorf("thread %d direct read workspace file = %v, want permission error", idx, rerr)
				return
			}
		}(i)
	}
	parked.Wait()
	close(checkNow)
	finished.Wait()
	close(errCh)

	var errs []error
	for e := range errCh {
		errs = append(errs, e)
	}
	return errors.Join(errs...)
}

func runSandboxBChild() error {
	wsA := os.Getenv(childWSEnv)
	insidePath := filepath.Join(wsA, "inside.txt")

	if _, err := Apply(Options{}); err != nil {
		return fmt.Errorf("Apply(sandbox-b): %w", err)
	}
	var errs []error
	if _, err := os.ReadFile(insidePath); !errors.Is(err, fs.ErrPermission) {
		errs = append(errs, fmt.Errorf("sandbox-b read sandbox-a file = %v, want permission error", err))
	}
	if err := os.WriteFile(filepath.Join(wsA, "intrude.txt"), []byte("bad"), 0o600); !errors.Is(err, fs.ErrPermission) {
		errs = append(errs, fmt.Errorf("sandbox-b write in sandbox-a workspace = %v, want permission error", err))
	}
	if _, err := os.ReadDir(wsA); !errors.Is(err, fs.ErrPermission) {
		errs = append(errs, fmt.Errorf("sandbox-b list sandbox-a workspace = %v, want permission error", err))
	}
	return errors.Join(errs...)
}

// TestApplyCapsTheCPUTimeOfTheJob proves that the lockdown puts the hard CPU cap
// on the job of the process, by reading the cap back in the locked child.
func TestApplyCapsTheCPUTimeOfTheJob(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childModeEnv+"=cpu")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lockdown child failed: %v\n%s", err, out)
	}
}

func runCPUChild() error {
	const quota = 500
	st, err := Apply(Options{CPUQuotaMillis: quota})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	if !st.CPUQuotaEnforced {
		return fmt.Errorf("status = %+v, want CPUQuotaEnforced", st)
	}
	// A NULL job handle names the job of the calling process.
	var got jobCPURateControl
	if err := queryJobInformation(0, jobObjectCPURateControlInformation, unsafe.Pointer(&got), unsafe.Sizeof(got)); err != nil {
		return fmt.Errorf("QueryInformationJobObject: %w", err)
	}
	want := jobCPURate(quota, runtime.NumCPU())
	if got.CPURate != want || got.ControlFlags&jobCPURateControlHardCap == 0 {
		return fmt.Errorf("job CPU cap = %+v, want a hard cap with rate %d", got, want)
	}
	return nil
}

// TestApplyLockdownWithTwoMounts proves that the file broker serves a writable
// mount and a read-only mount, refuses writes to the read-only mount, and keeps
// paths outside every mount closed.
func TestApplyLockdownWithTwoMounts(t *testing.T) {
	dir := func() string {
		p, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("EvalSymlinks: %v", err)
		}
		return p
	}
	rw, ro, outside := dir(), dir(), dir()
	if err := os.WriteFile(filepath.Join(ro, "existing.txt"), []byte("read-only-content"), 0o600); err != nil {
		t.Fatalf("WriteFile existing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("host-secret"), 0o600); err != nil {
		t.Fatalf("WriteFile secret: %v", err)
	}
	result := filepath.Join(t.TempDir(), "result.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childModeEnv+"=mounts", childWSEnv+"="+rw, childROEnv+"="+ro, childOutEnv+"="+outside, childResultEnv+"="+result)
	if out, err := cmd.CombinedOutput(); err != nil {
		reported, _ := os.ReadFile(result)
		t.Fatalf("lockdown child failed: %v\n%s\nreported: %s", err, out, reported)
	}
}

func runMountsChild() error {
	rw, ro, outside := os.Getenv(childWSEnv), os.Getenv(childROEnv), os.Getenv(childOutEnv)
	rwDir, closeRW, err := openPreLockdownDir(rw)
	if err != nil {
		return err
	}
	defer closeRW()
	roDir, closeRO, err := openPreLockdownDir(ro)
	if err != nil {
		return err
	}
	defer closeRO()
	outDir, closeOut, err := openPreLockdownDir(outside)
	if err != nil {
		return err
	}
	defer closeOut()

	st, err := Apply(Options{Mounts: []HostMount{{Path: rw}, {Path: ro, ReadOnly: true}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	if !st.Applied || !st.UnboundFileOpenBlocked {
		return fmt.Errorf("status = %+v, want an applied lockdown that blocks unbound opens", st)
	}
	b := ActiveWindowsFileBroker()
	if b == nil {
		return errors.New("broker is nil")
	}

	done := make(chan []error, 1)
	go func() {
		runtime.LockOSThread()
		var errs []error
		if err := BindThread(); err != nil {
			done <- []error{fmt.Errorf("BindThread: %w", err)}
			return
		}
		if err := brokerWriteFile(b, rwDir, "new.txt", "created"); err != nil {
			errs = append(errs, fmt.Errorf("create in the writable mount: %w", err))
		}
		if data, err := brokerReadFile(b, roDir, "existing.txt"); err != nil || data != "read-only-content" {
			errs = append(errs, fmt.Errorf("read in the read-only mount = %q, %v", data, err))
		}
		if err := brokerWriteFile(b, roDir, "new.txt", "forbidden"); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			errs = append(errs, fmt.Errorf("create in the read-only mount = %v, want ERROR_ACCESS_DENIED", err))
		}
		if _, err := brokerReadFile(b, outDir, "secret.txt"); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			errs = append(errs, fmt.Errorf("broker read in unmounted dir = %v, want ERROR_ACCESS_DENIED", err))
		}
		if _, err := os.ReadFile(filepath.Join(outside, "secret.txt")); !errors.Is(err, fs.ErrPermission) {
			errs = append(errs, fmt.Errorf("read outside every mount = %v, want a permission error", err))
		}
		done <- errs
	}()
	return errors.Join(<-done...)
}

// TestApplyLockdownWithFileMount proves that a file mount serves the broker for
// that file only while keeping the sibling file and the parent directory closed.
func TestApplyLockdownWithFileMount(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "target.txt"), []byte("target-data"), 0o600); err != nil {
		t.Fatalf("WriteFile target: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sibling.txt"), []byte("sibling-data"), 0o600); err != nil {
		t.Fatalf("WriteFile sibling: %v", err)
	}
	result := filepath.Join(t.TempDir(), "result.txt")
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childModeEnv+"=file-mount", childWSEnv+"="+dir, childResultEnv+"="+result)
	if out, err := cmd.CombinedOutput(); err != nil {
		reported, _ := os.ReadFile(result)
		t.Fatalf("lockdown child failed: %v\n%s\nreported: %s", err, out, reported)
	}
}

func runFileMountChild() error {
	dir := os.Getenv(childWSEnv)
	target := filepath.Join(dir, "target.txt")
	parentDir, closeParent, err := openPreLockdownDir(dir)
	if err != nil {
		return err
	}
	defer closeParent()
	held, err := os.OpenFile(target, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer held.Close()

	st, err := Apply(Options{Mounts: []HostMount{{Path: target, File: true}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	if !st.Applied || !st.UnboundFileOpenBlocked {
		return fmt.Errorf("status = %+v, want an applied lockdown that blocks unbound opens", st)
	}
	b := ActiveWindowsFileBroker()
	if b == nil {
		return errors.New("broker is nil")
	}

	var errs []error
	if _, err := held.WriteString("held"); err != nil {
		errs = append(errs, fmt.Errorf("write through the pre-opened handle: %w", err))
	}

	done := make(chan []error, 1)
	go func() {
		runtime.LockOSThread()
		var threadErrs []error
		if err := BindThread(); err != nil {
			done <- []error{fmt.Errorf("BindThread: %w", err)}
			return
		}
		h, err := b.OpenAt(
			parentDir,
			"target.txt",
			windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE,
			windows.FILE_ATTRIBUTE_NORMAL,
			windows.FILE_OPEN,
			windows.FILE_NON_DIRECTORY_FILE,
		)
		if err != nil {
			threadErrs = append(threadErrs, fmt.Errorf("broker open file mount: %w", err))
		} else {
			f := os.NewFile(uintptr(h), "target.txt")
			if _, werr := f.WriteString("bound"); werr != nil {
				threadErrs = append(threadErrs, fmt.Errorf("write file mount handle: %w", werr))
			}
			_ = f.Close()
		}
		if _, err := brokerReadFile(b, parentDir, "sibling.txt"); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			threadErrs = append(threadErrs, fmt.Errorf("broker open sibling = %v, want ERROR_ACCESS_DENIED", err))
		}
		if err := brokerWriteFile(b, parentDir, "created.txt", "x"); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			threadErrs = append(threadErrs, fmt.Errorf("broker create next to file mount = %v, want ERROR_ACCESS_DENIED", err))
		}
		if _, err := os.ReadFile(filepath.Join(dir, "sibling.txt")); !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("read sibling by path = %v, want a permission error", err))
		}
		if _, err := os.ReadDir(dir); !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("list the parent of the file mount = %v, want a permission error", err))
		}
		done <- threadErrs
	}()
	errs = append(errs, <-done...)
	return errors.Join(errs...)
}
