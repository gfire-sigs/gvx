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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	childModeEnv   = "GVX_HOSTLOCKDOWN_CHILD_MODE"
	childWSEnv     = "GVX_HOSTLOCKDOWN_WORKSPACE"
	childOutEnv    = "GVX_HOSTLOCKDOWN_OUTSIDE"
	childROEnv     = "GVX_HOSTLOCKDOWN_READONLY"
	childResultEnv = "GVX_HOSTLOCKDOWN_RESULT"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(childModeEnv); mode != "" {
		// The child opens the result file before the lockdown, because the
		// lockdown can refuse a write to the pipes of the parent.
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

func TestIsLogonSessionSID(t *testing.T) {
	tests := []struct {
		sid  string
		want bool
	}{
		{"S-1-5-5-0-123456", true},
		{"S-1-5-5-1-2", true},
		{"S-1-5-5-0", false},
		{"S-1-5-32-544", false},
		{"S-1-5-21-1-2-3", false},
		{"S-1-1-0", false},
	}
	for _, tt := range tests {
		if got := isLogonSessionSID(mustSID(t, tt.sid)); got != tt.want {
			t.Errorf("isLogonSessionSID(%s) = %v, want %v", tt.sid, got, tt.want)
		}
	}
}

func TestStaleLogonSIDs(t *testing.T) {
	current := mustSID(t, "S-1-5-5-0-111")
	sd, err := windows.SecurityDescriptorFromString(
		"D:(A;;FA;;;S-1-5-5-0-111)(A;;FA;;;S-1-5-5-0-222)(A;;FA;;;S-1-5-5-0-222)(A;;FA;;;S-1-5-32-544)(A;;FA;;;S-1-5-5-0-333)")
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("DACL: %v", err)
	}
	got := staleLogonSIDs(dacl, current)
	if len(got) != 2 || got[0].String() != "S-1-5-5-0-222" || got[1].String() != "S-1-5-5-0-333" {
		t.Fatalf("staleLogonSIDs = %v, want S-1-5-5-0-222 and S-1-5-5-0-333 once each", got)
	}
	if staleLogonSIDs(nil, current) != nil {
		t.Fatal("staleLogonSIDs(nil) is not nil")
	}
}

func TestWorkspaceAccessMask(t *testing.T) {
	rw := workspaceAccessMask(false)
	ro := workspaceAccessMask(true)
	writeBits := windows.ACCESS_MASK(windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.DELETE | fileDeleteChild)
	if rw&writeBits != writeBits {
		t.Errorf("read-write mask %#x lacks write bits %#x", rw, writeBits)
	}
	if ro&writeBits != 0 {
		t.Errorf("read-only mask %#x contains write bits %#x", ro, ro&writeBits)
	}
	if ro&windows.FILE_GENERIC_READ != windows.FILE_GENERIC_READ || rw&ro != ro {
		t.Errorf("masks ro=%#x rw=%#x: read-only must be a subset that includes generic read", ro, rw)
	}
}

// TestPrepareWorkspaceFileLabelsOnlyTheFile proves that a file mount puts the
// Low label and the logon SID entry on that file and on nothing around it.
func TestPrepareWorkspaceFileLabelsOnlyTheFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	sibling := filepath.Join(dir, "sibling.txt")
	for _, p := range []string{target, sibling} {
		if err := os.WriteFile(p, []byte("data"), 0o600); err != nil {
			t.Fatalf("WriteFile %q: %v", p, err)
		}
	}
	primary, err := openPrimaryToken()
	if err != nil {
		t.Fatal(err)
	}
	defer primary.Close()
	id, err := readTokenIdentity(primary)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareWorkspace(target, id.logon, false, true); err != nil {
		t.Fatalf("prepareWorkspace(file) = %v", err)
	}
	grant := workspaceGrant{logon: id.logon, mask: workspaceAccessMask(false)}
	state, err := grant.read(target, false)
	if err != nil || !state.complete() {
		t.Errorf("target state = %+v, %v; want the Low label and the logon entry", state, err)
	}
	for _, other := range []struct {
		path  string
		isDir bool
	}{{sibling, false}, {dir, true}} {
		state, err := grant.read(other.path, other.isDir)
		if err != nil {
			t.Fatalf("read %q: %v", other.path, err)
		}
		if state.labeled {
			t.Errorf("%q carries a Low label after a file mount of its neighbor", other.path)
		}
	}
}

func TestGrantsAccess(t *testing.T) {
	logon := mustSID(t, "S-1-5-5-0-123456")
	rw := workspaceAccessMask(false)
	tests := []struct {
		name string
		sddl string
		mask windows.ACCESS_MASK
		want bool
	}{
		{"full access", "D:(A;;FA;;;S-1-5-5-0-123456)", rw, true},
		{"read only entry for write mask", "D:(A;;FRFX;;;S-1-5-5-0-123456)", rw, false},
		{"read only entry for read mask", "D:(A;;FRFX;;;S-1-5-5-0-123456)", workspaceAccessMask(true), true},
		{"other sid", "D:(A;;FA;;;S-1-5-5-0-999999)", rw, false},
		{"inherit only entry", "D:(A;OICIIO;FA;;;S-1-5-5-0-123456)", rw, false},
		{"deny entry", "D:(D;;FA;;;S-1-5-5-0-123456)", rw, false},
		{"split entries", "D:(A;;FRFX;;;S-1-5-5-0-123456)(A;;FW;;;S-1-5-5-0-123456)(A;;SD;;;S-1-5-5-0-123456)(A;;0x40;;;S-1-5-5-0-123456)", rw, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString: %v", err)
			}
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatalf("DACL: %v", err)
			}
			if got := grantsAccess(dacl, logon, tt.mask); got != tt.want {
				var entries []string
				for i := uint32(0); i < uint32(dacl.AceCount); i++ {
					var ace *windows.ACCESS_ALLOWED_ACE
					if err := windows.GetAce(dacl, i, &ace); err != nil {
						entries = append(entries, fmt.Sprintf("GetAce(%d): %v", i, err))
						continue
					}
					entries = append(entries, fmt.Sprintf("type %d flags %#x mask %#x", ace.Header.AceType, ace.Header.AceFlags, uint32(ace.Mask)))
				}
				t.Fatalf("grantsAccess = %v, want %v for mask %#x and %d entries: %q",
					got, tt.want, uint32(tt.mask), dacl.AceCount, entries)
			}
		})
	}
}

func TestHasLowLabel(t *testing.T) {
	tests := []struct {
		name  string
		sddl  string
		isDir bool
		want  bool
	}{
		{"inheritable label on directory", lowLabelDirSDDL, true, true},
		{"inheritable label on file", lowLabelDirSDDL, false, true},
		{"file label on file", lowLabelFileSDDL, false, true},
		{"file label on directory", lowLabelFileSDDL, true, false},
		{"medium label", "S:(ML;OICI;NW;;;ME)", true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(tt.sddl)
			if err != nil {
				t.Fatalf("SecurityDescriptorFromString: %v", err)
			}
			sacl, _, err := sd.SACL()
			if err != nil {
				t.Fatalf("SACL: %v", err)
			}
			if got := hasLowLabel(sacl, tt.isDir); got != tt.want {
				t.Fatalf("hasLowLabel = %v, want %v", got, tt.want)
			}
		})
	}
	if hasLowLabel(nil, true) {
		t.Fatal("hasLowLabel(nil) = true")
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
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childModeEnv+"=files", childWSEnv+"="+ws, childOutEnv+"="+outside)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lockdown child failed: %v\n%s", err, out)
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
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
	ws, outside := os.Getenv(childWSEnv), os.Getenv(childOutEnv)
	secret := filepath.Join(outside, "secret.txt")

	root, err := os.OpenRoot(ws)
	if err != nil {
		return err
	}
	pre, err := os.OpenFile(filepath.Join(ws, "pre.txt"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	secretHandle, err := os.Open(secret)
	if err != nil {
		return err
	}

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
	expect(st.Applied && st.SubprocessBlocked && st.UnboundFileOpenBlocked && st.IntegrityDowngraded && st.Win32kBlocked, "status = %+v", st)
	expect(IsLockedDown(), "IsLockedDown = false after Apply")

	_, err = pre.WriteString("pre-opened")
	expect(err == nil, "write pre-opened handle: %v", err)
	buf := make([]byte, 16)
	n, err := secretHandle.Read(buf)
	expect(err == nil && string(buf[:n]) == "host-secret", "read pre-opened outside handle = %q, %v", buf[:n], err)

	// The restricted token on a locked thread still serves the workspace
	// through the pinned root handle and rejects every other path.
	done := make(chan []error, 1)
	go func() {
		runtime.LockOSThread()
		var threadErrs []error
		if err := BindThread(); err != nil {
			done <- []error{fmt.Errorf("BindThread: %w", err)}
			return
		}
		f, err := root.OpenFile("bound.txt", os.O_CREATE|os.O_RDWR, 0o600)
		if err != nil {
			threadErrs = append(threadErrs, fmt.Errorf("create through root on bound thread: %w", err))
		} else {
			_, werr := f.WriteString("bound")
			if werr != nil {
				threadErrs = append(threadErrs, fmt.Errorf("write on bound thread: %w", werr))
			}
			_ = f.Close()
		}
		if _, err := os.ReadFile(secret); !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("read outside path on bound thread = %v, want permission error", err))
		}
		done <- threadErrs
	}()
	errs = append(errs, <-done...)

	// The job limit of one active process rejects child processes.
	if err := exec.Command("cmd.exe", "/c", "echo", "forbidden").Run(); err == nil {
		errs = append(errs, errors.New("cmd.exe ran after Apply"))
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

// TestApplyLockdownWithTwoMounts proves that a writable mount and a read-only
// mount both serve a bound thread, that the read-only mount refuses a write,
// and that a path outside every mount stays closed.
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
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), childModeEnv+"=mounts", childWSEnv+"="+rw, childROEnv+"="+ro, childOutEnv+"="+outside)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("lockdown child failed: %v\n%s", err, out)
	}
}

func runMountsChild() error {
	rw, ro, outside := os.Getenv(childWSEnv), os.Getenv(childROEnv), os.Getenv(childOutEnv)
	rwRoot, err := os.OpenRoot(rw)
	if err != nil {
		return err
	}
	roRoot, err := os.OpenRoot(ro)
	if err != nil {
		return err
	}
	st, err := Apply(Options{Mounts: []HostMount{{Path: rw}, {Path: ro, ReadOnly: true}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	if !st.Applied || !st.UnboundFileOpenBlocked {
		return fmt.Errorf("status = %+v, want an applied lockdown that blocks unbound opens", st)
	}

	done := make(chan []error, 1)
	go func() {
		runtime.LockOSThread()
		var errs []error
		if err := BindThread(); err != nil {
			done <- []error{fmt.Errorf("BindThread: %w", err)}
			return
		}
		if f, err := rwRoot.OpenFile("new.txt", os.O_CREATE|os.O_RDWR, 0o600); err != nil {
			errs = append(errs, fmt.Errorf("create in the writable mount: %w", err))
		} else {
			_ = f.Close()
		}
		if data, err := roRoot.ReadFile("existing.txt"); err != nil || string(data) != "read-only-content" {
			errs = append(errs, fmt.Errorf("read in the read-only mount = %q, %v", data, err))
		}
		if f, err := roRoot.OpenFile("new.txt", os.O_CREATE|os.O_RDWR, 0o600); err == nil {
			_ = f.Close()
			errs = append(errs, errors.New("create in the read-only mount succeeded"))
		} else if !errors.Is(err, fs.ErrPermission) {
			errs = append(errs, fmt.Errorf("create in the read-only mount = %v, want a permission error", err))
		}
		if _, err := os.ReadFile(filepath.Join(outside, "secret.txt")); !errors.Is(err, fs.ErrPermission) {
			errs = append(errs, fmt.Errorf("read outside every mount = %v, want a permission error", err))
		}
		done <- errs
	}()
	return errors.Join(<-done...)
}

// TestApplyLockdownWithFileMount proves that a file mount serves a bound
// thread for that file only. The sibling file and the parent directory stay
// closed.
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	held, err := os.OpenFile(target, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	st, err := Apply(Options{Mounts: []HostMount{{Path: target, File: true}}})
	if err != nil {
		return fmt.Errorf("Apply: %w", err)
	}
	if !st.Applied || !st.UnboundFileOpenBlocked {
		return fmt.Errorf("status = %+v, want an applied lockdown that blocks unbound opens", st)
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
		f, err := root.OpenFile("target.txt", os.O_RDWR, 0)
		if err != nil {
			threadErrs = append(threadErrs, fmt.Errorf("open the file mount through the root on a bound thread: %w", err))
		} else {
			if _, err := f.WriteString("bound"); err != nil {
				threadErrs = append(threadErrs, fmt.Errorf("write the file mount on a bound thread: %w", err))
			}
			_ = f.Close()
		}
		if f, err := root.Open("sibling.txt"); err == nil {
			_ = f.Close()
			threadErrs = append(threadErrs, errors.New("open of the sibling file through the root succeeded"))
		} else if !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("open sibling through the root = %v, want a permission error", err))
		}
		if _, err := os.ReadFile(filepath.Join(dir, "sibling.txt")); !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("read sibling by path = %v, want a permission error", err))
		}
		if _, err := os.ReadDir(dir); !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("list the parent of the file mount = %v, want a permission error", err))
		}
		if _, err := root.OpenFile("created.txt", os.O_CREATE|os.O_RDWR, 0o600); !errors.Is(err, fs.ErrPermission) {
			threadErrs = append(threadErrs, fmt.Errorf("create next to the file mount = %v, want a permission error", err))
		}
		done <- threadErrs
	}()
	errs = append(errs, <-done...)
	return errors.Join(errs...)
}
