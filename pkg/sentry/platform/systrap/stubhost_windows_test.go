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

package systrap

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The stub host runs outside the lockdown with the full rights of the user. A
// handle with write access to it lets a compromised Sentry run code there. The
// Sentry must keep only a handle that waits for the exit.
func TestSentryKeepsNoWriteAccessToTheStubHost(t *testing.T) {
	p := newPlatform(t)
	h := p.host
	if h.wait == 0 {
		t.Fatal("the platform keeps no wait handle for the stub host")
	}
	if err := windows.TerminateProcess(h.wait, 1); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("TerminateProcess through the retained handle = %v, want access denied", err)
	}
	var buf [8]byte
	var n uintptr
	if err := windows.ReadProcessMemory(h.wait, uintptr(unsafe.Pointer(&buf[0])), &buf[0], 1, &n); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("ReadProcessMemory through the retained handle = %v, want access denied", err)
	}
	if err := h.cmd.Process.Kill(); err == nil {
		t.Error("the released os.Process still kills the host")
	}
	// The host must stay alive and serve requests after the release.
	if ev, _ := windows.WaitForSingleObject(h.wait, 0); ev == windows.WAIT_OBJECT_0 {
		t.Fatal("the stub host exited after the release of its handle")
	}
}

// Close waits for the host through the retained handle and reports a host that
// does not exit.
func TestStubHostCloseWaitsThroughTheRetainedHandle(t *testing.T) {
	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if p.host.wait != 0 {
		t.Error("Close left the wait handle open")
	}
}

// A policy of the machine can refuse the small stub image. The host must then
// start the stub from its own executable, and remember the choice.
func TestStubHostFallsBackWhenTheImageDoesNotStart(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	token, level, err := buildStubToken()
	if err != nil {
		t.Fatalf("buildStubToken: %v", err)
	}
	defer token.Close()
	h := &stubHostLoop{
		token: token, level: level, exe: exe,
		image: &stubImage{path: filepath.Join(t.TempDir(), "refused.exe")},
	}
	pi, _, err := h.startStubProcess()
	if err != nil {
		t.Fatalf("startStubProcess: %v", err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	defer windows.TerminateProcess(pi.Process, 0)
	if h.image != nil {
		t.Error("the host keeps the image that did not start")
	}
	pi2, _, err := h.startStubProcess()
	if err != nil {
		t.Fatalf("the second stub: %v", err)
	}
	defer windows.CloseHandle(pi2.Process)
	defer windows.CloseHandle(pi2.Thread)
	defer windows.TerminateProcess(pi2.Process, 0)
}

// A guest that runs a system call of its own, through a hidden SYSCALL
// instruction, acts as the token of its stub. Low integrity blocks writes only.
// The restricting SIDs must also block the read of a file that only the user
// can read, such as a key in the profile of the user.
func TestStubTokenCannotReadAFileThatOnlyTheUserCanRead(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	private := filepath.Join(t.TempDir(), "private.txt")
	if err := os.WriteFile(private, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(private, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatalf("SetNamedSecurityInfo: %v", err)
	}
	if _, err := os.ReadFile(private); err != nil {
		t.Fatalf("the user cannot read its own file: %v", err)
	}

	primary, _, err := buildStubToken()
	if err != nil {
		t.Fatalf("buildStubToken: %v", err)
	}
	defer primary.Close()
	var imp windows.Token
	if err := windows.DuplicateTokenEx(primary, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &imp); err != nil {
		t.Fatalf("DuplicateTokenEx: %v", err)
	}
	defer imp.Close()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := windows.SetThreadToken(nil, imp); err != nil {
		t.Fatalf("SetThreadToken: %v", err)
	}
	defer windows.RevertToSelf()

	if _, err := os.ReadFile(private); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Errorf("the stub token read the private file, error = %v, want access denied", err)
	}
	kernel32 := filepath.Join(os.Getenv("SystemRoot"), "System32", "kernel32.dll")
	f, err := os.Open(kernel32)
	if err != nil {
		t.Errorf("the stub token cannot read %s, which every process needs: %v", kernel32, err)
	} else {
		f.Close()
	}
}

func TestStubTokenMarksExtraGroupsDenyOnlyAndRestrictsLogonSID(t *testing.T) {
	primary, _, err := buildStubToken()
	if err != nil {
		t.Fatalf("buildStubToken: %v", err)
	}
	defer primary.Close()

	groups, err := primary.GetTokenGroups()
	if err != nil {
		t.Fatalf("GetTokenGroups: %v", err)
	}
	var logonSID *windows.SID
	for _, g := range groups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_INTEGRITY != 0 {
			continue
		}
		if g.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			logonSID = g.Sid
			continue
		}
		if g.Attributes&windows.SE_GROUP_ENABLED != 0 && !isStubAllowedGroupSID(g.Sid) {
			t.Errorf("unexpected enabled group SID %s in stub token (attrs=%#x)", g.Sid, g.Attributes)
		}
	}

	var needed uint32
	_ = windows.GetTokenInformation(primary, windows.TokenRestrictedSids, nil, 0, &needed)
	if needed == 0 {
		t.Fatal("TokenRestrictedSids returned zero size")
	}
	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(primary, windows.TokenRestrictedSids, &buf[0], needed, &needed); err != nil {
		t.Fatalf("GetTokenInformation(TokenRestrictedSids): %v", err)
	}
	restricted := (*windows.Tokengroups)(unsafe.Pointer(&buf[0]))
	for _, r := range restricted.AllGroups() {
		if logonSID != nil && windows.EqualSid(r.Sid, logonSID) {
			t.Errorf("TokenRestrictedSids unexpectedly includes logon SID %s", r.Sid)
		}
	}
}

func TestStubTokenDefaultDACLExcludesEveryoneAndIsolatesStubs(t *testing.T) {
	tokA, sdA, _, err := newStubIdentity()
	if err != nil {
		t.Fatalf("newStubIdentity A: %v", err)
	}
	defer tokA.Close()
	tokB, sdB, _, err := newStubIdentity()
	if err != nil {
		t.Fatalf("newStubIdentity B: %v", err)
	}
	defer tokB.Close()

	if sdA.String() == sdB.String() {
		t.Fatalf("two stub identities shared the same private SID in SDDL: %s", sdA.String())
	}

	everyone, err := windows.StringToSid("S-1-1-0")
	if err != nil {
		t.Fatal(err)
	}
	var needed uint32
	_ = windows.GetTokenInformation(tokA, windows.TokenDefaultDacl, nil, 0, &needed)
	if needed == 0 {
		t.Fatal("TokenDefaultDacl returned zero size")
	}
	buf := make([]byte, needed)
	if err := windows.GetTokenInformation(tokA, windows.TokenDefaultDacl, &buf[0], needed, &needed); err != nil {
		t.Fatalf("GetTokenInformation(TokenDefaultDacl): %v", err)
	}
	dacl := *(**windows.ACL)(unsafe.Pointer(&buf[0]))
	if dacl == nil {
		t.Fatal("TokenDefaultDacl has nil ACL")
	}
	type aceHeader struct {
		AceType  uint8
		AceFlags uint8
		AceSize  uint16
	}
	type accessAllowedAce struct {
		Header   aceHeader
		Mask     uint32
		SidStart uint32
	}
	aclHdr := (*struct {
		AclRevision uint8
		Sbz1        uint8
		AclSize     uint16
		AceCount    uint16
		Sbz2        uint16
	})(unsafe.Pointer(dacl))
	offset := uintptr(8)
	for i := uint16(0); i < aclHdr.AceCount; i++ {
		ace := (*accessAllowedAce)(unsafe.Pointer(uintptr(unsafe.Pointer(dacl)) + offset))
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if windows.EqualSid(sid, everyone) {
			t.Fatalf("TokenDefaultDacl grants access to Everyone (S-1-1-0)")
		}
		offset += uintptr(ace.Header.AceSize)
	}
}
