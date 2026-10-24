package gvxshim

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsEndpointUsesProtectedLocalPipe(t *testing.T) {
	paths := platformFixture(t)
	endpoint, err := listenLocal(t.Context(), paths, taskEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer endpoint.Listener.Close()
	if endpoint.Ref.Socket != nil {
		t.Fatal("Windows endpoint has filesystem socket ownership")
	}
	if duplicate, err := listenLocal(t.Context(), paths, taskEndpoint); err == nil {
		duplicate.Listener.Close()
		t.Fatal("existing pipe bind accepted")
	}
	accepted := make(chan net.Conn, 1)
	acceptError := make(chan error, 1)
	go func() {
		conn, err := endpoint.Listener.Accept()
		if err != nil {
			acceptError <- err
			return
		}
		accepted <- conn
	}()
	client, err := dialLocal(t.Context(), paths.TaskAddress)
	if err != nil {
		endpoint.Listener.Close()
		<-acceptError
		t.Fatal(err)
	}
	defer client.Close()
	var server net.Conn
	select {
	case server = <-accepted:
	case err := <-acceptError:
		t.Fatal(err)
	}
	defer server.Close()
	handle, ok := server.(interface{ Fd() uintptr })
	if !ok {
		t.Fatal("pipe connection does not expose its native handle")
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatalf("pipe DACL is not protected: %#x, %v", control, err)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		t.Fatalf("missing pipe DACL: %v", err)
	}
	type aclHeader struct {
		Revision  byte
		Reserved  byte
		Size      uint16
		Count     uint16
		Reserved2 uint16
	}
	count := (*aclHeader)(unsafe.Pointer(acl)).Count
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{owner: false, "S-1-5-18": false}
	if int(count) != len(expected) {
		t.Fatalf("pipe DACL ACE count: %d, want %d", count, len(expected))
	}
	for index := range uint32(count) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		seen, ok := expected[sid]
		if !ok || seen || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			t.Fatalf("unexpected pipe ACE: SID=%q, type=%d", sid, ace.Header.AceType)
		}
		expected[sid] = true
	}
	server.SetDeadline(time.Now().Add(5 * time.Second))
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte{7}); err != nil {
		t.Fatal(err)
	}
	var payload [1]byte
	if _, err := server.Read(payload[:]); err != nil || payload[0] != 7 {
		t.Fatalf("pipe payload: %v, %v", payload, err)
	}
}

func TestWindowsLocalDialRejectsRemotePipes(t *testing.T) {
	for _, address := range []string{`\\remote\pipe\gvx`, `npipe:////remote/pipe/gvx`, "tcp://127.0.0.1:1"} {
		if conn, err := dialLocal(t.Context(), address); err == nil {
			conn.Close()
			t.Errorf("accepted %q", address)
		} else if !errors.Is(err, errUnsafeEntry) {
			t.Errorf("remote pipe error: %v", err)
		}
	}
}

func TestWindowsUnsafeStateACLIsNotRepaired(t *testing.T) {
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(bundle, ".gvx-shim")
	name, err := windows.UTF16PtrFromString(statePath)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	attributes := windows.SecurityAttributes{SecurityDescriptor: sd}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	if err := windows.CreateDirectory(name, &attributes); err != nil {
		t.Fatal(err)
	}
	handle, err := platformOpenInitial(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	before, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	id := instanceIdentity{Owner: owner, Namespace: "unsafe-acl", ID: "instance", Bundle: bundle, ContainerdAddress: `\\.\pipe\platform-containerd`}
	if paths, err := openPaths(t.Context(), id, createPaths); err == nil {
		paths.Close()
		t.Fatal("world-writable state accepted")
	}
	after, err := windows.GetSecurityInfo(windows.Handle(handle.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("unsafe ACL changed: before %s, after %s", before, after)
	}
	entries, err := os.ReadDir(statePath)
	if err != nil || len(entries) != 0 {
		t.Fatalf("unsafe directory modified: %v, %v", entries, err)
	}
}

func TestWindowsDiagnosticsEnforcesKernelAppend(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("first"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = openDiagnostics(paths, ref)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var written uint32
	if err := windows.WriteFile(windows.Handle(file.Fd()), []byte("second"), &written, &windows.Overlapped{}); err != nil || written != 6 {
		t.Fatalf("append at explicit offset zero: bytes=%d, error=%v", written, err)
	}
	if err := file.Truncate(0); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("append-only handle truncation: %v, want access denied", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := paths.State.Root.ReadFile(ref.Name)
	if err != nil || string(data) != "firstsecond" {
		t.Fatalf("kernel append content: %q, %v", data, err)
	}
	if err := removeOwned(paths.State, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := paths.State.Root.Lstat(ref.Name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("diagnostics after owned cleanup: %v", err)
	}
}

func TestWindowsUnsafeDiagnosticsACLIsNotRepaired(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("private diagnostics"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(paths.Identity.Bundle, ".gvx-shim", ref.Name)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if file, err := openDiagnostics(paths, ref); err == nil {
		file.Close()
		t.Fatal("world-readable diagnostics accepted")
	} else if !errors.Is(err, errUnsafeEntry) {
		t.Fatalf("unsafe diagnostics error: %v", err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("unsafe diagnostics ACL changed: before %s, after %s", before, after)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "private diagnostics" {
		t.Fatalf("unsafe diagnostics changed: %q, %v", data, err)
	}
}
