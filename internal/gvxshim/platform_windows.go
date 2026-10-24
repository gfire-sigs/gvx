package gvxshim

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
)

func currentOwner() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String(), nil
}

func protectedDACL() (string, error) {
	owner, err := currentOwner()
	if err != nil {
		return "", err
	}
	acl := "D:P(A;;GA;;;" + owner + ")"
	if owner != "S-1-5-18" {
		acl += "(A;;GA;;;SY)"
	}
	return acl, nil
}

func normalizeContainerdAddress(address string) (string, error) {
	address = strings.TrimPrefix(address, "npipe://")
	address = strings.ReplaceAll(address, "/", `\`)
	if !strings.HasPrefix(strings.ToLower(address), `\\.\pipe\`) || strings.ContainsRune(address, 0) {
		return "", errUnsafeEntry
	}
	name := address[len(`\\.\pipe\`):]
	if !validComponent(name) {
		return "", errUnsafeEntry
	}
	return `\\.\pipe\` + name, nil
}

func platformAddresses(id instanceIdentity, key string) (string, string, error) {
	return `\\.\pipe\gvx-shim-` + key + "-task", `\\.\pipe\gvx-shim-` + key + "-stop", nil
}

func windowsPathError(op, name string, err error) error {
	var status windows.NTStatus
	if errors.As(err, &status) {
		err = status.Errno()
	}
	return &os.PathError{Op: op, Path: name, Err: err}
}

func platformOpenInitial(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, windowsPathError("open", path, err)
	}
	return os.NewFile(uintptr(h), path), nil
}

func nativeRelative(dir *pinnedDir, name string, access, disposition, options uint32, create bool) (*os.File, error) {
	if !validComponent(name) {
		return nil, errUnsafeEntry
	}
	unicode, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	oa := windows.OBJECT_ATTRIBUTES{RootDirectory: windows.Handle(dir.Handle.Fd()), ObjectName: unicode, Attributes: windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE}
	oa.Length = uint32(unsafe.Sizeof(oa))
	if create {
		sddl, err := protectedDACL()
		if err != nil {
			return nil, err
		}
		owner, err := currentOwner()
		if err != nil {
			return nil, err
		}
		oa.SecurityDescriptor, err = windows.SecurityDescriptorFromString("O:" + owner + sddl)
		if err != nil {
			return nil, err
		}
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	// Metadata validation also needs FILE_READ_ATTRIBUTES on write-only and append-only handles.
	err = windows.NtCreateFile(&h, access|windows.SYNCHRONIZE|windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES, &oa, &iosb, nil, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, disposition, options|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT, 0, 0)
	runtime.KeepAlive(oa)
	if err != nil {
		return nil, windowsPathError("NtCreateFile", name, err)
	}
	return os.NewFile(uintptr(h), name), nil
}

func platformOpenRelative(dir *pinnedDir, name string, flags int, perm os.FileMode, directory bool) (*os.File, error) {
	access := uint32(windows.FILE_GENERIC_READ)
	if flags&os.O_RDWR != 0 {
		access |= windows.FILE_GENERIC_WRITE
	} else if flags&os.O_WRONLY != 0 {
		access = windows.FILE_GENERIC_WRITE
	}
	if flags&os.O_APPEND != 0 {
		access &^= windows.FILE_WRITE_DATA
		access |= windows.FILE_APPEND_DATA
	}
	disposition := uint32(windows.FILE_OPEN)
	if flags&os.O_CREATE != 0 {
		disposition = windows.FILE_OPEN_IF
	}
	if flags&os.O_EXCL != 0 {
		disposition = windows.FILE_CREATE
		access |= windows.DELETE
	}
	options := uint32(windows.FILE_NON_DIRECTORY_FILE)
	if directory {
		options = windows.FILE_DIRECTORY_FILE
	}
	f, err := nativeRelative(dir, name, access, disposition, options, flags&os.O_CREATE != 0)
	if err != nil {
		return nil, err
	}
	if disposition == windows.FILE_CREATE {
		kind := regularEntry
		if directory {
			kind = directoryEntry
		}
		if _, err := validateFile(f, kind, true); err != nil {
			// FILE_CREATE proves ownership; delete through that handle, not a potentially replaced path.
			var remove byte = 1
			removeErr := windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &remove, 1)
			return nil, errors.Join(err, removeErr, f.Close())
		}
	}
	return f, nil
}

func platformMkdir(dir *pinnedDir, name string) error {
	f, err := nativeRelative(dir, name, windows.FILE_GENERIC_READ|windows.FILE_GENERIC_WRITE, windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE, true)
	if err != nil {
		return err
	}
	return f.Close()
}

func windowsFileIdentity(file *os.File) (fileIdentity, error) {
	var id fileIdentity
	if err := windows.GetFileInformationByHandleEx(windows.Handle(file.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return fileIdentity{}, err
	}
	return id, nil
}

func platformRootIdentity(root *os.Root) (fileIdentity, error) {
	f, err := root.Open(".")
	if err != nil {
		return fileIdentity{}, err
	}
	id, err := windowsFileIdentity(f)
	return id, errors.Join(err, f.Close())
}

func platformValidateInfo(info os.FileInfo, kind entryKind, private bool) error {
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return errUnsafeEntry
	}
	if kind == regularEntry && info.Mode().IsRegular() || kind == directoryEntry && info.IsDir() {
		return nil
	}
	return errUnsafeEntry
}

func validateWindowsSecurity(file *os.File, private bool) error {
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	current, err := currentOwner()
	if err != nil {
		return err
	}
	if owner == nil || owner.String() != current {
		return errUnsafeEntry
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if private && control&windows.SE_DACL_PROTECTED == 0 {
		return errUnsafeEntry
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		return errors.Join(errUnsafeEntry, err)
	}
	type aclHeader struct {
		Revision  byte
		Reserved  byte
		Size      uint16
		Count     uint16
		Reserved2 uint16
	}
	count := (*aclHeader)(unsafe.Pointer(acl)).Count
	if private && ((current == "S-1-5-18" && count != 1) || (current != "S-1-5-18" && count != 2)) {
		return errUnsafeEntry
	}
	var userAllowed, systemAllowed bool
	for index := range uint32(count) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, index, &ace); err != nil {
			return err
		}
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE && !private {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return errUnsafeEntry
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if private && (ace.Header.AceFlags != 0 || (uint32(ace.Mask) != windows.GENERIC_ALL && uint32(ace.Mask) != 0x001f01ff)) {
			return errUnsafeEntry
		}
		if sid == current {
			if private && userAllowed {
				return errUnsafeEntry
			}
			if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE == 0 {
				userAllowed = true
			}
			continue
		}
		if sid == "S-1-5-18" {
			if private && systemAllowed {
				return errUnsafeEntry
			}
			systemAllowed = true
			continue
		}
		if !private && sid == "S-1-5-32-544" {
			continue
		}
		const fileDeleteChild = 0x00000040
		const mutable = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | fileDeleteChild
		if private || uint32(ace.Mask)&mutable != 0 {
			return errUnsafeEntry
		}
	}
	if !userAllowed || (private && current != "S-1-5-18" && !systemAllowed) {
		return errUnsafeEntry
	}
	return nil
}

func validateFile(file *os.File, kind entryKind, private bool) (fileIdentity, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return fileIdentity{}, err
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fileIdentity{}, errUnsafeEntry
	}
	isDir := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if kind != regularEntry && kind != directoryEntry || kind == directoryEntry && !isDir || kind == regularEntry && (isDir || info.NumberOfLinks != 1) {
		return fileIdentity{}, errUnsafeEntry
	}
	if private {
		if err := validateWindowsSecurity(file, true); err != nil {
			return fileIdentity{}, err
		}
	}
	return windowsFileIdentity(file)
}

func validateBundle(file *os.File) error { return validateWindowsSecurity(file, false) }

func platformEntryIdentity(dir *pinnedDir, name string, info os.FileInfo, kind entryKind) (fileIdentity, error) {
	f, err := platformOpenRelative(dir, name, os.O_RDONLY, 0, kind == directoryEntry)
	if err != nil {
		return fileIdentity{}, err
	}
	id, err := validateFile(f, kind, true)
	return id, errors.Join(err, f.Close())
}

func platformRemove(dir *pinnedDir, entry ownedEntry) error {
	options := uint32(windows.FILE_NON_DIRECTORY_FILE)
	if entry.Kind == directoryEntry {
		options = windows.FILE_DIRECTORY_FILE
	}
	f, err := nativeRelative(dir, entry.Name, windows.DELETE|windows.FILE_GENERIC_READ, windows.FILE_OPEN, options, false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	id, err := validateFile(f, entry.Kind, true)
	if err != nil || id != entry.Identity {
		return errors.Join(errPathChanged, err, f.Close())
	}
	var remove byte = 1
	err = windows.SetFileInformationByHandle(windows.Handle(f.Fd()), windows.FileDispositionInfo, &remove, 1)
	return errors.Join(err, f.Close())
}

func platformOpenEndpoints(ctx context.Context, p *instancePaths, mode pathMode) error {
	return ctx.Err()
}
func platformRevalidateEndpoints(p *instancePaths, expected pathSnapshot) error {
	if expected.UnixEndpointRoot != nil || expected.UnixEndpointDir != nil {
		return errPathChanged
	}
	return nil
}
func prepareEndpointDir(ctx context.Context, p *instancePaths) error  { return ctx.Err() }
func removeEndpointDir(p *instancePaths, expected fileIdentity) error { return errUnsafeEntry }

func tryLock(l *ownedLock) error {
	var overlapped windows.Overlapped
	err := windows.LockFileEx(windows.Handle(l.File.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
		return errLockBusy
	}
	return err
}
func unlock(l *ownedLock) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(l.File.Fd()), 0, 1, 0, &overlapped)
}

func configureChild(cmd *exec.Cmd) {
	const detachedProcess = 0x00000008
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: detachedProcess | windows.CREATE_NEW_PROCESS_GROUP, HideWindow: true}
}

func listenProtectedPipe(address string) (net.Listener, error) {
	normalized, err := normalizeContainerdAddress(address)
	if err != nil || normalized != address {
		return nil, errors.Join(errUnsafeEntry, err)
	}
	dacl, err := protectedDACL()
	if err != nil {
		return nil, err
	}
	return winio.ListenPipe(address, &winio.PipeConfig{SecurityDescriptor: dacl, MessageMode: false, InputBufferSize: 4096, OutputBufferSize: 4096})
}

func listenLocal(ctx context.Context, paths *instancePaths, kind endpointKind) (*ownedEndpoint, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := paths.Revalidate(paths.Snapshot); err != nil {
		return nil, err
	}
	address := paths.TaskAddress
	if kind == stopEndpoint {
		address = paths.StopAddress
	} else if kind != taskEndpoint {
		return nil, errUnsafeEntry
	}
	listener, err := listenProtectedPipe(address)
	if err != nil {
		return nil, err
	}
	return &ownedEndpoint{Listener: listener, Ref: endpointRef{Address: address}}, nil
}

func dialLocal(ctx context.Context, address string) (net.Conn, error) {
	normalized, err := normalizeContainerdAddress(address)
	if err != nil || normalized != address {
		return nil, errors.Join(errUnsafeEntry, err)
	}
	return winio.DialPipeContext(ctx, address)
}

var waitNamedPipe = windows.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")

func absentEndpoints(paths *instancePaths) error {
	for _, address := range []string{paths.TaskAddress, paths.StopAddress} {
		name, err := windows.UTF16PtrFromString(address)
		if err != nil {
			return err
		}
		available, _, callErr := waitNamedPipe.Call(uintptr(unsafe.Pointer(name)), 1)
		runtime.KeepAlive(name)
		if available != 0 || errors.Is(callErr, windows.ERROR_SEM_TIMEOUT) {
			return errUnsafeEntry
		}
		if !errors.Is(callErr, windows.ERROR_FILE_NOT_FOUND) {
			return windowsPathError("WaitNamedPipe", address, callErr)
		}
	}
	return nil
}
