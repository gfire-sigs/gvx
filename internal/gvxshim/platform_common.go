package gvxshim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var errUnsafeEntry = errors.New("unsafe filesystem entry")
var errLockBusy = errors.New("coordination lock is held")
var errPathChanged = errors.New("pinned filesystem identity changed")

func canonicalBundle(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Resolve only the parent. The bundle itself must not be a link.
	parent, err := filepath.EvalSymlinks(filepath.Dir(absolute))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(absolute)), nil
}

func validComponent(name string) bool {
	return name != "" && name != "." && name != ".." && !strings.ContainsAny(name, "/\\:\x00") && strings.TrimRight(name, ". ") == name && filepath.Base(name) == name
}
func pinInitial(path string, owned bool) (*pinnedDir, error) {
	h, err := platformOpenInitial(path)
	if err != nil {
		return nil, err
	}
	id, err := validateFile(h, directoryEntry, owned)
	if err != nil {
		return nil, errors.Join(err, h.Close())
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, errors.Join(err, h.Close())
	}
	p := &pinnedDir{Root: r, Handle: h, ID: id}
	if err := validatePinned(p, owned); err != nil {
		return nil, errors.Join(err, closePinned(p))
	}
	return p, nil
}

func pinChild(parent *pinnedDir, name string, private bool, create bool) (*pinnedDir, error) {
	if !validComponent(name) {
		return nil, errUnsafeEntry
	}
	if create {
		if err := platformMkdir(parent, name); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
	}
	h, err := platformOpenRelative(parent, name, os.O_RDONLY, 0, true)
	if err != nil {
		return nil, err
	}
	id, err := validateFile(h, directoryEntry, private)
	if err != nil {
		return nil, errors.Join(err, h.Close())
	}
	r, err := parent.Root.OpenRoot(name)
	if err != nil {
		return nil, errors.Join(err, h.Close())
	}
	p := &pinnedDir{Root: r, Handle: h, ID: id}
	if err := validatePinned(p, private); err != nil {
		return nil, errors.Join(err, closePinned(p))
	}
	return p, nil
}

func validatePinned(p *pinnedDir, private bool) error {
	if p == nil {
		return errPathChanged
	}
	id, err := validateFile(p.Handle, directoryEntry, private)
	if err != nil {
		return err
	}
	rootID, err := platformRootIdentity(p.Root)
	if err != nil {
		return err
	}
	if id != p.ID || rootID != p.ID {
		return errPathChanged
	}
	return nil
}

func verifyChild(parent *pinnedDir, name string, child *pinnedDir, private bool) error {
	if parent == nil {
		return errPathChanged
	}
	if child == nil {
		_, err := parent.Root.Lstat(name)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		return errPathChanged
	}
	if err := validatePinned(child, private); err != nil {
		return err
	}
	f, err := platformOpenRelative(parent, name, os.O_RDONLY, 0, true)
	if err != nil {
		return err
	}
	id, err := validateFile(f, directoryEntry, private)
	if err = errors.Join(err, f.Close()); err != nil {
		return err
	}
	if id != child.ID {
		return errPathChanged
	}
	return nil
}

func openPaths(ctx context.Context, id instanceIdentity, mode pathMode) (_ *instancePaths, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	owner, err := currentOwner()
	if err != nil {
		return nil, err
	}
	if id.Owner != owner || !filepath.IsAbs(id.Bundle) || filepath.Clean(id.Bundle) != id.Bundle {
		return nil, errUnsafeEntry
	}
	p := &instancePaths{Identity: id, BundleName: filepath.Base(id.Bundle)}
	defer func() {
		if err != nil {
			err = errors.Join(err, p.Close())
		}
	}()
	p.BundleParent, err = pinInitial(filepath.Dir(id.Bundle), false)
	if err != nil {
		return nil, err
	}
	p.Snapshot.BundleParent = p.BundleParent.ID
	p.TaskAddress, p.StopAddress, err = platformAddresses(id, endpointKey(id))
	if err != nil {
		return nil, err
	}
	p.Bundle, err = pinChild(p.BundleParent, p.BundleName, false, false)
	if errors.Is(err, os.ErrNotExist) && mode == inspectPaths {
		p.Bundle = nil
		if err = platformOpenEndpoints(ctx, p, mode); err != nil {
			return nil, err
		}
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	if err = validateBundle(p.Bundle.Handle); err != nil {
		return nil, err
	}
	p.Snapshot.Bundle = p.Bundle.ID
	p.State, err = pinChild(p.Bundle, ".gvx-shim", true, mode == createPaths)
	if errors.Is(err, os.ErrNotExist) && mode == inspectPaths {
		p.State = nil
		if err = platformOpenEndpoints(ctx, p, mode); err != nil {
			return nil, err
		}
		return p, nil
	}
	if err != nil {
		return nil, err
	}
	p.Snapshot.State = p.State.ID
	for _, name := range []string{"command.lock", "lease"} {
		flags := os.O_RDWR
		if mode == createPaths {
			flags |= os.O_CREATE
		}
		f, openErr := openPrivateFile(p.State, name, flags, 0600)
		if openErr != nil {
			return nil, openErr
		}
		identity, identityErr := validateFile(f, regularEntry, true)
		if err = errors.Join(identityErr, f.Close()); err != nil {
			return nil, err
		}
		if name == "command.lock" {
			p.Snapshot.CommandLock = identity
		} else {
			p.Snapshot.Lease = identity
		}
	}
	if err = platformOpenEndpoints(ctx, p, mode); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *instancePaths) Revalidate(expected pathSnapshot) error {
	if p.Snapshot != expectedSnapshotWithoutPointers(expected, p.Snapshot) {
		return errPathChanged
	}
	if err := validatePinned(p.BundleParent, false); err != nil {
		return err
	}
	if p.BundleParent.ID != expected.BundleParent {
		return errPathChanged
	}
	if err := verifyChild(p.BundleParent, p.BundleName, p.Bundle, false); err != nil {
		return err
	}
	if p.Bundle == nil {
		return platformRevalidateEndpoints(p, expected)
	}
	if p.Bundle.ID != expected.Bundle {
		return errPathChanged
	}
	if err := validateBundle(p.Bundle.Handle); err != nil {
		return err
	}
	if err := verifyChild(p.Bundle, ".gvx-shim", p.State, true); err != nil {
		return err
	}
	if p.State == nil {
		return platformRevalidateEndpoints(p, expected)
	}
	if p.State.ID != expected.State {
		return errPathChanged
	}
	for _, item := range []struct {
		name string
		id   fileIdentity
	}{{"command.lock", expected.CommandLock}, {"lease", expected.Lease}} {
		ref, err := inspectEntry(p.State, item.name, regularEntry)
		if err != nil {
			return err
		}
		if ref.Identity != item.id {
			return errPathChanged
		}
	}
	return platformRevalidateEndpoints(p, expected)
}

func expectedSnapshotWithoutPointers(expected, actual pathSnapshot) pathSnapshot {
	if (expected.UnixEndpointRoot == nil) != (actual.UnixEndpointRoot == nil) || (expected.UnixEndpointDir == nil) != (actual.UnixEndpointDir == nil) {
		return expected
	}
	if expected.UnixEndpointRoot != nil && *expected.UnixEndpointRoot == *actual.UnixEndpointRoot {
		expected.UnixEndpointRoot = actual.UnixEndpointRoot
	}
	if expected.UnixEndpointDir != nil && *expected.UnixEndpointDir == *actual.UnixEndpointDir {
		expected.UnixEndpointDir = actual.UnixEndpointDir
	}
	return expected
}

func closePinned(p *pinnedDir) error {
	if p == nil {
		return nil
	}
	return errors.Join(p.Root.Close(), p.Handle.Close())
}

func (p *instancePaths) Close() error {
	if p == nil {
		return nil
	}
	return errors.Join(closePinned(p.UnixEndpointDir), closePinned(p.UnixEndpointRoot), closePinned(p.State), closePinned(p.Bundle), closePinned(p.BundleParent))
}

func inspectEntry(dir *pinnedDir, name string, kind entryKind) (ownedEntry, error) {
	if dir == nil || !validComponent(name) {
		return ownedEntry{}, errUnsafeEntry
	}
	info, err := dir.Root.Lstat(name)
	if err != nil {
		return ownedEntry{}, err
	}
	if err := platformValidateInfo(info, kind, true); err != nil {
		return ownedEntry{}, err
	}
	id, err := platformEntryIdentity(dir, name, info, kind)
	if err != nil {
		return ownedEntry{}, err
	}
	return ownedEntry{Name: name, Kind: kind, Identity: id}, nil
}

func openPrivateFile(dir *pinnedDir, name string, flags int, perm os.FileMode) (*os.File, error) {
	if dir == nil || !validComponent(name) {
		return nil, errUnsafeEntry
	}
	f, err := platformOpenRelative(dir, name, flags&^os.O_TRUNC, perm, false)
	if err != nil {
		return nil, err
	}
	if _, err := validateFile(f, regularEntry, true); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	// Truncate only the validated handle, never an unvalidated existing entry.
	if flags&os.O_TRUNC != 0 {
		if err := f.Truncate(0); err != nil {
			return nil, errors.Join(err, f.Close())
		}
	}
	return f, nil
}

func createRecordTemp(dir *pinnedDir) (*os.File, ownedEntry, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, ownedEntry{}, err
	}
	name := ".state-" + hex.EncodeToString(token[:])
	f, err := openPrivateFile(dir, name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, ownedEntry{}, err
	}
	id, err := validateFile(f, regularEntry, true)
	if err != nil {
		return nil, ownedEntry{}, errors.Join(err, f.Close())
	}
	return f, ownedEntry{Name: name, Kind: regularEntry, Identity: id}, nil
}

func createDiagnostics(paths *instancePaths) (*os.File, ownedEntry, error) {
	f, err := openPrivateFile(paths.State, "diagnostics.log", os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_APPEND, 0600)
	if err != nil {
		return nil, ownedEntry{}, err
	}
	id, err := validateFile(f, regularEntry, true)
	if err != nil {
		return nil, ownedEntry{}, errors.Join(err, f.Close())
	}
	return f, ownedEntry{Name: "diagnostics.log", Kind: regularEntry, Identity: id}, nil
}

func openLock(paths *instancePaths, name lockName) (*ownedLock, error) {
	filename, expected := "command.lock", paths.Snapshot.CommandLock
	if name == lifetimeLease {
		filename, expected = "lease", paths.Snapshot.Lease
	} else if name != commandLock {
		return nil, errUnsafeEntry
	}
	f, err := openPrivateFile(paths.State, filename, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	id, err := validateFile(f, regularEntry, true)
	if err != nil || id != expected {
		return nil, errors.Join(errPathChanged, err, f.Close())
	}
	return &ownedLock{File: f, Ref: ownedEntry{Name: filename, Kind: regularEntry, Identity: id}}, nil
}

func lock(ctx context.Context, l *ownedLock) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := tryLock(l)
		if !errors.Is(err, errLockBusy) {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (l *ownedLock) Close() error { return l.File.Close() }

func removeOwned(dir *pinnedDir, entry ownedEntry) error {
	if err := validatePinned(dir, true); err != nil {
		return err
	}
	actual, err := inspectEntry(dir, entry.Name, entry.Kind)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if actual != entry {
		return fmt.Errorf("remove %s: %w", entry.Name, errPathChanged)
	}
	return platformRemove(dir, entry)
}
