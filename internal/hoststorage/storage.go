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

// Package hoststorage validates opens and identities of host storage objects.
package hoststorage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrUnsupported reports that the host cannot enforce storage isolation.
var ErrUnsupported = errors.New("host storage isolation is not supported")

// StorageIdentity identifies an opened object and its mount.
type StorageIdentity struct {
	Volume uint64
	Mount  uint64
	File   [2]uint64
	Links  uint32
}

// SameFile reports whether i and other identify the same filesystem object.
func (i StorageIdentity) SameFile(other StorageIdentity) bool {
	return i.Volume == other.Volume && i.File == other.File
}

// SameMount reports whether i and other lie on the same mount.
func (i StorageIdentity) SameMount(other StorageIdentity) bool {
	return i.Volume == other.Volume && i.Mount == other.Mount
}

// StorageVolumesDisjoint reports whether distinct mounts can share storage.
// Callers compare ancestry instead when both directories are on one mount.
func StorageVolumesDisjoint(a, b *os.File, aID, bID StorageIdentity) bool {
	return aID.Volume != bID.Volume && storageVolumesDisjoint(a, b)
}

// IdentifyStorage inspects the open descriptor, not its name.
func IdentifyStorage(f *os.File) (StorageIdentity, error) {
	return storageFileIdentity(f)
}

// VerifyStorageFile requires an opened regular file with exactly one link.
func VerifyStorageFile(f *os.File) (StorageIdentity, error) {
	info, err := f.Stat()
	if err != nil {
		return StorageIdentity{}, err
	}
	id, err := IdentifyStorage(f)
	if err != nil {
		return StorageIdentity{}, err
	}
	if !info.Mode().IsRegular() || id.Links != 1 {
		return StorageIdentity{}, fmt.Errorf("%q is not a single-link regular file", f.Name())
	}
	return id, nil
}

// StatStorageFile reads the identity of one regular, single-link child without
// following links or referring to its parent by path.
func StatStorageFile(dir *os.File, name string) (StorageIdentity, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return StorageIdentity{}, os.ErrInvalid
	}
	id, err := statStorageFile(dir, name)
	if err != nil {
		return StorageIdentity{}, err
	}
	parentID, err := IdentifyStorage(dir)
	if err != nil {
		return StorageIdentity{}, err
	}
	if id.Links != 1 || !parentID.SameMount(id) {
		return StorageIdentity{}, fmt.Errorf("%q is not a single-link file on the same mount", name)
	}
	return id, nil
}

// OpenStorageFile opens one regular file under dir. It never truncates the
// entry and never follows a symbolic link, reparse point, or mount transition.
func OpenStorageFile(dir *os.File, name string, flags int, perm os.FileMode) (*os.File, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." || flags&os.O_TRUNC != 0 {
		return nil, os.ErrInvalid
	}
	f, err := openStorageFile(dir, name, flags, perm)
	if err != nil {
		return nil, err
	}
	parentID, err := IdentifyStorage(dir)
	if err == nil {
		var id StorageIdentity
		id, err = VerifyStorageFile(f)
		if err == nil && !parentID.SameMount(id) {
			err = fmt.Errorf("%q crosses a mount boundary", name)
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return f, nil
}

// OpenStorageDir opens one child directory on the same mount as dir.
func OpenStorageDir(dir *os.File, name string, create bool, perm os.FileMode) (*os.File, error) {
	if !filepath.IsLocal(name) || filepath.Base(name) != name || name == "." {
		return nil, os.ErrInvalid
	}
	child, err := openStorageDir(dir, name, create, perm)
	if err != nil {
		return nil, err
	}
	parentID, err := IdentifyStorage(dir)
	if err == nil {
		var childID StorageIdentity
		childID, err = IdentifyStorage(child)
		if err == nil && !parentID.SameMount(childID) {
			err = fmt.Errorf("%q crosses a mount boundary", name)
		}
	}
	if err != nil {
		_ = child.Close()
		return nil, err
	}
	return child, nil
}

// StorageAncestry returns the opened directory's identity and its ancestors
// on the same mount.
func StorageAncestry(dir *os.File) ([]StorageIdentity, error) {
	id, err := IdentifyStorage(dir)
	if err != nil {
		return nil, err
	}
	ids := []StorageIdentity{id}
	for cur := dir; ; {
		parent, err := storageParent(cur)
		if cur != dir {
			_ = cur.Close()
		}
		if err != nil {
			return nil, err
		}
		if parent == nil {
			return ids, nil
		}
		next, err := IdentifyStorage(parent)
		if err != nil {
			_ = parent.Close()
			return nil, err
		}
		if !id.SameMount(next) || id.SameFile(next) {
			_ = parent.Close()
			return ids, nil
		}
		ids = append(ids, next)
		cur, id = parent, next
	}
}
