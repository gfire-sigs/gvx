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

package gvx

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"z.gfire.dev/gvx/internal/hoststorage"
)

type bundleRoot struct {
	path       string
	root       *os.Root
	dir        *os.File
	identities []hoststorage.StorageIdentity
}

func openBundleRoot(path string, isolated bool) (*bundleRoot, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	if !isolated {
		return &bundleRoot{path: path, root: root}, nil
	}
	dir, err := root.Open(".")
	if err := errors.Join(err, root.Close()); err != nil {
		if dir != nil {
			err = errors.Join(err, dir.Close())
		}
		return nil, err
	}
	return &bundleRoot{path: path, dir: dir}, nil
}

func (b *bundleRoot) Close() error {
	if b.dir != nil {
		return b.dir.Close()
	}
	return b.root.Close()
}

func (b *bundleRoot) openFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if b.dir != nil {
		f, err := hoststorage.OpenStorageFile(b.dir, name, flag, perm)
		if err != nil {
			return nil, err
		}
		id, err := hoststorage.VerifyStorageFile(f)
		if err != nil {
			return nil, errors.Join(err, f.Close())
		}
		b.identities = append(b.identities, id)
		return f, nil
	}
	root := b.root

	// Reject special files before opening. The OS root confines the open to
	// this bundle even if the entry changes after the type inspection.

	info, err := root.Lstat(name)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file (mode %v)", name, info.Mode())
		}
	case flag&os.O_CREATE != 0 && errors.Is(err, fs.ErrNotExist):
	default:
		return nil, err
	}
	f, err := root.OpenFile(name, flag, perm)
	if err != nil {
		return nil, err
	}
	info, err = f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file (mode %v)", name, info.Mode())
	}
	return f, nil
}
