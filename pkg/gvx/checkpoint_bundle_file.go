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
)

// openBundleFile opens the file name of the checkpoint bundle in dir. The
// file must be a regular file, or absent when flag has os.O_CREATE.
//
// A bundle is untrusted input. A symbolic link in it could redirect a read or
// a write of the host process to another host file, and a FIFO could block
// the open call. The function reads the type of the entry before it opens the
// entry. It opens the entry through an os.Root, so a name that another
// process replaces between the two steps cannot leave dir.
func openBundleFile(dir, name string, flag int, perm os.FileMode) (*os.File, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()

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
