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

package gvx

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func openEphemeralVolumeFile(dir string) (*os.File, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for range 8 {
		token, err := randomEphemeralToken()
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, ephemeralStagingPrefix+token+ext4VolumeSuffix)
		pathPtr, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return nil, err
		}
		h, err := windows.CreateFile(
			pathPtr,
			windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE,
			0,
			nil,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_DELETE_ON_CLOSE,
			0,
		)
		if errors.Is(err, windows.ERROR_FILE_EXISTS) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(h), path), nil
	}
	return nil, errors.New("exhausted retries allocating unique ephemeral volume file")
}
