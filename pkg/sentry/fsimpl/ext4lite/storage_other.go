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

//go:build !linux && !darwin && !windows

package ext4lite

import (
	"errors"
	"os"
)

// platformTier is the only tier that this operating system offers. No
// preallocation call is available, so the file grows with ftruncate.
const platformTier = tierFallback

// lockFile does nothing on this operating system. No portable lock call is
// available, so two sandboxes that mount the same file are not detected.
func lockFile(*os.File) error { return nil }

// unlockFile does nothing, as lockFile does nothing.
func unlockFile(*os.File) error { return nil }

// availBytes reports that this operating system has no free-space call that
// works on a handle.
func availBytes(*os.File) (uint64, error) {
	return 0, errors.ErrUnsupported
}

// osNativeGrow is never called, because platformTier is tierFallback. It
// exists so that nativeGrow has a default value.
func osNativeGrow(*os.File, int64, int64) error {
	return errors.ErrUnsupported
}

// nativeUnsupported reports whether err means that the host volume does not
// support preallocation.
func nativeUnsupported(err error) bool {
	return errors.Is(err, errors.ErrUnsupported)
}
