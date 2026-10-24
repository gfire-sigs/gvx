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

//go:build darwin || windows

package hostfs

import (
	"errors"
	"io/fs"
	"strings"
)

// probeResolves reports whether the host resolves name to an entry. An entry
// that the host finds under another case counts as found. The second result is
// false when the lookup failed for another reason.
func probeResolves(host hostBackend, name string) (found, ok bool) {
	_, err := host.lstat(name)
	switch {
	case err == nil, errors.Is(err, errNameMismatch):
		return true, true
	case errors.Is(err, fs.ErrNotExist):
		return false, true
	}
	return false, false
}

// probeFoldsCase reports whether the volume of the workspace root treats names
// that differ in case as one name. A writable workspace creates a temporary
// probe file. A read-only workspace compares a name of an existing entry with
// its upper-case form. The second result is false when the probe cannot tell.
func probeFoldsCase(host hostBackend, readOnly bool) (folds, ok bool) {
	if readOnly {
		entries, err := host.readDir(".")
		if err != nil {
			return false, false
		}
		for _, e := range entries {
			variant := strings.ToUpper(e.name)
			if variant == e.name {
				variant = strings.ToLower(e.name)
			}
			if variant == e.name {
				continue
			}
			return probeResolves(host, variant)
		}
		return false, false
	}
	name := probeBase() + "q"
	_, remove, err := createProbeFile(host, name)
	if err != nil {
		return false, false
	}
	defer remove()
	return probeResolves(host, strings.ToUpper(name))
}

// probeNormalizes reports whether the volume treats the NFC and NFD forms of a
// name as one name. It needs a writable workspace and returns false for ok
// otherwise.
func probeNormalizes(host hostBackend, readOnly bool) (normalizes, ok bool) {
	if readOnly {
		return false, false
	}
	base := probeBase()
	_, remove, err := createProbeFile(host, base+"\u00e9")
	if err != nil {
		return false, false
	}
	defer remove()
	return probeResolves(host, base+"e\u0301")
}
