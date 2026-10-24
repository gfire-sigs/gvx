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

package hostfs

import (
	"io"
	"os"
	"strings"
)

const (
	// appleDoubleMaxSize is the largest size of an AppleDouble file that
	// hostfs treats as host clutter.
	appleDoubleMaxSize = 64 << 10

	// appleDoublePrefix starts the name of an AppleDouble file.
	appleDoublePrefix = "._"

	dsStoreName   = ".DS_Store"
	thumbsDBName  = "Thumbs.db"
	hostOSDarwin  = "darwin"
	hostOSWindows = "windows"
)

// appleDoubleMagic is the first four bytes of an AppleDouble file.
var appleDoubleMagic = [4]byte{0x00, 0x05, 0x16, 0x07}

// clutterRules selects the files that the desktop shell of the host writes
// into a directory and that the guest must not see.
type clutterRules struct {
	// dsStore hides .DS_Store files of Finder.
	dsStore bool
	// appleDouble hides ._ files that hold AppleDouble data.
	appleDouble bool
	// thumbsDB hides Thumbs.db files of Explorer.
	thumbsDB bool
}

// clutterRulesFor returns the rules of the host operating system goos, in the
// form of runtime.GOOS.
func clutterRulesFor(goos string) clutterRules {
	switch goos {
	case hostOSDarwin:
		return clutterRules{dsStore: true, appleDouble: true}
	case hostOSWindows:
		return clutterRules{thumbsDB: true}
	}
	return clutterRules{}
}

// candidate reports whether the name can be host clutter. It needs no host
// call.
func (r clutterRules) candidate(leaf string) bool {
	switch {
	case r.dsStore && leaf == dsStoreName:
		return true
	case r.thumbsDB && strings.EqualFold(leaf, thumbsDBName):
		return true
	case r.appleDouble && len(leaf) > len(appleDoublePrefix) && strings.HasPrefix(leaf, appleDoublePrefix):
		return true
	}
	return false
}

// needsContent reports whether the verdict for the name depends on the size
// and the content of the file.
func (r clutterRules) needsContent(leaf string) bool {
	return r.appleDouble && strings.HasPrefix(leaf, appleDoublePrefix)
}

// isClutterLocked reports whether the host entry leaf in the directory dirRel
// is host clutter that .gvx_meta does not own. A zero info.kind means that the
// caller cannot read the entry, for example after a delete event. The verdict
// then follows the name. A directory is never clutter, and the check returns
// before it reads .gvx_meta, so a pin open that holds no lock stays safe.
// Callers hold w.mu, except for a call with a non-regular, known kind.
func (w *Workspace) isClutterLocked(dirRel, leaf string, info hostInfo) bool {
	if !w.clutter.candidate(leaf) {
		return false
	}
	if info.kind != 0 && info.kind != hostKindRegular {
		return false
	}
	if _, owned := w.meta[joinRelPath(dirRel, w.codec.ToGuest(leaf))]; owned {
		return false
	}
	if info.kind == 0 {
		return true
	}
	if !w.clutter.needsContent(leaf) {
		return true
	}
	return info.size <= appleDoubleMaxSize && w.hasAppleDoubleMagic(dirRel, leaf)
}

// hasAppleDoubleMagic reads the first four bytes of the file leaf in the
// directory dirRel. A failed read means that the file is not clutter.
func (w *Workspace) hasAppleDoubleMagic(dirRel, leaf string) bool {
	hostDir, err := w.hostPath(dirRel)
	if err != nil {
		return false
	}
	f, err := w.host.open(hostChild(hostDir, leaf), os.O_RDONLY, 0)
	if err != nil {
		return false
	}
	defer func() {
		_ = f.Close()
	}()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic == appleDoubleMagic
}

// isHostClutter reports whether the guest must not see the host entry
// hostName of the directory dirRel. The path dirRel is the guest path of the
// directory. The verdict covers host shell clutter, the internal hostfs names,
// and host names that start with the codec prefix but that the codec never
// writes. A zero info.kind decides by name. The method takes w.mu, so callers
// must not hold it.
func (w *Workspace) isHostClutter(dirRel, hostName string, info hostInfo) bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return false
	}
	return w.isHiddenLocked(dirRel, hostName, info)
}

// hostVisibleName returns the guest name of the host entry hostName in the
// directory dirRel, and false when the guest must not see the entry. The
// method takes w.mu, so callers must not hold it.
func (w *Workspace) hostVisibleName(dirRel, hostName string, info hostInfo) (string, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed || w.isHiddenLocked(dirRel, hostName, info) {
		return "", false
	}
	return w.listName(dirRel, hostName), true
}

// purgeEmptyDirLocked prepares the removal of the directory rel, which the
// host stores at the path hostDir. It fails with errNotEmpty when the guest
// sees an entry in the directory. Otherwise it unlinks the verified host
// clutter files, so that the host removal does not fail with ENOTEMPTY.
// Callers hold w.mu for writing.
func (w *Workspace) purgeEmptyDirLocked(rel, hostDir string) error {
	visible, clutter, err := w.listDirLocked(rel)
	if err != nil {
		return err
	}
	if len(visible) > 0 {
		return errNotEmpty
	}
	for _, leaf := range clutter {
		if err := w.host.unlink(hostChild(hostDir, leaf)); err != nil && !isNotExist(err) {
			return err
		}
	}
	return nil
}
