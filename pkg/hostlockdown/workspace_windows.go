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

package hostlockdown

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// lowLabelDirSDDL labels a directory Low with no-write-up and makes new
	// children inherit the label. LW is the Low mandatory level alias.
	lowLabelDirSDDL = "S:(ML;OICI;NW;;;LW)"
	// lowLabelFileSDDL labels a file Low. Files do not carry inherit flags.
	lowLabelFileSDDL = "S:(ML;;NW;;;LW)"

	aceTypeMandatoryLabel = 0x11 // SYSTEM_MANDATORY_LABEL_ACE_TYPE

	// fileDeleteChild is FILE_DELETE_CHILD. Directory rename and unlink need it.
	fileDeleteChild = 0x40
)

// workspaceAccessMask returns the rights that the logon SID needs on workspace
// objects. The restricted token evaluates them in addition to the user rights.
func workspaceAccessMask(readOnly bool) windows.ACCESS_MASK {
	mask := windows.ACCESS_MASK(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_EXECUTE)
	if !readOnly {
		mask |= windows.FILE_GENERIC_WRITE | windows.DELETE | fileDeleteChild
	}
	return mask
}

// workspaceGrant describes what step 1 installs on each workspace object.
type workspaceGrant struct {
	logon    *windows.SID
	mask     windows.ACCESS_MASK
	readOnly bool
}

// prepareWorkspace applies step 1. For a writable workspace it labels every
// object Low so MIC permits guest writes after the token downgrade. For every
// workspace it grants the logon SID access so the restricted thread token
// passes its second access evaluation.
//
// A file mount (isFile) labels and grants that one file with no inheritance
// flags. The parent directory and the sibling files keep their security
// descriptors, so the restricted token cannot reach them by path.
//
// For a directory, SetNamedSecurityInfo propagates inheritable ACEs to
// existing children. The walk then verifies every object and repairs the ones
// that keep a protected ACL. The walk skips symbolic links and junctions, so
// it never changes a target outside the workspace.
func prepareWorkspace(path string, logon *windows.SID, readOnly, isFile bool) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("hostlockdown: resolve workspace %q: %w", path, err)
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return fmt.Errorf("hostlockdown: resolve workspace symlinks %q: %w", abs, err)
	}
	grant := workspaceGrant{logon: logon, mask: workspaceAccessMask(readOnly), readOnly: readOnly}
	if isFile {
		return grant.apply(root, false)
	}
	if err := grant.apply(root, true); err != nil {
		return err
	}
	return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("hostlockdown: walk workspace %q: %w", p, err)
		}
		if p == root || d.Type()&(fs.ModeSymlink|fs.ModeIrregular) != 0 {
			return nil
		}
		return grant.apply(p, d.IsDir())
	})
}

// apply makes path carry the label and the logon ACE. A directory gets
// inheritable entries so that new children inherit them.
func (g workspaceGrant) apply(path string, isDir bool) error {
	state, err := g.read(path, isDir)
	if err != nil {
		return err
	}
	if state.complete() {
		return nil
	}
	if !g.readOnly && !state.labeled {
		if err := setLowLabel(path, isDir); err != nil {
			return err
		}
	}
	if !state.granted {
		if err := g.addLogonACE(path, isDir, state.dacl); err != nil {
			return err
		}
	}
	state, err = g.read(path, isDir)
	if err != nil {
		return err
	}
	if !state.complete() {
		return fmt.Errorf("hostlockdown: workspace object %q still lacks the Low label or the logon SID entry after update", path)
	}
	return nil
}

type objectState struct {
	labeled bool
	granted bool
	dacl    *windows.ACL
}

func (s objectState) complete() bool { return s.labeled && s.granted }

// read queries the mandatory label and the DACL of path. When the workspace is
// read-only, the label counts as present because step 1 does not write it.
func (g workspaceGrant) read(path string, isDir bool) (objectState, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.LABEL_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return objectState{}, fmt.Errorf("hostlockdown: GetNamedSecurityInfo %q: %w", path, err)
	}
	st := objectState{labeled: g.readOnly}
	if sd == nil {
		// An object without a descriptor allows every access.
		st.granted = true
		return st, nil
	}
	if !g.readOnly {
		sacl, _, saclErr := sd.SACL()
		switch {
		case saclErr == nil:
			st.labeled = hasLowLabel(sacl, isDir)
		case !errors.Is(saclErr, windows.ERROR_OBJECT_NOT_FOUND):
			return objectState{}, fmt.Errorf("hostlockdown: read label of %q: %w", path, saclErr)
		}
	}
	dacl, _, daclErr := sd.DACL()
	switch {
	case daclErr == nil && dacl == nil, errors.Is(daclErr, windows.ERROR_OBJECT_NOT_FOUND):
		// A NULL DACL or an absent DACL allows every access.
		st.granted = true
	case daclErr != nil:
		return objectState{}, fmt.Errorf("hostlockdown: read DACL of %q: %w", path, daclErr)
	default:
		st.dacl = dacl
		st.granted = grantsAccess(dacl, g.logon, g.mask)
	}
	return st, nil
}

// addLogonACE grants the current logon SID access. The same update revokes
// entries of earlier logon sessions: their SIDs never match again, so they
// would only pile up in the workspace ACLs.
func (g workspaceGrant) addLogonACE(path string, isDir bool, current *windows.ACL) error {
	inherit := uint32(windows.NO_INHERITANCE)
	if isDir {
		inherit = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	// TrusteeValue holds a raw SID address, so the SIDs stay pinned until the
	// ACL is built.
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(g.logon)
	entries := []windows.EXPLICIT_ACCESS{sidEntry(g.logon, g.mask, windows.GRANT_ACCESS, inherit)}
	for _, stale := range staleLogonSIDs(current, g.logon) {
		pin.Pin(stale)
		entries = append(entries, sidEntry(stale, 0, windows.REVOKE_ACCESS, windows.NO_INHERITANCE))
	}
	merged, err := windows.ACLFromEntries(entries, current)
	if err != nil {
		return fmt.Errorf("hostlockdown: build DACL for %q: %w", path, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, merged, nil); err != nil {
		return fmt.Errorf("hostlockdown: SetNamedSecurityInfo(DACL) %q: %w", path, err)
	}
	return nil
}

func sidEntry(sid *windows.SID, mask windows.ACCESS_MASK, mode windows.ACCESS_MODE, inherit uint32) windows.EXPLICIT_ACCESS {
	return windows.EXPLICIT_ACCESS{
		AccessPermissions: mask,
		AccessMode:        mode,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_UNKNOWN,
			TrusteeValue: windows.TrusteeValueFromSID(sid),
		},
	}
}

// isLogonSessionSID reports whether sid has the form S-1-5-5-X-Y of a logon
// session SID (SECURITY_LOGON_IDS_RID).
func isLogonSessionSID(sid *windows.SID) bool {
	return sid != nil && sid.IsValid() &&
		sid.IdentifierAuthority() == windows.SECURITY_NT_AUTHORITY &&
		sid.SubAuthorityCount() == 3 && sid.SubAuthority(0) == securityLogonIDsRID
}

// securityLogonIDsRID is SECURITY_LOGON_IDS_RID, the first sub-authority of
// every logon session SID.
const securityLogonIDsRID = 5

// staleLogonSIDs returns the logon session SIDs in dacl other than current.
func staleLogonSIDs(dacl *windows.ACL, current *windows.SID) []*windows.SID {
	if dacl == nil {
		return nil
	}
	var stale []*windows.SID
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return stale
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if isLogonSessionSID(sid) && !sid.Equals(current) && !containsSID(stale, sid) {
			stale = append(stale, sid)
		}
	}
	return stale
}

func containsSID(list []*windows.SID, sid *windows.SID) bool {
	for _, s := range list {
		if s.Equals(sid) {
			return true
		}
	}
	return false
}

func setLowLabel(path string, isDir bool) error {
	sddl := lowLabelFileSDDL
	if isDir {
		sddl = lowLabelDirSDDL
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("hostlockdown: parse label SDDL %q: %w", sddl, err)
	}
	sacl, _, err := sd.SACL()
	if err != nil {
		return fmt.Errorf("hostlockdown: label SACL from %q: %w", sddl, err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.LABEL_SECURITY_INFORMATION, nil, nil, nil, sacl); err != nil {
		return fmt.Errorf("hostlockdown: SetNamedSecurityInfo(label) %q: %w", path, err)
	}
	return nil
}

// grantsAccess reports whether the allow entries for sid that apply to the
// object itself cover mask together.
func grantsAccess(dacl *windows.ACL, sid *windows.SID, mask windows.ACCESS_MASK) bool {
	var granted windows.ACCESS_MASK
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return false
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(sid) {
			granted |= ace.Mask
		}
	}
	return granted&mask == mask
}

// hasLowLabel reports whether sacl holds a Low mandatory label. A directory
// label must also be inheritable by new files and subdirectories.
func hasLowLabel(sacl *windows.ACL, isDir bool) bool {
	if sacl == nil {
		return false
	}
	for i := uint32(0); i < uint32(sacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(sacl, i, &ace); err != nil {
			return false
		}
		if ace.Header.AceType != aceTypeMandatoryLabel {
			continue
		}
		if !isLowIntegritySID((*windows.SID)(unsafe.Pointer(&ace.SidStart))) {
			continue
		}
		const inheritBoth = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
		if !isDir || ace.Header.AceFlags&inheritBoth == inheritBoth {
			return true
		}
	}
	return false
}
