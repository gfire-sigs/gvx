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
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// lowIntegritySID is the Low mandatory label SID (SECURITY_MANDATORY_LOW_RID 0x1000).
	lowIntegritySID = "S-1-16-4096"
	lowIntegrityRID = 0x1000

	// disableMaxPrivilege is the CreateRestrictedToken flag DISABLE_MAX_PRIVILEGE.
	disableMaxPrivilege = 0x1
)

var (
	modAdvapi32               = windows.NewLazySystemDLL("advapi32.dll")
	procAdjustTokenPrivileges = modAdvapi32.NewProc("AdjustTokenPrivileges")
	procCreateRestrictedToken = modAdvapi32.NewProc("CreateRestrictedToken")
	procIsTokenRestricted     = modAdvapi32.NewProc("IsTokenRestricted")
)

// tokenIdentity holds the SIDs of the primary token that later steps need.
// Every SID points into a Go-heap buffer that these fields keep reachable.
type tokenIdentity struct {
	user   *windows.SID
	logon  *windows.SID
	groups []windows.SIDAndAttributes
}

func readTokenIdentity(token windows.Token) (*tokenIdentity, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("hostlockdown: GetTokenInformation(TokenUser): %w", err)
	}
	groups, err := token.GetTokenGroups()
	if err != nil {
		return nil, fmt.Errorf("hostlockdown: GetTokenInformation(TokenGroups): %w", err)
	}
	id := &tokenIdentity{
		user:   user.User.Sid,
		groups: groups.AllGroups(),
	}
	logon, err := findLogonSID(id.groups)
	if err != nil {
		return nil, err
	}
	id.logon = logon
	return id, nil
}

// findLogonSID returns the logon session SID. The restricted token keeps it
// as the only enabled and restricting SID, so a token without one cannot
// reach the workspace.
func findLogonSID(groups []windows.SIDAndAttributes) (*windows.SID, error) {
	for _, g := range groups {
		if g.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			return g.Sid, nil
		}
	}
	return nil, errors.New("hostlockdown: process token has no logon SID")
}

// denyOnlySIDs lists every enabled token SID that the restricted token turns
// into a deny-only SID: the user SID and all groups except the logon SID, the
// integrity label and groups that are already deny-only or disabled.
func denyOnlySIDs(user *windows.SID, groups []windows.SIDAndAttributes) []windows.SIDAndAttributes {
	return denyOnlySIDsForMode(user, groups, false)
}

func denyOnlySIDsForMode(user *windows.SID, groups []windows.SIDAndAttributes, allowOutboundNet bool) []windows.SIDAndAttributes {
	out := []windows.SIDAndAttributes{{Sid: user, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY}}
	for _, g := range groups {
		switch {
		case g.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID:
		case g.Attributes&windows.SE_GROUP_INTEGRITY != 0:
		case g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0:
		case g.Attributes&windows.SE_GROUP_ENABLED == 0:
		case allowOutboundNet && isEveryoneSID(g.Sid):
		default:
			out = append(out, windows.SIDAndAttributes{Sid: g.Sid, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY})
		}
	}
	return out
}

func isEveryoneSID(sid *windows.SID) bool {
	return sid != nil && sid.IsValid() &&
		sid.IdentifierAuthority() == windows.SECURITY_WORLD_SID_AUTHORITY &&
		sid.SubAuthorityCount() == 1 && sid.SubAuthority(0) == 0
}

type tokenDefaultDACL struct {
	DefaultDACL *windows.ACL
}

// grantLogonInDefaultDACL adds the logon SID with GENERIC_ALL to the default
// DACL of token so unnamed kernel objects created by the process (such as the
// containment job, anonymous sections, events, and impersonation tokens) remain
// accessible after threads bind the restricted token.
func grantLogonInDefaultDACL(token windows.Token, logon *windows.SID) error {
	buf, err := tokenInformation(token, windows.TokenDefaultDacl)
	if err != nil {
		return fmt.Errorf("hostlockdown: GetTokenInformation(TokenDefaultDacl): %w", err)
	}
	tdd := (*tokenDefaultDACL)(unsafe.Pointer(&buf[0]))
	var pin runtime.Pinner
	defer pin.Unpin()
	pin.Pin(logon)
	entries := []windows.EXPLICIT_ACCESS{
		sidEntry(logon, windows.GENERIC_ALL, windows.GRANT_ACCESS, windows.NO_INHERITANCE),
	}
	merged, err := windows.ACLFromEntries(entries, tdd.DefaultDACL)
	if err != nil {
		return fmt.Errorf("hostlockdown: build TokenDefaultDacl: %w", err)
	}
	newTDD := tokenDefaultDACL{DefaultDACL: merged}
	if err := windows.SetTokenInformation(
		token,
		windows.TokenDefaultDacl,
		(*byte)(unsafe.Pointer(&newTDD)),
		uint32(unsafe.Sizeof(newTDD)),
	); err != nil {
		return fmt.Errorf("hostlockdown: SetTokenInformation(TokenDefaultDacl): %w", err)
	}
	return nil
}

// tokenInformation returns the raw TokenInformation buffer for class.
func tokenInformation(token windows.Token, class uint32) ([]byte, error) {
	n := uint32(256)
	for {
		buf := make([]byte, n)
		err := windows.GetTokenInformation(token, class, &buf[0], n, &n)
		if err == nil {
			return buf[:n], nil
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return nil, err
		}
	}
}

// removeAllTokenPrivileges deletes every privilege from the live token with
// SE_PRIVILEGE_REMOVED. A disabled privilege could be enabled again.
func removeAllTokenPrivileges(token windows.Token) error {
	buf, err := tokenInformation(token, windows.TokenPrivileges)
	if err != nil {
		return fmt.Errorf("hostlockdown: GetTokenInformation(TokenPrivileges): %w", err)
	}
	privs := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0]))
	if privs.PrivilegeCount > 0 {
		all := unsafe.Slice((*windows.LUIDAndAttributes)(unsafe.Add(unsafe.Pointer(&buf[0]), unsafe.Offsetof(privs.Privileges))), privs.PrivilegeCount)
		for i := range all {
			all[i].Attributes = windows.SE_PRIVILEGE_REMOVED
		}
		// AdjustTokenPrivileges returns TRUE with ERROR_NOT_ALL_ASSIGNED when it
		// skipped a privilege, so the last error decides success.
		r1, _, callErr := procAdjustTokenPrivileges.Call(
			uintptr(token),
			0,
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			0,
			0,
		)
		if r1 == 0 {
			return fmt.Errorf("hostlockdown: AdjustTokenPrivileges: %w", callErr)
		}
		if errors.Is(callErr, windows.ERROR_NOT_ALL_ASSIGNED) {
			return fmt.Errorf("hostlockdown: AdjustTokenPrivileges removed only part of the privileges: %w", callErr)
		}
	}
	return verifyNoPrivileges(token)
}

func verifyNoPrivileges(token windows.Token) error {
	buf, err := tokenInformation(token, windows.TokenPrivileges)
	if err != nil {
		return fmt.Errorf("hostlockdown: re-read TokenPrivileges: %w", err)
	}
	if n := (*windows.Tokenprivileges)(unsafe.Pointer(&buf[0])).PrivilegeCount; n != 0 {
		return fmt.Errorf("hostlockdown: token still holds %d privileges after removal", n)
	}
	return nil
}

// lowerTokenIntegrityToLow sets the live token to the Low mandatory level and
// reads the level back.
func lowerTokenIntegrityToLow(token windows.Token) error {
	lowSID, err := windows.StringToSid(lowIntegritySID)
	if err != nil {
		return fmt.Errorf("hostlockdown: parse %s: %w", lowIntegritySID, err)
	}
	tml := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        lowSID,
			Attributes: windows.SE_GROUP_INTEGRITY,
		},
	}
	if err := windows.SetTokenInformation(
		token,
		windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&tml)),
		tml.Size(),
	); err != nil {
		return fmt.Errorf("hostlockdown: SetTokenInformation(TokenIntegrityLevel): %w", err)
	}
	buf, err := tokenInformation(token, windows.TokenIntegrityLevel)
	if err != nil {
		return fmt.Errorf("hostlockdown: re-read TokenIntegrityLevel: %w", err)
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	if !isLowIntegritySID(label.Label.Sid) {
		return fmt.Errorf("hostlockdown: token integrity level is %s after lowering, want %s", label.Label.Sid, lowIntegritySID)
	}
	return nil
}

func isLowIntegritySID(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	n := sid.SubAuthorityCount()
	return n > 0 && sid.IdentifierAuthority() == windows.SECURITY_MANDATORY_LABEL_AUTHORITY && sid.SubAuthority(uint32(n-1)) == lowIntegrityRID
}

// createRestrictedImpersonationToken copies the live token into an
// impersonation token with DISABLE_MAX_PRIVILEGE, deny-only SIDs and the
// logon SID as the restricting SID (plus Everyone when allowOutboundNet is
// true so Winsock may open \Device\Afd\Endpoint). The system grants access
// only when both the enabled SIDs and the restricting SIDs allow it.
//
// The impersonation copy keeps TOKEN_IMPERSONATE access, which SetThreadToken
// needs. WRITE_RESTRICTED stays off so that the restriction covers reads.
func createRestrictedImpersonationToken(primary windows.Token, id *tokenIdentity, allowOutboundNet bool) (windows.Token, error) {
	var imp windows.Token
	if err := windows.DuplicateTokenEx(
		primary,
		windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&imp,
	); err != nil {
		return 0, fmt.Errorf("hostlockdown: DuplicateTokenEx: %w", err)
	}
	defer imp.Close()

	deny := denyOnlySIDsForMode(id.user, id.groups, allowOutboundNet)
	restrict := []windows.SIDAndAttributes{{Sid: id.logon}}
	if allowOutboundNet {
		everyoneSID, err := windows.StringToSid("S-1-1-0")
		if err != nil {
			return 0, fmt.Errorf("hostlockdown: parse S-1-1-0: %w", err)
		}
		restrict = append(restrict, windows.SIDAndAttributes{Sid: everyoneSID})
	}
	var restricted windows.Token
	r1, _, callErr := procCreateRestrictedToken.Call(
		uintptr(imp),
		disableMaxPrivilege,
		uintptr(len(deny)),
		uintptr(unsafe.Pointer(&deny[0])),
		0,
		0,
		uintptr(len(restrict)),
		uintptr(unsafe.Pointer(&restrict[0])),
		uintptr(unsafe.Pointer(&restricted)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("hostlockdown: CreateRestrictedToken: %w", callErr)
	}
	if err := verifyRestrictedToken(restricted); err != nil {
		_ = restricted.Close()
		return 0, err
	}
	return restricted, nil
}

func verifyRestrictedToken(token windows.Token) error {
	r1, _, _ := procIsTokenRestricted.Call(uintptr(token))
	if r1 == 0 {
		return errors.New("hostlockdown: IsTokenRestricted reports an unrestricted token")
	}
	return nil
}
