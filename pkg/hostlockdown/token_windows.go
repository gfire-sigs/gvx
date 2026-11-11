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
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	// untrustedIntegritySID is the Untrusted mandatory label SID (SECURITY_MANDATORY_UNTRUSTED_RID 0x0).
	untrustedIntegritySID = "S-1-16-0"
	untrustedIntegrityRID = 0x0

	// lowIntegritySID is the Low mandatory label SID (SECURITY_MANDATORY_LOW_RID 0x1000).
	lowIntegritySID = "S-1-16-4096"
	lowIntegrityRID = 0x1000

	// nullSIDString is NULL_SID. Restricted thread tokens carry only NULL_SID in
	// RestrictedSids so every NTFS and named host object fails Pass 2 of SeAccessCheck.
	nullSIDString = "S-1-0-0"

	// everyoneSIDString is World / Everyone. Only the Low-integrity outbound
	// socket broker token keeps Everyone when AllowOutboundNet is true.
	everyoneSIDString = "S-1-1-0"

	// localSystemSIDString is NT AUTHORITY\SYSTEM.
	localSystemSIDString = "S-1-5-18"

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

// findLogonSID returns the logon session SID from groups.
func findLogonSID(groups []windows.SIDAndAttributes) (*windows.SID, error) {
	for _, g := range groups {
		if g.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID {
			return g.Sid, nil
		}
	}
	return nil, errors.New("hostlockdown: process token has no logon SID")
}

// denyOnlySIDs lists every enabled token SID that the restricted thread token
// converts to SE_GROUP_USE_FOR_DENY_ONLY: the user SID and all enabled groups
// except the logon SID, the integrity label, and groups that are already
// deny-only or disabled. Everyone (S-1-1-0) becomes deny-only in all modes.
func denyOnlySIDs(user *windows.SID, groups []windows.SIDAndAttributes) []windows.SIDAndAttributes {
	return buildDenyOnlySIDs(user, groups, false)
}

func buildDenyOnlySIDs(user *windows.SID, groups []windows.SIDAndAttributes, keepEveryone bool) []windows.SIDAndAttributes {
	out := []windows.SIDAndAttributes{{Sid: user, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY}}
	for _, g := range groups {
		switch {
		case g.Attributes&windows.SE_GROUP_LOGON_ID == windows.SE_GROUP_LOGON_ID:
		case g.Attributes&windows.SE_GROUP_INTEGRITY != 0:
		case g.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY != 0:
		case g.Attributes&windows.SE_GROUP_ENABLED == 0:
		case keepEveryone && isEveryoneSID(g.Sid):
		default:
			out = append(out, windows.SIDAndAttributes{Sid: g.Sid, Attributes: windows.SE_GROUP_USE_FOR_DENY_ONLY})
		}
	}
	return out
}

func isEveryoneSID(sid *windows.SID) bool {
	auth, subs, ok := sidFields(sid)
	return ok && auth == windows.SECURITY_WORLD_SID_AUTHORITY && len(subs) == 1 && subs[0] == 0
}

// sidFields returns the identifier authority and the sub-authorities of a
// valid SID. It reads the SID bytes directly. The accessors of
// golang.org/x/sys/windows convert a returned uintptr into a pointer, and
// the checkptr instrumentation of -race stops the process when that pointer
// points into a SID in Go memory.
func sidFields(sid *windows.SID) (windows.SidIdentifierAuthority, []uint32, bool) {
	var auth windows.SidIdentifierAuthority
	if sid == nil || !sid.IsValid() {
		return auth, nil, false
	}
	// A SID is Revision (1 byte), SubAuthorityCount (1 byte),
	// IdentifierAuthority (6 bytes), and SubAuthorityCount uint32 values.
	b := unsafe.Slice((*byte)(unsafe.Pointer(sid)), sid.Len())
	if len(b) < 8 || len(b) < 8+4*int(b[1]) {
		return auth, nil, false
	}
	copy(auth.Value[:], b[2:8])
	subs := make([]uint32, b[1])
	for i := range subs {
		subs[i] = binary.LittleEndian.Uint32(b[8+4*i:])
	}
	return auth, subs, true
}

type tokenDefaultDACL struct {
	DefaultDACL *windows.ACL
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

// grantDefaultDACL grants GENERIC_ALL to user, SYSTEM, logon, and NULL_SID in
// the default DACL of token. Unnamed kernel objects created by the process
// (such as waitable timers in Go runtime.minit, anonymous sections, and events)
// then pass both Pass 1 (logon) and Pass 2 (NULL_SID) of SeAccessCheck while
// named NTFS objects deny NULL_SID.
func grantDefaultDACL(token windows.Token, id *tokenIdentity) error {
	systemSID, err := windows.StringToSid(localSystemSIDString)
	if err != nil {
		return fmt.Errorf("hostlockdown: parse %s: %w", localSystemSIDString, err)
	}
	nullSID, err := windows.StringToSid(nullSIDString)
	if err != nil {
		return fmt.Errorf("hostlockdown: parse %s: %w", nullSIDString, err)
	}
	buf, err := tokenInformation(token, windows.TokenDefaultDacl)
	if err != nil {
		return fmt.Errorf("hostlockdown: GetTokenInformation(TokenDefaultDacl): %w", err)
	}
	tdd := (*tokenDefaultDACL)(unsafe.Pointer(&buf[0]))
	var pin runtime.Pinner
	defer pin.Unpin()
	for _, s := range []*windows.SID{id.user, systemSID, id.logon, nullSID} {
		pin.Pin(s)
	}
	entries := []windows.EXPLICIT_ACCESS{
		sidEntry(id.user, windows.GENERIC_ALL, windows.GRANT_ACCESS, windows.NO_INHERITANCE),
		sidEntry(systemSID, windows.GENERIC_ALL, windows.GRANT_ACCESS, windows.NO_INHERITANCE),
		sidEntry(id.logon, windows.GENERIC_ALL, windows.GRANT_ACCESS, windows.NO_INHERITANCE),
		sidEntry(nullSID, windows.GENERIC_ALL, windows.GRANT_ACCESS, windows.NO_INHERITANCE),
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
	return lowerTokenIntegrity(token, lowIntegritySID, lowIntegrityRID)
}

// lowerTokenIntegrityToUntrusted sets the live token to the Untrusted mandatory
// level and reads the level back.
func lowerTokenIntegrityToUntrusted(token windows.Token) error {
	return lowerTokenIntegrity(token, untrustedIntegritySID, untrustedIntegrityRID)
}

func lowerTokenIntegrity(token windows.Token, sidStr string, rid uint32) error {
	targetSID, err := windows.StringToSid(sidStr)
	if err != nil {
		return fmt.Errorf("hostlockdown: parse %s: %w", sidStr, err)
	}
	tml := windows.Tokenmandatorylabel{
		Label: windows.SIDAndAttributes{
			Sid:        targetSID,
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
	if !isIntegritySID(label.Label.Sid, rid) {
		return fmt.Errorf("hostlockdown: token integrity level is %s after lowering, want %s", label.Label.Sid, sidStr)
	}
	return nil
}

func isLowIntegritySID(sid *windows.SID) bool {
	return isIntegritySID(sid, lowIntegrityRID)
}

func isUntrustedIntegritySID(sid *windows.SID) bool {
	return isIntegritySID(sid, untrustedIntegrityRID)
}

func isIntegritySID(sid *windows.SID, rid uint32) bool {
	auth, subs, ok := sidFields(sid)
	return ok && len(subs) > 0 && auth == windows.SECURITY_MANDATORY_LABEL_AUTHORITY && subs[len(subs)-1] == rid
}

// createBrokerImpersonationToken duplicates a privilege-stripped primary token
// into an impersonation token before Apply lowers primary to Untrusted
// integrity. The dedicated pinned-root file broker thread attaches this token
// and closes the handle immediately so no handle remains in the process handle
// table.
func createBrokerImpersonationToken(primary windows.Token) (windows.Token, error) {
	var imp windows.Token
	if err := windows.DuplicateTokenEx(
		primary,
		windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&imp,
	); err != nil {
		return 0, fmt.Errorf("hostlockdown: DuplicateTokenEx(broker): %w", err)
	}
	if err := verifyNoPrivileges(imp); err != nil {
		_ = imp.Close()
		return 0, err
	}
	return imp, nil
}

// createRestrictedImpersonationToken copies primary into an Untrusted-integrity
// impersonation token with DISABLE_MAX_PRIVILEGE, deny-only user and group
// SIDs (including Everyone), and NULL_SID (S-1-0-0) as the sole restricting
// SID. Matching primary's Untrusted level preserves SecurityImpersonation on
// threads bound after Apply lowers primary, while blocking every named NTFS
// path and Winsock endpoint.
func createRestrictedImpersonationToken(primary windows.Token, id *tokenIdentity) (windows.Token, error) {
	nullSID, err := windows.StringToSid(nullSIDString)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: parse %s: %w", nullSIDString, err)
	}
	deny := denyOnlySIDs(id.user, id.groups)
	restrict := []windows.SIDAndAttributes{{Sid: nullSID}}
	return buildRestrictedImpersonationToken(primary, deny, restrict, untrustedIntegritySID, untrustedIntegrityRID)
}

// createSweeperImpersonationToken builds a Low-integrity restricted
// impersonation token with NULL_SID (S-1-0-0) and deny-only user and group
// SIDs for the background thread-sweeper OS thread. Low integrity permits
// OpenThread against peer threads created by Low-integrity net-broker workers
// as well as Untrusted threads, while NULL_SID denies all NTFS and named
// host-object access.
func createSweeperImpersonationToken(primary windows.Token, id *tokenIdentity) (windows.Token, error) {
	nullSID, err := windows.StringToSid(nullSIDString)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: parse %s: %w", nullSIDString, err)
	}
	deny := denyOnlySIDs(id.user, id.groups)
	restrict := []windows.SIDAndAttributes{{Sid: nullSID}}
	return buildRestrictedImpersonationToken(primary, deny, restrict, lowIntegritySID, lowIntegrityRID)
}

// createNetBrokerImpersonationToken builds a Low-integrity restricted
// impersonation token for outbound NAT dials and TCP listener accepts when
// AllowOutboundNet is true. User and group SIDs other than logon and Everyone
// remain deny-only so broker threads cannot read user profile files or mutate
// Medium-integrity host objects.
func createNetBrokerImpersonationToken(primary windows.Token, id *tokenIdentity) (windows.Token, error) {
	nullSID, err := windows.StringToSid(nullSIDString)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: parse %s: %w", nullSIDString, err)
	}
	everyoneSID, err := windows.StringToSid(everyoneSIDString)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: parse %s: %w", everyoneSIDString, err)
	}
	deny := buildDenyOnlySIDs(id.user, id.groups, true)
	restrict := []windows.SIDAndAttributes{{Sid: nullSID}, {Sid: everyoneSID}}
	return buildRestrictedImpersonationToken(primary, deny, restrict, lowIntegritySID, lowIntegrityRID)
}

func buildRestrictedImpersonationToken(primary windows.Token, deny, restrict []windows.SIDAndAttributes, integritySID string, integrityRID uint32) (windows.Token, error) {
	var imp windows.Token
	if err := windows.DuplicateTokenEx(
		primary,
		windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT,
		nil,
		windows.SecurityImpersonation,
		windows.TokenImpersonation,
		&imp,
	); err != nil {
		return 0, fmt.Errorf("hostlockdown: DuplicateTokenEx: %w", err)
	}
	defer imp.Close()
	if err := lowerTokenIntegrity(imp, integritySID, integrityRID); err != nil {
		return 0, err
	}

	var pin runtime.Pinner
	defer pin.Unpin()
	for i := range deny {
		pin.Pin(deny[i].Sid)
	}
	for i := range restrict {
		pin.Pin(restrict[i].Sid)
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
	if err := verifyNoPrivileges(restricted); err != nil {
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
