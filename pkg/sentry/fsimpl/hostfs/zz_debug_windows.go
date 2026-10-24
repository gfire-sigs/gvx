//go:build windows

package hostfs

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func debugSD(path string) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.LABEL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Sprintf("%s: %v", path, err)
	}
	return fmt.Sprintf("%s: %s", path, sd.String())
}

func debugToken(t windows.Token) string {
	var sb strings.Builder
	var n uint32
	_ = windows.GetTokenInformation(t, windows.TokenIntegrityLevel, nil, 0, &n)
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(t, windows.TokenIntegrityLevel, &buf[0], n, &n); err == nil {
		tml := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
		fmt.Fprintf(&sb, "IL=%s ", tml.Label.Sid.String())
	}
	restricted, _ := t.IsRestricted()
	fmt.Fprintf(&sb, "restricted=%v ", restricted)
	if u, err := t.GetTokenUser(); err == nil {
		fmt.Fprintf(&sb, "user=%s ", u.User.Sid.String())
	}
	if g, err := t.GetTokenGroups(); err == nil {
		for _, a := range g.AllGroups() {
			fmt.Fprintf(&sb, "[%s %#x]", a.Sid.String(), a.Attributes)
		}
	}
	return sb.String()
}

func debugAccess(path string) string {
	out := "thread-token: " + debugToken(windows.GetCurrentThreadEffectiveToken()) + "\n"
	pt, err := windows.OpenCurrentProcessToken()
	if err == nil {
		out += "process-token: " + debugToken(pt) + "\n"
	}
	out += debugSD(filepath.Dir(path)) + "\n" + debugSD(path) + "\n"
	return out
}
