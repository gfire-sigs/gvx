//go:build windows

package systrap

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestDiagRestrictedToken starts the small stub image under several tokens and
// prints the exit code of each. It tells which restricting SIDs the loader needs.
func TestDiagRestrictedToken(t *testing.T) {
	user, _ := windows.GetCurrentProcessToken().GetTokenUser()
	logon := ""
	if g, err := windows.GetCurrentProcessToken().GetTokenGroups(); err == nil {
		for _, a := range g.AllGroups() {
			if a.Attributes&0xC0000000 == 0xC0000000 { // SE_GROUP_LOGON_ID
				logon = a.Sid.String()
			}
		}
	}
	t.Logf("user %s logon %s", user.User.Sid.String(), logon)
	sets := map[string][]string{
		"none":                      nil,
		"everyone":                  {"S-1-1-0"},
		"users":                     {"S-1-5-32-545"},
		"restricted":                {"S-1-5-12"},
		"everyone+users+restricted": {"S-1-1-0", "S-1-5-32-545", "S-1-5-12"},
		"+authenticated":            {"S-1-1-0", "S-1-5-32-545", "S-1-5-12", "S-1-5-11"},
		"+interactive+network":      {"S-1-1-0", "S-1-5-32-545", "S-1-5-12", "S-1-5-11", "S-1-5-4", "S-1-2-0"},
		"+logon":                    {"S-1-1-0", "S-1-5-32-545", "S-1-5-12", logon},
		"+admins":                   {"S-1-1-0", "S-1-5-32-545", "S-1-5-12", "S-1-5-32-544"},
		"+appPackages":              {"S-1-1-0", "S-1-5-32-545", "S-1-5-12", "S-1-15-2-1"},
		"+system":                   {"S-1-1-0", "S-1-5-32-545", "S-1-5-12", "S-1-5-18"},
	}
	dirs := map[string]string{"tempdir": t.TempDir(), "workdir": filepath.Join(mustGetwd(t), ".diag")}
	_ = os.MkdirAll(dirs["workdir"], 0o755)
	defer os.RemoveAll(dirs["workdir"])
	for dn, dir := range dirs {
		img, err := createStubImage(dir)
		if err != nil {
			t.Fatalf("createStubImage(%s): %v", dir, err)
		}
		for name, sids := range sets {
			tok, _, err := buildStubTokenWith(sids)
			if err != nil {
				t.Logf("DIAG dir=%s set=%s: token error: %v", dn, name, err)
				continue
			}
			h := &stubHostLoop{token: tok, exe: "", image: nil}
			pi, _, err := h.createProcessFor(img.path)
			if err != nil {
				t.Logf("DIAG dir=%s set=%s: CreateProcessAsUser: %v", dn, name, err)
				tok.Close()
				continue
			}
			_, _ = windows.ResumeThread(pi.Thread)
			ev, _ := windows.WaitForSingleObject(pi.Process, 8000)
			var code uint32
			_ = windows.GetExitCodeProcess(pi.Process, &code)
			t.Logf("DIAG dir=%s set=%s: wait=%d exit=%#x", dn, name, ev, code)
			windows.TerminateProcess(pi.Process, 0)
			windows.CloseHandle(pi.Process)
			windows.CloseHandle(pi.Thread)
			tok.Close()
		}
		img.close()
	}
}

func mustGetwd(t *testing.T) string {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}
