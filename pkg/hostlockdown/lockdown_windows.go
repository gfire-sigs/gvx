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
	"fmt"
	"path/filepath"
	"sync"

	"golang.org/x/sys/windows"
)

// OS handles that live for the whole process. The restricted token stays open so
// BindThread can attach it to any thread later. The job handle stays open so
// the containment job outlives every other reference to it.
var (
	handlesMu       sync.RWMutex
	restrictedToken windows.Token
	containmentJob  windows.Handle
)

// applyOSLockdown runs the SPEC 3.8 Windows steps in order. Each step returns
// its error. Status fields change only after the step succeeded and its effect
// was read back from the OS.
func applyOSLockdown(opts Options) (st Status, err error) {
	primary, err := openPrimaryToken()
	if err != nil {
		return Status{}, err
	}
	defer primary.Close()
	id, err := readTokenIdentity(primary)
	if err != nil {
		return Status{}, err
	}

	// Step 1: Low-Integrity label and logon SID entry on every mount. A
	// directory that two mounts name, or that lies below another mount, gets
	// the rights of each mount. A file mount gets the label and the entry on
	// that one file. Each grant only adds access, so the order of the mounts
	// does not matter.
	mountsReal := make([]string, 0, len(opts.Mounts))
	for _, m := range opts.Mounts {
		real, err := resolveMount(m.Path)
		if err != nil {
			return Status{}, err
		}
		if err := prepareWorkspace(real, id.logon, m.ReadOnly, m.File); err != nil {
			return Status{}, err
		}
		mountsReal = append(mountsReal, real)
	}

	// Step 2: remove every privilege from the live primary token.
	if err := removeAllTokenPrivileges(primary); err != nil {
		return Status{}, err
	}

	// Step 3: lower the live primary token to Low integrity.
	if err := lowerTokenIntegrityToLow(primary); err != nil {
		return Status{}, err
	}
	st.IntegrityDowngraded = true

	// Step 4: restricted impersonation token for BindThread.
	restricted, err := createRestrictedImpersonationToken(primary, id)
	if err != nil {
		return Status{}, err
	}
	keep := false
	defer func() {
		if !keep {
			_ = restricted.Close()
		}
	}()
	if err := probeRestrictedOpenBlocked(restricted, mountsReal); err != nil {
		return Status{}, err
	}
	st.UnboundFileOpenBlocked = true

	// Steps 5 to 7: containment job.
	job, err := createContainmentJob(opts.CPUQuotaMillis)
	if err != nil {
		return Status{}, err
	}
	st.SubprocessBlocked = true
	st.CPUQuotaEnforced = opts.CPUQuotaMillis > 0

	// Step 8: disallow win32k system calls.
	if err := disableWin32kSystemCalls(); err != nil {
		_ = windows.CloseHandle(job)
		return Status{}, err
	}
	st.Win32kBlocked = true

	handlesMu.Lock()
	restrictedToken = restricted
	containmentJob = job
	handlesMu.Unlock()
	keep = true
	return st, nil
}

func openPrimaryToken() (windows.Token, error) {
	var token windows.Token
	err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE,
		&token,
	)
	if err != nil {
		return 0, fmt.Errorf("hostlockdown: OpenProcessToken: %w", err)
	}
	return token, nil
}

func resolveMount(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: resolve mount %q: %w", path, err)
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: resolve mount symlinks %q: %w", abs, err)
	}
	if filepath.Dir(real) == real {
		return "", fmt.Errorf("hostlockdown: mount %q resolves to the volume root %q and would allow every file on it", path, real)
	}
	return real, nil
}

// BindThread attaches the process-lifetime restricted token to the calling OS
// thread. Call it right after runtime.LockOSThread on every vCPU thread, and
// keep the thread locked until the goroutine exits.
//
// The token lets the thread reach only the workspace, so a compromised vCPU
// thread cannot read other user files. BindThread returns ErrNotLockedDown
// before a successful Apply.
func BindThread() error {
	handlesMu.RLock()
	token := restrictedToken
	handlesMu.RUnlock()
	if token == 0 {
		return ErrNotLockedDown
	}
	if err := windows.SetThreadToken(nil, token); err != nil {
		return fmt.Errorf("hostlockdown: SetThreadToken: %w", err)
	}
	return nil
}
