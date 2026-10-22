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

package hostlockdown

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	tokenIsAppContainerClass = 29
	tokenCapabilitiesClass   = 30
)

func tokenIsAppContainer(token windows.Token) (bool, error) {
	data, err := tokenInformation(token, tokenIsAppContainerClass)
	if err != nil {
		return false, fmt.Errorf("hostlockdown: read AppContainer token: %w", err)
	}
	return *(*uint32)(unsafe.Pointer(&data[0])) != 0, nil
}

func requireAppContainerToken(token windows.Token) error {
	app, err := tokenIsAppContainer(token)
	if err != nil {
		return err
	}
	if !app {
		return errors.New("hostlockdown: worker requires an AppContainer process token")
	}
	data, err := tokenInformation(token, tokenCapabilitiesClass)
	if err != nil {
		return fmt.Errorf("hostlockdown: read token capabilities: %w", err)
	}
	if *(*uint32)(unsafe.Pointer(&data[0])) != 0 {
		return errors.New("hostlockdown: worker token has capabilities")
	}
	return nil
}

// RequireAppContainer verifies the primary token before a worker accepts broker resources.
func RequireAppContainer() error {
	var token windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token); err != nil {
		return err
	}
	defer token.Close()
	return requireAppContainerToken(token)
}

func applyAppContainerLockdown(primary windows.Token) (Status, error) {
	if err := requireAppContainerToken(primary); err != nil {
		return Status{}, err
	}
	if err := verifyContainmentJob(0); err != nil {
		return Status{}, err
	}
	if err := removeAllTokenPrivileges(primary); err != nil {
		return Status{}, err
	}
	if err := lowerTokenIntegrityToLow(primary); err != nil {
		return Status{}, err
	}
	if err := disableWin32kSystemCalls(); err != nil {
		return Status{}, err
	}
	if home := os.Getenv("USERPROFILE"); home != "" {
		if err := openUnlistedPaths([]string{home}); err != nil {
			return Status{}, err
		}
	} else {
		return Status{}, errors.New("hostlockdown: worker has no user profile for the file probe")
	}
	return Status{AppContainer: true, SubprocessBlocked: true, UnboundFileOpenBlocked: true, NetworkOutboundBlocked: true, IntegrityDowngraded: true, Win32kBlocked: true}, nil
}
