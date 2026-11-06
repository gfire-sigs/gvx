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

//go:build darwin

package hostcerts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	securityTool        = "/usr/bin/security"
	systemKeychain      = "/Library/Keychains/System.keychain"
	systemRootsKeychain = "/System/Library/Keychains/SystemRootCertificates.keychain"
	securityTimeout     = 60 * time.Second
)

// collectSystem lists the certificates of the System, SystemRootCertificates,
// and login keychains and keeps the ones that the trust settings accept for
// TLS servers. The system domain of the trust settings names every built-in
// root. The admin domain names the roots that a device management profile or
// an administrator added. The user domain names the roots of the login user.
// The command `security` is the only interface that needs neither cgo nor a
// private framework call.
func collectSystem(ctx context.Context) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, securityTimeout)
	defer cancel()

	var errs []error
	keychains := []string{systemKeychain, systemRootsKeychain}
	if home, err := os.UserHomeDir(); err == nil {
		login := filepath.Join(home, "Library", "Keychains", "login.keychain-db")
		if _, err := os.Stat(login); err == nil {
			keychains = append(keychains, login)
		}
	}
	var candidates [][]byte
	for _, keychain := range keychains {
		out, err := runSecurity(ctx, "find-certificate", "-a", "-p", keychain)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		candidates = append(candidates, ParsePEM(out)...)
	}

	lists, err := exportTrustLists(ctx)
	if err != nil {
		errs = append(errs, err)
	}
	var trusted [][]byte
	for _, der := range dedupe(candidates) {
		if trustedForSSL(lists, der) {
			trusted = append(trusted, der)
		}
	}

	extra, err := envRoots(os.Getenv, ":")
	if err != nil {
		errs = append(errs, err)
	}
	return append(trusted, extra...), errors.Join(errs...)
}

// exportTrustLists returns the trust lists of the user, admin, and system
// domains, in this order. A domain without trust settings gives an empty list.
func exportTrustLists(ctx context.Context) ([]trustList, error) {
	dir, err := os.MkdirTemp("", "gvx-trust-*")
	if err != nil {
		return nil, fmt.Errorf("hostcerts: create a directory for the trust settings: %w", err)
	}
	defer os.RemoveAll(dir)

	var lists []trustList
	var errs []error
	for _, domain := range []struct {
		name string
		flag []string
	}{{"user", nil}, {"admin", []string{"-d"}}, {"system", []string{"-s"}}} {
		file := filepath.Join(dir, domain.name+".plist")
		args := append([]string{"trust-settings-export"}, domain.flag...)
		if _, err := runSecurity(ctx, append(args, file)...); err != nil {
			// A domain that holds no settings makes the command fail.
			if !strings.Contains(err.Error(), "No Trust Settings") {
				errs = append(errs, fmt.Errorf("export the %s trust settings: %w", domain.name, err))
			}
			lists = append(lists, nil)
			continue
		}
		data, err := os.ReadFile(file)
		if err != nil {
			errs = append(errs, err)
			lists = append(lists, nil)
			continue
		}
		list, err := parseTrustList(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s trust settings: %w", domain.name, err))
		}
		lists = append(lists, list)
	}
	return lists, errors.Join(errs...)
}

// runSecurity runs the macOS command `security` and returns its output. The
// error holds the standard error text of the command.
func runSecurity(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, securityTool, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return out, fmt.Errorf("hostcerts: security %s: %w: %s", args[0], err, bytes.TrimSpace(stderr.Bytes()))
	}
	return out, nil
}
