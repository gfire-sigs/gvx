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

package hvf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Hypervisor.framework refuses hv_vm_create in a process whose code signature
// lacks the com.apple.security.hypervisor entitlement. Release builds sign the
// binary at build time with `codesign -s - --entitlements`. The convenience in
// this file lets an unsigned binary, for example a plain `go test` binary,
// sign a private copy of itself and run that copy instead.
//
// GVX_HVF_SIGNED has two roles. The re-executed copy receives it, which stops
// a second attempt. A caller that sets it to any non-empty value before the
// start disables the convenience, for example to test the failure path or to
// forbid the temporary copy.
const (
	envSigned  = "GVX_HVF_SIGNED"
	envTempDir = "GVX_HVF_TEMP_DIR"

	tempDirPattern = "gvx-hvf-*"

	// entitlementPlist grants only the hypervisor entitlement.
	entitlementPlist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>com.apple.security.hypervisor</key>
	<true/>
</dict>
</plist>
`
)

func init() {
	// The re-executed copy deletes its own directory: the original process
	// cannot, because exec replaced it. The deletion makes os.Executable name
	// a missing file in the copy: callers that need their own image must
	// use a binary that was signed at build time.
	if os.Getenv(envSigned) == "" {
		return
	}
	dir := os.Getenv(envTempDir)
	if dir == "" {
		return
	}
	os.Unsetenv(envTempDir)
	if isOwnTempDir(dir) {
		warmDarwinTLS()
		os.RemoveAll(dir)
	}
}

// warmDarwinTLS initializes macOS Security.framework before the re-executed
// binary unlinks its temporary executable directory, preventing subsequent
// SecPolicyCreateSSL calls from failing with error 0.
func warmDarwinTLS() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return
	}
	_, _ = cert.Verify(x509.VerifyOptions{DNSName: "localhost"})
}

// isOwnTempDir reports whether dir has the shape of a directory that
// signAndReexec creates, so a forged environment cannot delete other paths.
func isOwnTempDir(dir string) bool {
	prefix := strings.TrimSuffix(tempDirPattern, "*")
	return filepath.Dir(dir) == filepath.Clean(os.TempDir()) && strings.HasPrefix(filepath.Base(dir), prefix)
}

// codesignTool is the signing tool. Tests replace it to exercise failures.
var codesignTool = "/usr/bin/codesign"

// withEnv returns env with each key set to the following value, without any
// earlier entry for the same key: the first duplicate wins in getenv.
func withEnv(env []string, kv ...string) []string {
	drop := make(map[string]bool, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		drop[kv[i]] = true
	}
	out := make([]string, 0, len(env)+len(kv)/2)
	for _, e := range env {
		if key, _, _ := strings.Cut(e, "="); !drop[key] {
			out = append(out, e)
		}
	}
	for i := 0; i < len(kv); i += 2 {
		out = append(out, kv[i]+"="+kv[i+1])
	}
	return out
}

var entitlement struct {
	once sync.Once
	err  error
}

// createVMWithEntitlement creates the VM. When the framework denies it, the
// function tries once per process to run a signed copy of the executable.
func createVMWithEntitlement() error {
	err := hvVMCreate()
	if err == nil {
		return nil
	}
	code, isHV := hvCode(err)
	if !isHV || (code != hvErrGeneral && code != hvErrDenied) {
		return err
	}
	entitlement.once.Do(func() {
		entitlement.err = signAndReexec()
	})
	if entitlement.err != nil {
		return errors.Join(err, entitlement.err)
	}
	return err
}

// signAndReexec copies the executable into a private directory, signs the copy
// with the hypervisor entitlement, and replaces the process image with it. It
// returns only on failure.
func signAndReexec() error {
	if os.Getenv(envSigned) != "" {
		return fmt.Errorf("hvf: %s is set, so the process does not sign itself again", envSigned)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("hvf: locate the executable: %w", err)
	}
	dir, err := os.MkdirTemp("", tempDirPattern)
	if err != nil {
		return fmt.Errorf("hvf: create a private directory: %w", err)
	}
	signed, err := signedCopy(exe, dir)
	if err != nil {
		return errors.Join(err, os.RemoveAll(dir))
	}
	env := withEnv(os.Environ(), envSigned, "1", envTempDir, dir)
	if err := unix.Exec(signed, os.Args, env); err != nil {
		return errors.Join(fmt.Errorf("hvf: run the signed copy: %w", err), os.RemoveAll(dir))
	}
	return nil
}

// signedCopy writes a signed copy of exe into dir and returns its path. dir
// must be private to the caller: files use O_EXCL, so an existing file is an
// error instead of a hijack.
func signedCopy(exe, dir string) (string, error) {
	copyPath := filepath.Join(dir, "gvx")
	plistPath := filepath.Join(dir, "entitlements.plist")
	if err := writeExclusive(plistPath, strings.NewReader(entitlementPlist), 0o600); err != nil {
		return "", err
	}
	src, err := os.Open(exe)
	if err != nil {
		return "", fmt.Errorf("hvf: open the executable: %w", err)
	}
	defer src.Close()
	if err := writeExclusive(copyPath, src, 0o700); err != nil {
		return "", err
	}
	out, err := exec.Command(codesignTool, "--force", "--sign", "-", "--entitlements", plistPath, copyPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("hvf: codesign the executable copy: %w: %s", err, bytes.TrimSpace(out))
	}
	return copyPath, nil
}

func writeExclusive(path string, src io.Reader, mode os.FileMode) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("hvf: create %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("hvf: close %s: %w", path, cerr)
		}
	}()
	if _, err := io.Copy(f, src); err != nil {
		return fmt.Errorf("hvf: write %s: %w", path, err)
	}
	return nil
}
