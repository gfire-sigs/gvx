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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const childEnv = "GVX_HVF_TEST_CHILD"

// testExecutable returns the path of the test binary. After the signed re-exec
// os.Executable names a deleted file, so the original argv[0] serves instead.
func testExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err == nil {
		if _, serr := os.Stat(exe); serr == nil {
			return exe
		}
	}
	abs, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	return abs
}

func codesignOutput(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("/usr/bin/codesign", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("codesign %v: %v: %s", args, err, out)
	}
	return string(out)
}

func TestSignedCopyCarriesOnlyTheHypervisorEntitlement(t *testing.T) {
	exe := testExecutable(t)
	dir := t.TempDir()
	signed, err := signedCopy(exe, dir)
	if err != nil {
		t.Fatalf("signedCopy: %v", err)
	}
	info, err := os.Stat(signed)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Errorf("signed copy mode = %v, want 0700", mode)
	}
	plist, err := os.Stat(filepath.Join(dir, "entitlements.plist"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := plist.Mode().Perm(); mode != 0o600 {
		t.Errorf("plist mode = %v, want 0600", mode)
	}
	ents := codesignOutput(t, "-d", "--entitlements", "-", "--xml", signed)
	if !strings.Contains(ents, "com.apple.security.hypervisor") {
		t.Errorf("entitlements %q lack com.apple.security.hypervisor", ents)
	}
	if n := strings.Count(ents, "<key>"); n != 1 {
		t.Errorf("entitlements carry %d keys, want only the hypervisor key: %s", n, ents)
	}
}

func TestSignedCopyRefusesToReuseFiles(t *testing.T) {
	exe := testExecutable(t)
	dir := t.TempDir()
	if _, err := signedCopy(exe, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := signedCopy(exe, dir); err == nil || !strings.Contains(err.Error(), "exist") {
		t.Errorf("second signedCopy into the same directory = %v, want a file exists error", err)
	}
}

func TestSignedCopySurfacesCodesignOutput(t *testing.T) {
	fake := filepath.Join(t.TempDir(), "codesign")
	script := "#!/bin/sh\necho 'fake codesign diagnostic: key not found' >&2\nexit 3\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	old := codesignTool
	codesignTool = fake
	defer func() { codesignTool = old }()

	exe := testExecutable(t)
	_, err := signedCopy(exe, t.TempDir())
	if err == nil {
		t.Fatal("signedCopy succeeded although the signing tool failed")
	}
	if !strings.Contains(err.Error(), "fake codesign diagnostic: key not found") {
		t.Errorf("error %q does not carry the tool's stderr", err)
	}
}

func TestWithEnvReplacesEarlierEntries(t *testing.T) {
	got := withEnv([]string{"A=1", "GVX_HVF_SIGNED=", "B=2", "GVX_HVF_SIGNED=x"}, "GVX_HVF_SIGNED", "1", "C", "3")
	want := []string{"A=1", "B=2", "GVX_HVF_SIGNED=1", "C=3"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("withEnv = %v, want %v", got, want)
	}
}

func TestSignAndReexecRefusesWhenAlreadySigned(t *testing.T) {
	t.Setenv(envSigned, "1")
	if err := signAndReexec(); err == nil || !strings.Contains(err.Error(), envSigned) {
		t.Errorf("signAndReexec with %s set = %v, want an error that names the variable", envSigned, err)
	}
}

func TestIsOwnTempDirOnlyMatchesCreatedDirectories(t *testing.T) {
	own, err := os.MkdirTemp("", tempDirPattern)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(own)
	if !isOwnTempDir(own) {
		t.Errorf("isOwnTempDir(%q) = false for a directory MkdirTemp created", own)
	}
	for _, other := range []string{"/", "/Users", filepath.Join(os.TempDir(), "other-dir"), filepath.Join(own, "child")} {
		if isOwnTempDir(other) {
			t.Errorf("isOwnTempDir(%q) = true", other)
		}
	}
}

// TestChildCreatesPlatform runs only inside the process that
// TestUnsignedBinarySignsItselfOnce starts.
func TestChildCreatesPlatform(t *testing.T) {
	if os.Getenv(childEnv) == "" {
		t.Skip("runs only as a child of TestUnsignedBinarySignsItselfOnce")
	}
	p, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{DNSName: "localhost"}); err != nil && strings.Contains(err.Error(), "SecPolicyCreateSSL") {
		t.Fatalf("TLS certificate check failed with SecPolicyCreateSSL after re-exec: %v", err)
	}
	exe, _ := os.Executable()
	io.WriteString(os.Stdout, "CHILD-EXE="+exe+"\n")
	io.WriteString(os.Stdout, "CHILD-SIGNED="+os.Getenv(envSigned)+"\n")
}

// TestUnsignedBinarySignsItselfOnce copies the test binary, removes the
// hypervisor entitlement, and runs the copy. New must sign a private copy,
// run it, and the run must remove that copy.
func TestUnsignedBinarySignsItselfOnce(t *testing.T) {
	requireHypervisor(t)
	if os.Getenv(childEnv) != "" {
		t.Skip("the child runs TestChildCreatesPlatform")
	}
	exe := testExecutable(t)
	plain := filepath.Join(t.TempDir(), "plain.test")
	src, err := os.Open(exe)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	if err := writeExclusive(plain, src, 0o700); err != nil {
		t.Fatal(err)
	}
	// An ad-hoc signature without entitlements is what `go test` produces.
	codesignOutput(t, "--force", "--sign", "-", plain)

	cmd := exec.Command(plain, "-test.run", "^TestChildCreatesPlatform$", "-test.v")
	cmd.Env = append(os.Environ(), childEnv+"=1", envSigned+"=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child run failed: %v\n%s", err, out)
	}
	text := string(out)
	if !strings.Contains(text, "CHILD-SIGNED=1") {
		t.Errorf("the child did not run through the signed copy:\n%s", text)
	}
	var childExe string
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(line, "CHILD-EXE="); ok {
			childExe = strings.TrimSpace(v)
		}
	}
	if childExe == "" || childExe == plain {
		t.Fatalf("child executable %q is not a signed copy of %q", childExe, plain)
	}
	if _, err := os.Stat(filepath.Dir(childExe)); !os.IsNotExist(err) {
		t.Errorf("the signed copy directory %s was not removed (stat error %v)", filepath.Dir(childExe), err)
	}
}
