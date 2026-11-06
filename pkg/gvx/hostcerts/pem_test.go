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

package hostcerts

import (
	"bytes"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestParsePEMKeepsOnlyParsableCertificates(t *testing.T) {
	a, b := makeRoot(t, "a"), makeRoot(t, "b")
	data := append([]byte("# a comment line\n"), pemOf(a)...)
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("key")})...)
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})...)
	data = append(data, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: b})...)
	data = append(data, pemOf(b)...)

	got := ParsePEM(data)
	if len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Fatalf("ParsePEM returned %d certificates, want [a b]: a block of another type, a block with headers, and a broken certificate are skipped", len(got))
	}
}

func TestDedupeKeepsTheFirstOfEachCertificate(t *testing.T) {
	a, b := makeRoot(t, "a"), makeRoot(t, "b")
	got := dedupe([][]byte{a, b, a, b, a})
	if len(got) != 2 || !bytes.Equal(got[0], a) || !bytes.Equal(got[1], b) {
		t.Fatalf("dedupe returned %d certificates, want [a b]", len(got))
	}
}

func TestCollectUnixFollowsTheGoRule(t *testing.T) {
	dir := t.TempDir()
	a, b, c, d := makeRoot(t, "a"), makeRoot(t, "b"), makeRoot(t, "c"), makeRoot(t, "d")
	write := func(name string, ders ...[]byte) string {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, pemOf(ders...), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	first := write("first.pem", a)
	second := write("second.pem", b)
	write("certs/one.pem", c)
	write("certs/two.pem", d, c)
	if err := os.Mkdir(filepath.Join(dir, "certs", "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, "certs", "broken.pem")); err != nil {
		t.Skipf("no symbolic links: %v", err)
	}
	files := []string{filepath.Join(dir, "absent.pem"), first, second}
	dirs := []string{filepath.Join(dir, "certs"), filepath.Join(dir, "no-such-dir")}
	none := func(string) string { return "" }

	t.Run("the first file that exists, and every directory", func(t *testing.T) {
		got, err := collectUnix(none, files, dirs)
		if err != nil {
			t.Fatal(err)
		}
		want := [][]byte{a, c, d}
		if got := dedupe(got); !sameDER(got, want) {
			t.Fatalf("got %d certificates, want [a c d]", len(got))
		}
	})
	t.Run("SSL_CERT_FILE replaces the files and SSL_CERT_DIR replaces the directories", func(t *testing.T) {
		// Relative names avoid a colon in a Windows drive letter.
		t.Chdir(dir)
		env := map[string]string{"SSL_CERT_FILE": second, "SSL_CERT_DIR": "no-such-dir:certs/../certs"}
		got, err := collectUnix(func(k string) string { return env[k] }, files, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := dedupe(got); !sameDER(got, [][]byte{b, c, d}) {
			t.Fatalf("got %d certificates, want [b c d]", len(got))
		}
	})
	t.Run("an SSL_CERT_FILE that does not exist is an error", func(t *testing.T) {
		env := map[string]string{"SSL_CERT_FILE": filepath.Join(dir, "typo.pem")}
		_, err := collectUnix(func(k string) string { return env[k] }, files, nil)
		if err == nil {
			t.Fatal("collectUnix returned no error for a missing SSL_CERT_FILE")
		}
	})
}

func TestEnvRootsReadsTheFileAndTheDirectories(t *testing.T) {
	dir := t.TempDir()
	a, b := makeRoot(t, "a"), makeRoot(t, "b")
	file := filepath.Join(dir, "a.pem")
	if err := os.WriteFile(file, pemOf(a), 0o644); err != nil {
		t.Fatal(err)
	}
	certs := filepath.Join(dir, "certs")
	if err := os.Mkdir(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certs, "b.pem"), pemOf(b), 0o644); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"SSL_CERT_FILE": file, "SSL_CERT_DIR": ";" + certs + ";"}
	got, err := envRoots(func(k string) string { return env[k] }, ";")
	if err != nil {
		t.Fatal(err)
	}
	if !sameDER(got, [][]byte{a, b}) {
		t.Fatalf("got %d certificates, want [a b]", len(got))
	}
}

func sameDER(got, want [][]byte) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if !bytes.Equal(got[i], want[i]) {
			return false
		}
	}
	return true
}
