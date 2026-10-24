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

package hostfs

import (
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func newVolumeEnv(t *testing.T, caps WorkspaceCaps, fold, verified, win bool) *env {
	t.Helper()
	return newEnvOpts(t, volumeOptions(caps, fold, verified, win))
}

// volumeCase names one modeled volume for the table of subtests.
type volumeCase struct {
	name     string
	caps     WorkspaceCaps
	verified bool
	win      bool
}

// foldingVolumes are the modeled volumes that fold case: NTFS, where the
// backend verifies names, and APFS, where the backend resolves them silently.
var foldingVolumes = []volumeCase{
	{"ntfs", winCaps, true, true},
	{"apfs", macCaps, false, false},
}

func sortedCopy(s []string) []string {
	out := slices.Clone(s)
	slices.Sort(out)
	return out
}

func TestWindowsVolumeStoresEscapedNames(t *testing.T) {
	for _, verified := range []bool{true, false} {
		t.Run(fmt.Sprintf("verified=%v", verified), func(t *testing.T) {
			e := newVolumeEnv(t, winCaps, true, verified, true)
			guestToHost := map[string]string{
				"aux.c":         "~gvx~aux.c",
				"Net::HTTP.3pm": "~gvx~Net%3A%3AHTTP.3pm",
				"CON":           "~gvx~CON",
				"trail.":        "~gvx~trail%2E",
				"back\\slash":   "~gvx~back%5Cslash",
				"~gvx~literal":  "~gvx~~gvx~literal",
				"100%":          "100%",
				"50%:off":       "~gvx~50%25%3Aoff",
				"plain.txt":     "plain.txt",
			}
			var guests, hosts []string
			for g, h := range guestToHost {
				e.writeFile(g, []byte("data of "+g))
				guests = append(guests, g)
				hosts = append(hosts, h)
			}
			if got, want := hostNames(t, e.dir), sortedCopy(hosts); !slices.Equal(got, want) {
				t.Fatalf("host names = %q, want %q", got, want)
			}
			if got, want := e.readdir("."), sortedCopy(guests); !slices.Equal(got, want) {
				t.Fatalf("guest listing = %q, want %q", got, want)
			}
			for _, g := range guests {
				if got := e.readFile(g); string(got) != "data of "+g {
					t.Fatalf("read %q = %q", g, got)
				}
				e.mustStat(g)
			}

			// A directory with an escaped name holds escaped names.
			e.mustMkdir("Net::dir")
			e.writeFile("Net::dir/aux.h", []byte("header"))
			if got := hostNames(t, e.host("~gvx~Net%3A%3Adir")); !slices.Equal(got, []string{"~gvx~aux.h"}) {
				t.Fatalf("host names of the escaped directory = %q", got)
			}
			if got := e.readdir("Net::dir"); !slices.Equal(got, []string{"aux.h"}) {
				t.Fatalf("guest listing of the escaped directory = %q", got)
			}

			if err := e.rename("aux.c", "com1.txt"); err != nil {
				t.Fatalf("rename: %v", err)
			}
			if _, err := os.Stat(e.host("~gvx~com1.txt")); err != nil {
				t.Fatalf("renamed host file: %v", err)
			}
			_, err := e.stat("aux.c")
			wantErrno(t, "stat of the old name", err, linuxerr.ENOENT)
			if got := e.readFile("com1.txt"); string(got) != "data of aux.c" {
				t.Fatalf("read after rename = %q", got)
			}
			if err := e.link("com1.txt", "lpt1"); err != nil {
				t.Fatalf("link: %v", err)
			}
			if err := e.unlink("com1.txt"); err != nil {
				t.Fatal(err)
			}
			if got := e.readFile("lpt1"); string(got) != "data of aux.c" {
				t.Fatalf("read of the link = %q", got)
			}
			if err := e.unlink("Net::dir/aux.h"); err != nil {
				t.Fatal(err)
			}
			if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("Net::dir")); err != nil {
				t.Fatalf("rmdir: %v", err)
			}
		})
	}
}

func TestMetaKeysAreGuestPaths(t *testing.T) {
	e := newVolumeEnv(t, winCaps, true, true, true)
	e.writeFile("aux.c", []byte("x"))
	if err := e.ws.Chmod("aux.c", 0o640); err != nil {
		t.Fatal(err)
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.host(MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	var parsed metaStoreFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Version != metaVersion {
		t.Fatalf("meta version = %d, want %d", parsed.Version, metaVersion)
	}
	if m, ok := parsed.Entries["aux.c"]; !ok || m.Mode&0o7777 != 0o640 {
		t.Fatalf("meta entries = %+v, want a record under the guest path aux.c", parsed.Entries)
	}
	for k := range parsed.Entries {
		if strings.Contains(k, codecPrefix) {
			t.Fatalf("meta key %q holds a host name", k)
		}
	}
}

func TestCaseVariantsCoexistOnFoldingVolumes(t *testing.T) {
	for _, vc := range foldingVolumes {
		t.Run(vc.name, func(t *testing.T) {
			opts := volumeOptions(vc.caps, true, vc.verified, vc.win)
			e, closeEnv := openEnvAt(t, resolvedTempDir(t), opts)

			variants := []struct{ guest, host, data string }{
				{"Readme.md", "Readme.md", "first"},
				{"readme.md", "~gvx~readme.md", "second"},
				{"README.md", "~gvx~%52%45%41%44%4D%45.md", "third"},
			}
			for _, v := range variants {
				e.writeFile(v.guest, []byte(v.data))
			}
			var hosts []string
			for _, v := range variants {
				hosts = append(hosts, v.host)
			}
			if got, want := hostNames(t, e.dir), sortedCopy(hosts); !slices.Equal(got, want) {
				t.Fatalf("host names = %q, want %q", got, want)
			}
			if got := e.readdir("."); !slices.Equal(got, []string{"README.md", "Readme.md", "readme.md"}) {
				t.Fatalf("guest listing = %q", got)
			}
			check := func(e *env, wantData map[string]string) {
				t.Helper()
				for guest, data := range wantData {
					if got := e.readFile(guest); string(got) != data {
						t.Fatalf("read %q = %q, want %q", guest, got, data)
					}
				}
				_, err := e.stat("ReadMe.md")
				wantErrno(t, "stat of a fourth variant", err, linuxerr.ENOENT)
			}
			check(e, map[string]string{"Readme.md": "first", "readme.md": "second", "README.md": "third"})
			if _, err := e.open("readme.md", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644); err == nil {
				t.Fatal("exclusive create of an existing variant succeeded")
			} else {
				wantErrno(t, "exclusive create of a variant", err, linuxerr.EEXIST)
			}

			// The first name goes away. The others keep their stored names.
			if err := e.unlink("Readme.md"); err != nil {
				t.Fatal(err)
			}
			check(e, map[string]string{"readme.md": "second", "README.md": "third"})
			if err := e.ws.Chmod("readme.md", 0o600); err != nil {
				t.Fatal(err)
			}

			// A reopened workspace finds the escaped names without memory of
			// the first run: the .gvx_meta records point at them.
			closeEnv()
			e2, _ := openEnvAt(t, e.dir, opts)
			check(e2, map[string]string{"readme.md": "second", "README.md": "third"})
			if st := e2.mustStat("readme.md"); st.Mode&0o7777 != 0o600 {
				t.Fatalf("mode of readme.md after reopen = %o, want 600", st.Mode&0o7777)
			}
			if got := e2.readdir("."); !slices.Equal(got, []string{"README.md", "readme.md"}) {
				t.Fatalf("guest listing after reopen = %q", got)
			}

			// A new first name takes the plain slot again.
			e2.writeFile("Readme.md", []byte("again"))
			if got := hostNames(t, e2.dir); !slices.Contains(got, "Readme.md") {
				t.Fatalf("host names = %q, want the plain Readme.md", got)
			}
			check(e2, map[string]string{"Readme.md": "again", "readme.md": "second", "README.md": "third"})

			// A rename onto a variant replaces that file and keeps the others.
			if err := e2.rename("readme.md", "Readme.md"); err != nil {
				t.Fatalf("rename onto a variant: %v", err)
			}
			if got := e2.readdir("."); !slices.Equal(got, []string{"README.md", "Readme.md"}) {
				t.Fatalf("guest listing after the rename = %q", got)
			}
			check(e2, map[string]string{"Readme.md": "second", "README.md": "third"})
		})
	}
}

func TestCaseVariantDirectoriesCoexist(t *testing.T) {
	for _, vc := range foldingVolumes {
		t.Run(vc.name, func(t *testing.T) {
			opts := volumeOptions(vc.caps, true, vc.verified, vc.win)
			e, closeEnv := openEnvAt(t, resolvedTempDir(t), opts)
			e.mustMkdir("Dir")
			e.mustMkdir("dir")
			e.writeFile("Dir/a", []byte("A"))
			e.writeFile("dir/b", []byte("B"))
			if got := e.readdir("Dir"); !slices.Equal(got, []string{"a"}) {
				t.Fatalf("listing of Dir = %q", got)
			}
			if got := e.readdir("dir"); !slices.Equal(got, []string{"b"}) {
				t.Fatalf("listing of dir = %q", got)
			}
			if got, want := hostNames(t, e.dir), []string{"Dir", "~gvx~dir"}; !slices.Equal(got, want) {
				t.Fatalf("host names = %q, want %q", got, want)
			}
			if err := e.rename("dir", "other"); err != nil {
				t.Fatalf("rename of the escaped directory: %v", err)
			}
			if got := e.readFile("other/b"); string(got) != "B" {
				t.Fatalf("other/b = %q", got)
			}
			if err := e.rename("other", "dir"); err != nil {
				t.Fatalf("rename back: %v", err)
			}
			if got := e.readFile("dir/b"); string(got) != "B" {
				t.Fatalf("dir/b = %q", got)
			}
			if err := e.unlink("Dir/a"); err != nil {
				t.Fatal(err)
			}
			if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("Dir")); err != nil {
				t.Fatalf("rmdir Dir: %v", err)
			}
			closeEnv()
			e2, _ := openEnvAt(t, e.dir, opts)
			if got := e2.readFile("dir/b"); string(got) != "B" {
				t.Fatalf("dir/b after reopen = %q", got)
			}
		})
	}
}

func TestMetaOfEscapedEntriesSurvivesReopenAndPruning(t *testing.T) {
	opts := volumeOptions(winCaps, true, true, true)
	e, closeEnv := openEnvAt(t, resolvedTempDir(t), opts)
	e.writeFile("aux.c", []byte("x"))
	e.writeFile("Net::x", []byte("y"))
	e.writeFile("readme", []byte("1"))
	e.writeFile("README", []byte("2"))
	for _, p := range []string{"aux.c", "Net::x", "readme", "README"} {
		if err := e.ws.Chmod(p, 0o640); err != nil {
			t.Fatal(err)
		}
	}
	closeEnv()
	e2, _ := openEnvAt(t, e.dir, opts)
	for _, p := range []string{"aux.c", "Net::x", "readme", "README"} {
		if st := e2.mustStat(p); st.Mode&0o7777 != 0o640 {
			t.Fatalf("mode of %q after reopen = %o, want 640", p, st.Mode&0o7777)
		}
	}
}

func TestNormalizedHostNamesShowAsNFC(t *testing.T) {
	for _, caps := range []WorkspaceCaps{apfsCSCaps, macCaps} {
		t.Run(fmt.Sprintf("fold=%v", !caps.CaseSensitive), func(t *testing.T) {
			e := newEnvOpts(t, workspaceOptions{coalesce: defaultCoalesceWindow, caps: &caps})
			nfd, nfc := "cafe\u0301.txt", "caf\u00e9.txt"
			if err := os.WriteFile(e.host(nfd), []byte("host"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := e.readdir("."); !slices.Equal(got, []string{nfc}) {
				t.Fatalf("listing = %q, want the NFC name %q", got, nfc)
			}
			for _, name := range []string{nfc, nfd} {
				if got := e.readFile(name); string(got) != "host" {
					t.Fatalf("read %q = %q", name, got)
				}
			}
			if a, b := e.mustStat(nfc), e.mustStat(nfd); a.Ino != b.Ino {
				t.Fatalf("NFC and NFD names show inodes %d and %d, want one file", a.Ino, b.Ino)
			}
			_, err := e.open(nfc, linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
			wantErrno(t, "create of the NFC name beside a host NFD file", err, linuxerr.EEXIST)

			// The guest creates an NFD name on purpose: .gvx_meta records it, and
			// the listing keeps the NFD form.
			explicit := "re\u0301sume\u0301"
			e.writeFile(explicit, []byte("explicit"))
			if got := e.readdir("."); !slices.Contains(got, explicit) {
				t.Fatalf("listing = %q, want the explicit NFD name %q", got, explicit)
			}
			if got := e.readFile("r\u00e9sum\u00e9"); string(got) != "explicit" {
				t.Fatalf("read by NFC form = %q", got)
			}
			if err := e.unlink(nfc); err != nil {
				t.Fatalf("unlink by NFC name: %v", err)
			}
			if _, err := os.Stat(e.host(nfd)); err == nil {
				t.Fatal("the host NFD file survived the unlink")
			}
		})
	}
}

func TestOverlongEncodedNameFailsWithENAMETOOLONG(t *testing.T) {
	e := newVolumeEnv(t, winCaps, true, true, true)
	name := strings.Repeat(":", 90)
	_, err := e.open(name, linux.O_CREAT|linux.O_WRONLY, 0o644)
	wantErrno(t, "create of an overlong encoded name", err, linuxerr.ENAMETOOLONG)
	_, err = e.stat(name)
	wantErrno(t, "stat of an overlong encoded name", err, linuxerr.ENAMETOOLONG)
	wantErrno(t, "mkdir of an overlong encoded name", e.mkdir(name), linuxerr.ENAMETOOLONG)
	if got := hostNames(t, e.dir); len(got) != 0 {
		t.Fatalf("host names = %q, want none", got)
	}
}

func TestLinuxVolumeNeverTranslatesNames(t *testing.T) {
	if isWindowsHost() {
		t.Skip("a real Windows volume refuses these names, so this test models a Linux volume on Linux and macOS only")
	}
	e := newVolumeEnv(t, linuxCaps, false, false, false)
	names := []string{"aux.c", "~gvx~literal", "Net::HTTP.3pm", "%41", "trail.", "Readme", "other"}
	for _, n := range names {
		e.writeFile(n, []byte(n))
	}
	if got, want := hostNames(t, e.dir), sortedCopy(names); !slices.Equal(got, want) {
		t.Fatalf("host names = %q, want the guest names %q", got, want)
	}
	if got, want := e.readdir("."), sortedCopy(names); !slices.Equal(got, want) {
		t.Fatalf("guest listing = %q, want %q", got, want)
	}

	// The fast path allocates nothing.
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := e.ws.hostPath("dir/sub/file.txt"); err != nil {
			t.Error(err)
		}
		if _, err := e.ws.hostLeaf("dir", "file.txt"); err != nil {
			t.Error(err)
		}
	})
	if allocs != 0 {
		t.Fatalf("the Linux name path allocates %v times per lookup, want 0", allocs)
	}
}

func TestPlainNamesCostNoAllocationOnTranslatingHosts(t *testing.T) {
	for _, vc := range foldingVolumes {
		t.Run(vc.name, func(t *testing.T) {
			e := newVolumeEnv(t, vc.caps, true, vc.verified, vc.win)
			allocs := testing.AllocsPerRun(100, func() {
				if _, err := e.ws.hostPath("dir/sub/file.txt"); err != nil {
					t.Error(err)
				}
			})
			if allocs != 0 {
				t.Fatalf("hostPath of a plain path allocates %v times, want 0", allocs)
			}
		})
	}
}

func TestInternalHostNamesAreHiddenOnEveryHost(t *testing.T) {
	for _, vc := range []struct {
		name string
		caps WorkspaceCaps
	}{{"linux", linuxCaps}, {"windows", winCaps}, {"mac", macCaps}} {
		t.Run(vc.name, func(t *testing.T) {
			e := newVolumeEnv(t, vc.caps, false, false, false)
			e.writeFile("visible", []byte("v"))
			for _, n := range []string{"~gvx~tmp.7", "~gvx~swap.7"} {
				if err := os.WriteFile(e.host(n), []byte("internal"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if got := e.readdir("."); !slices.Equal(got, []string{"visible"}) {
				t.Fatalf("listing = %q, want only visible", got)
			}
			for _, n := range []string{"~gvx~tmp.7", "tmp.7", "~gvx~swap.7", "swap.7"} {
				if _, err := e.stat(n); !linuxerr.Equals(linuxerr.ENOENT, err) {
					t.Fatalf("stat %q = %v, want ENOENT", n, err)
				}
			}
			// A guest name that starts with tmp. never reaches the internal
			// names, even when the codec must escape it.
			if vc.caps.RestrictsWinNames {
				e.writeFile("tmp.9:", []byte("x"))
				if got := hostNames(t, e.dir); slices.Contains(got, "~gvx~tmp.9%3A") {
					t.Fatalf("host names = %q: the guest name reached the internal namespace", got)
				}
				if got := e.readFile("tmp.9:"); string(got) != "x" {
					t.Fatalf("read tmp.9: = %q", got)
				}
			}
		})
	}
}

func TestMalformedAndForeignPrefixedHostNamesAreHidden(t *testing.T) {
	e := newVolumeEnv(t, winCSCaps, false, false, true)
	e.writeFile("shown", []byte("s"))
	for _, n := range []string{"~gvx~100%", "~gvx~%4d", "~gvx~%ZZ"} {
		if err := os.WriteFile(e.host(n), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// On a volume that keeps case, the prefix with a plain name is not a form
	// that the codec writes.
	if err := os.WriteFile(e.host("~gvx~foreign"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := e.readdir("."); !slices.Equal(got, []string{"shown"}) {
		t.Fatalf("listing = %q, want only shown", got)
	}
	for _, n := range []string{"~gvx~100%", "100%", "foreign", "~gvx~foreign"} {
		if _, err := e.stat(n); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat %q = %v, want ENOENT", n, err)
		}
	}
}

func TestGuestNameAndVisibleNameHelpers(t *testing.T) {
	e := newVolumeEnv(t, winCaps, true, true, true)
	if got := e.ws.guestName("~gvx~aux.c"); got != "aux.c" {
		t.Fatalf("guestName = %q", got)
	}
	if got := e.ws.guestName("plain"); got != "plain" {
		t.Fatalf("guestName of a plain name = %q", got)
	}
	reg := hostInfo{kind: hostKindRegular}
	if name, ok := e.ws.hostVisibleName(".", "~gvx~Net%3A%3AHTTP.3pm", reg); !ok || name != "Net::HTTP.3pm" {
		t.Fatalf("hostVisibleName = (%q, %v)", name, ok)
	}
	for _, hidden := range []string{"~gvx~%ZZ", "~gvx~tmp.1", "~gvx~swap.2"} {
		if _, ok := e.ws.hostVisibleName(".", hidden, reg); ok {
			t.Fatalf("hostVisibleName(%q) shows a hidden name", hidden)
		}
		if !e.ws.isHostClutter(".", hidden, reg) {
			t.Fatalf("isHostClutter(%q) = false, want true", hidden)
		}
	}
	if e.ws.isHostClutter(".", "plain", reg) {
		t.Fatal("isHostClutter(plain) = true")
	}
}

func TestForcedCapsAreRecorded(t *testing.T) {
	for name, caps := range codecConfigs {
		t.Run(name, func(t *testing.T) {
			e := newVolumeEnv(t, caps, !caps.CaseSensitive, !caps.CaseSensitive, caps.RestrictsWinNames)
			if got := e.ws.Caps(); got != caps {
				t.Fatalf("Caps() = %+v, want the forced %+v", got, caps)
			}
		})
	}
}
