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
	"errors"
	"path"
	"slices"
	"strings"
	"testing"
)

// fakeGuest is a map-backed GuestFS. A link makes two paths name one file, as
// a symbolic link does.
type fakeGuest struct {
	files  map[string][]byte
	dirs   map[string]bool
	links  map[string]string
	writes []string
}

func newFakeGuest() *fakeGuest {
	return &fakeGuest{files: map[string][]byte{}, dirs: map[string]bool{}, links: map[string]string{}}
}

func (g *fakeGuest) resolve(p string) string {
	if target, ok := g.links[p]; ok {
		return target
	}
	return p
}

func (g *fakeGuest) ReadFile(p string) ([]byte, bool, error) {
	data, ok := g.files[g.resolve(p)]
	return data, ok, nil
}

func (g *fakeGuest) DirExists(p string) (bool, error) { return g.dirs[p], nil }

func (g *fakeGuest) WriteFile(p string, data []byte) error {
	g.files[g.resolve(p)] = bytes.Clone(data)
	g.writes = append(g.writes, p)
	for dir := path.Dir(p); dir != "/"; dir = path.Dir(dir) {
		g.dirs[dir] = true
	}
	return nil
}

func (g *fakeGuest) roots(t *testing.T, p string) [][]byte {
	t.Helper()
	data, ok := g.files[g.resolve(p)]
	if !ok {
		t.Fatalf("%s does not exist", p)
	}
	return ParsePEM(data)
}

func (g *fakeGuest) anchors(dir string) [][]byte {
	var names []string
	for p := range g.files {
		if path.Dir(p) == dir {
			names = append(names, p)
		}
	}
	slices.Sort(names)
	var out [][]byte
	for _, name := range names {
		out = append(out, ParsePEM(g.files[name])...)
	}
	return out
}

func noneCovered(string) bool { return false }

func TestInstallDebianLayoutAddsRootsAndAnchors(t *testing.T) {
	image1, image2, host1, host2 := makeRoot(t, "i1"), makeRoot(t, "i2"), makeRoot(t, "h1"), makeRoot(t, "h2")
	g := newFakeGuest()
	g.files[DefaultBundlePath] = pemOf(image1, image2)
	g.dirs[DebianAnchorDir] = true

	if err := Install(g, [][]byte{image2, host1, host2, host1}, noneCovered); err != nil {
		t.Fatal(err)
	}

	if got := g.roots(t, DefaultBundlePath); !sameDER(got, [][]byte{image1, image2, host1, host2}) {
		t.Errorf("bundle holds %d certificates, want image1 image2 host1 host2 (the image root image2 once)", len(got))
	}
	if got := g.anchors(DebianAnchorDir); !sameDER(sortedDER(got), sortedDER([][]byte{host1, host2})) {
		t.Errorf("anchor directory holds %d certificates, want host1 and host2 only", len(got))
	}
	for p := range g.files {
		if path.Dir(p) == DebianAnchorDir && !(strings.HasPrefix(path.Base(p), "gvx-host-") && strings.HasSuffix(p, ".crt")) {
			t.Errorf("anchor file %s does not match gvx-host-*.crt", p)
		}
	}
	if g.dirs[RedHatAnchorDir] {
		t.Errorf("Install created %s in a Debian image", RedHatAnchorDir)
	}
	if _, ok := g.files["/etc/ssl/cert.pem"]; ok {
		t.Errorf("Install created /etc/ssl/cert.pem, which the image lacks")
	}
}

func TestInstallAlpineLayoutWritesTheSharedBundleOnce(t *testing.T) {
	image, host := makeRoot(t, "image"), makeRoot(t, "host")
	g := newFakeGuest()
	g.files[DefaultBundlePath] = pemOf(image)
	g.links["/etc/ssl/cert.pem"] = DefaultBundlePath

	if err := Install(g, [][]byte{host}, noneCovered); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{DefaultBundlePath, "/etc/ssl/cert.pem"} {
		if got := g.roots(t, p); !sameDER(got, [][]byte{image, host}) {
			t.Errorf("%s holds %d certificates, want image and host once each", p, len(got))
		}
	}
	bundleWrites := 0
	for _, p := range g.writes {
		if p == DefaultBundlePath || p == "/etc/ssl/cert.pem" {
			bundleWrites++
		}
	}
	if bundleWrites != 1 {
		t.Errorf("Install wrote the shared bundle %d times, want 1: %v", bundleWrites, g.writes)
	}
	if got := g.anchors(DebianAnchorDir); !sameDER(got, [][]byte{host}) {
		t.Errorf("Alpine without the directory %s: anchors = %d certificates, want the host root", DebianAnchorDir, len(got))
	}
}

func TestInstallRedHatLayout(t *testing.T) {
	image, host := makeRoot(t, "image"), makeRoot(t, "host")
	extracted := "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
	g := newFakeGuest()
	g.files[extracted] = pemOf(image)
	g.links["/etc/pki/tls/certs/ca-bundle.crt"] = extracted
	g.dirs[RedHatAnchorDir] = true

	if err := Install(g, [][]byte{host}, noneCovered); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{extracted, "/etc/pki/tls/certs/ca-bundle.crt"} {
		if got := g.roots(t, p); !sameDER(got, [][]byte{image, host}) {
			t.Errorf("%s holds %d certificates, want image and host", p, len(got))
		}
	}
	if got := g.anchors(RedHatAnchorDir); !sameDER(got, [][]byte{host}) {
		t.Errorf("%s holds %d certificates, want the host root", RedHatAnchorDir, len(got))
	}
	if g.dirs[DebianAnchorDir] {
		t.Errorf("Install created %s in a Red Hat image", DebianAnchorDir)
	}
	if _, ok := g.files[DefaultBundlePath]; ok {
		t.Errorf("Install created %s in an image that has a bundle", DefaultBundlePath)
	}
}

func TestInstallSuseBundle(t *testing.T) {
	image, host := makeRoot(t, "image"), makeRoot(t, "host")
	g := newFakeGuest()
	g.files["/etc/ssl/ca-bundle.pem"] = pemOf(image)

	if err := Install(g, [][]byte{host}, noneCovered); err != nil {
		t.Fatal(err)
	}
	if got := g.roots(t, "/etc/ssl/ca-bundle.pem"); !sameDER(got, [][]byte{image, host}) {
		t.Errorf("bundle holds %d certificates, want image and host", len(got))
	}
}

func TestInstallImageWithoutBundleCreatesTheDefaultBundle(t *testing.T) {
	a, b := makeRoot(t, "a"), makeRoot(t, "b")
	g := newFakeGuest()

	if err := Install(g, [][]byte{a, b}, noneCovered); err != nil {
		t.Fatal(err)
	}

	if got := g.roots(t, DefaultBundlePath); !sameDER(got, [][]byte{a, b}) {
		t.Errorf("new bundle holds %d certificates, want a and b", len(got))
	}
	if got := g.anchors(DebianAnchorDir); len(got) != 2 {
		t.Errorf("anchor directory holds %d certificates, want 2", len(got))
	}
}

func TestInstallKeepsEveryRootAnImageBundleAlreadyHolds(t *testing.T) {
	image := makeRoot(t, "image")
	g := newFakeGuest()
	original := append([]byte("# Mozilla bundle\n"), pemOf(image)...)
	g.files[DefaultBundlePath] = original

	if err := Install(g, [][]byte{image}, noneCovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(g.files[DefaultBundlePath], original) {
		t.Errorf("Install changed a bundle that holds every host root")
	}
	if len(g.writes) != 0 {
		t.Errorf("Install wrote %v when the image holds every host root", g.writes)
	}
}

func TestInstallKeepsTheImageBundleText(t *testing.T) {
	image, host := makeRoot(t, "image"), makeRoot(t, "host")
	head := append([]byte("Comment of the distribution\n"), bytes.TrimSuffix(pemOf(image), []byte("\n"))...)
	g := newFakeGuest()
	g.files[DefaultBundlePath] = head

	if err := Install(g, [][]byte{host}, noneCovered); err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(g.files[DefaultBundlePath], append(bytes.Clone(head), '\n')) {
		t.Errorf("the image text changed or the new block does not start on a new line:\n%s", g.files[DefaultBundlePath])
	}
}

func TestInstallIsIdempotent(t *testing.T) {
	image, host := makeRoot(t, "image"), makeRoot(t, "host")
	g := newFakeGuest()
	g.files[DefaultBundlePath] = pemOf(image)
	g.links["/etc/ssl/cert.pem"] = DefaultBundlePath
	g.dirs[DebianAnchorDir] = true

	if err := Install(g, [][]byte{host}, noneCovered); err != nil {
		t.Fatal(err)
	}
	snapshot := newFakeGuest()
	for k, v := range g.files {
		snapshot.files[k] = bytes.Clone(v)
	}
	g.writes = nil
	if err := Install(g, [][]byte{host}, noneCovered); err != nil {
		t.Fatal(err)
	}
	for p, want := range snapshot.files {
		if !bytes.Equal(g.files[p], want) {
			t.Errorf("a second Install changed %s", p)
		}
	}
	if len(g.files) != len(snapshot.files) {
		t.Errorf("a second Install created files: %d, want %d", len(g.files), len(snapshot.files))
	}
}

func TestInstallSkipsPathsThatAMountCovers(t *testing.T) {
	image, host := makeRoot(t, "image"), makeRoot(t, "host")
	g := newFakeGuest()
	g.files[DefaultBundlePath] = pemOf(image)
	g.files["/etc/ssl/cert.pem"] = pemOf(image)
	g.dirs[DebianAnchorDir] = true
	covered := func(p string) bool {
		return p == "/etc/ssl/cert.pem" || strings.HasPrefix(p, DebianAnchorDir+"/")
	}

	if err := Install(g, [][]byte{host}, covered); err != nil {
		t.Fatal(err)
	}

	if got := g.roots(t, DefaultBundlePath); !sameDER(got, [][]byte{image, host}) {
		t.Errorf("the uncovered bundle holds %d certificates, want image and host", len(got))
	}
	if got := g.roots(t, "/etc/ssl/cert.pem"); !sameDER(got, [][]byte{image}) {
		t.Errorf("the covered bundle changed: it holds %d certificates, want only image", len(got))
	}
	if got := g.anchors(DebianAnchorDir); len(got) != 0 {
		t.Errorf("Install wrote %d anchors below a covered directory", len(got))
	}
}

func TestInstallDoesNotCreateTheDefaultBundleWhenAMountCoversIt(t *testing.T) {
	host := makeRoot(t, "host")
	g := newFakeGuest()
	covered := func(p string) bool { return p == DefaultBundlePath }

	if err := Install(g, [][]byte{host}, covered); err != nil {
		t.Fatal(err)
	}
	if _, ok := g.files[DefaultBundlePath]; ok {
		t.Errorf("Install wrote the covered path %s", DefaultBundlePath)
	}
}

func TestInstallReportsReadAndWriteErrors(t *testing.T) {
	host := makeRoot(t, "host")
	boom := errors.New("boom")
	for _, tc := range []struct {
		name string
		fs   GuestFS
	}{
		{"read", errGuest{read: boom}},
		{"write", errGuest{write: boom}},
		{"dir", errGuest{dir: boom}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Install(tc.fs, [][]byte{host}, noneCovered); !errors.Is(err, boom) {
				t.Errorf("Install error = %v, want it to wrap %v", err, boom)
			}
		})
	}
}

type errGuest struct{ read, write, dir error }

func (g errGuest) ReadFile(string) ([]byte, bool, error) { return nil, false, g.read }
func (g errGuest) DirExists(string) (bool, error)        { return false, g.dir }
func (g errGuest) WriteFile(string, []byte) error        { return g.write }

func sortedDER(ders [][]byte) [][]byte {
	out := slices.Clone(ders)
	slices.SortFunc(out, bytes.Compare)
	return out
}
