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

package main

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/oci"
)

// cliResult is the outcome of one command run.
type cliResult struct {
	code   int
	stdout string
	stderr string
}

// cliEnv is a private cache directory and Docker config for the image commands.
type cliEnv struct {
	t        *testing.T
	cacheDir string
}

// newCLIEnv gives a test its own cache and an empty Docker config.
func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	return &cliEnv{t: t, cacheDir: filepath.Join(t.TempDir(), "cache")}
}

// run executes "rungv <command> -cache-dir <dir> <args...>" with stdin.
func (e *cliEnv) runWithStdin(stdin io.Reader, command string, args ...string) cliResult {
	e.t.Helper()
	return runCLIArgs(e.t, stdin, append([]string{command, "-cache-dir", e.cacheDir}, args...)...)
}

func (e *cliEnv) run(command string, args ...string) cliResult {
	e.t.Helper()
	return e.runWithStdin(nil, command, args...)
}

// runCLIArgs executes executeCLI with buffers for the output.
func runCLIArgs(t *testing.T, stdin io.Reader, args ...string) cliResult {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := executeCLI(context.Background(), args, stdin, &stdout, &stderr)
	return cliResult{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

// mustSucceed fails the test unless the command exited with 0.
func (r cliResult) mustSucceed(t *testing.T, what string) cliResult {
	t.Helper()
	if r.code != 0 {
		t.Fatalf("%s exited with %d\nstdout: %s\nstderr: %s", what, r.code, r.stdout, r.stderr)
	}
	return r
}

// testRegistry is an in-process registry with one image at gvx/app:v1.
type testRegistry struct {
	*testimage.Registry
	// Host is the registry name in an image reference, such as "127.0.0.1:41234".
	Host string
}

// ref returns the reference of the image under tag.
func (r testRegistry) ref(tag string) string { return r.Host + "/gvx/app:" + tag }

// startRegistry serves one image of the host architecture with the given layers.
func startRegistry(t *testing.T, layers ...testimage.File) testRegistry {
	t.Helper()
	var tars [][]byte
	for _, l := range layers {
		raw, err := testimage.Tar(l)
		if err != nil {
			t.Fatalf("build layer %s: %v", l.Name, err)
		}
		tars = append(tars, raw)
	}
	reg := testimage.NewRegistryServer(t, "gvx/app", "v1", testimage.Image{
		Arch: runtime.GOARCH, Layers: tars, Cmd: []string{"/bin/true"}, Env: []string{"A=1"}, WorkingDir: "/w",
	})
	return testRegistry{Registry: reg, Host: strings.TrimPrefix(reg.URL, "http://")}
}

// twoFiles are two layers with one file each.
func twoFiles() []testimage.File {
	return []testimage.File{{Name: "one.txt", Data: []byte("1")}, {Name: "two.txt", Data: []byte("2")}}
}

// pull pulls ref into the cache of e and fails the test on error.
func (e *cliEnv) pull(ref string) {
	e.t.Helper()
	e.run("pull", ref).mustSucceed(e.t, "pull "+ref)
}

// imageIDs returns the full image IDs that "images -q --no-trunc -a" prints.
func (e *cliEnv) imageIDs() []string {
	e.t.Helper()
	out := e.run("images", "-q", "--no-trunc", "-a").mustSucceed(e.t, "images -q").stdout
	return strings.Fields(out)
}

// basicRegistry answers /v2/ behind HTTP basic authentication.
func basicRegistry(t *testing.T, user, pass string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != user || p != pass {
			w.Header().Set("Www-Authenticate", `Basic realm="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestHumanSizeUsesDecimalUnits(t *testing.T) {
	for _, tc := range []struct {
		size int64
		want string
	}{
		{0, "0B"}, {999, "999B"}, {1000, "1kB"}, {7_800_000, "7.8MB"}, {1_234_567_890, "1.235GB"},
	} {
		if got := humanSize(tc.size); got != tc.want {
			t.Errorf("humanSize(%d) = %q, want %q", tc.size, got, tc.want)
		}
	}
}

func TestHumanDurationUsesCoarseUnits(t *testing.T) {
	for _, tc := range []struct {
		d    time.Duration
		want string
	}{
		{500 * time.Millisecond, "Less than a second"},
		{30 * time.Second, "30 seconds"},
		{time.Minute + time.Second, "About a minute"},
		{5 * time.Minute, "5 minutes"},
		{time.Hour, "About an hour"},
		{30 * time.Hour, "30 hours"},
		{3 * 24 * time.Hour, "3 days"},
		{6 * 7 * 24 * time.Hour, "6 weeks"},
		{100 * 24 * time.Hour, "3 months"},
		{3 * 365 * 24 * time.Hour, "3 years"},
	} {
		if got := humanDuration(tc.d); got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
	if got := createdSince(time.Time{}, time.Now()); got != "N/A" {
		t.Errorf("createdSince(zero) = %q, want N/A", got)
	}
}

func TestImageRowsListsTagsDigestsAndDanglingImages(t *testing.T) {
	images := []oci.Image{
		{Repository: "library/alpine", BaseURL: oci.DefaultRegistryBaseURL, ID: "sha256:aaa", Tags: []string{"3.20", "latest"}, Digest: "sha256:d1"},
		{Repository: "org/pinned", BaseURL: "https://ghcr.io", ID: "sha256:bbb", Pinned: true, Digest: "sha256:d2"},
		{ID: "sha256:ccc", Digest: "sha256:d3"},
	}
	rows := imageRows(images, false, nil)
	var got []string
	for _, r := range rows {
		got = append(got, r.Repository+" "+r.Tag)
	}
	if want := "alpine 3.20|alpine latest|ghcr.io/org/pinned <none>"; strings.Join(got, "|") != want {
		t.Errorf("rows = %q, want %q", strings.Join(got, "|"), want)
	}

	all := imageRows(images, true, nil)
	if len(all) != 4 || all[3].Repository != "<none>" || all[3].Tag != "<none>" {
		t.Errorf("rows with all = %+v, want a dangling row <none> <none> last", all)
	}

	filter, err := parseImageFilter("alpine:latest")
	if err != nil {
		t.Fatal(err)
	}
	if rows := imageRows(images, true, &filter); len(rows) != 1 || rows[0].Tag != "latest" {
		t.Errorf("rows for alpine:latest = %+v, want the latest row", rows)
	}
	filter, err = parseImageFilter("alpine")
	if err != nil {
		t.Fatal(err)
	}
	if rows := imageRows(images, true, &filter); len(rows) != 2 {
		t.Errorf("rows for alpine = %+v, want both tags", rows)
	}
}
