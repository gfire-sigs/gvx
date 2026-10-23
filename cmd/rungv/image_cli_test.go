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
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"
)

var (
	digestLine = regexp.MustCompile(`(?m)^Digest: (sha256:[0-9a-f]{64})$`)
	shortID    = regexp.MustCompile(`^[0-9a-f]{12}$`)
)

func TestPullPrintsTheDigestAndStatusLines(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)

	first := env.run("pull", reg.ref("v1")).mustSucceed(t, "first pull")
	for _, want := range []string{
		"v1: Pulling from gvx/app",
		"Status: Downloaded newer image for " + reg.ref("v1"),
		reg.ref("v1") + "\n",
	} {
		if !strings.Contains(first.stdout, want) {
			t.Errorf("first pull output lacks %q:\n%s", want, first.stdout)
		}
	}
	m := digestLine.FindStringSubmatch(first.stdout)
	if m == nil {
		t.Fatalf("first pull output has no Digest line:\n%s", first.stdout)
	}

	second := env.run("pull", reg.ref("v1")).mustSucceed(t, "second pull")
	if !strings.Contains(second.stdout, "Status: Image is up to date for "+reg.ref("v1")) {
		t.Errorf("second pull output lacks the up-to-date status:\n%s", second.stdout)
	}
	if got := digestLine.FindStringSubmatch(second.stdout); got == nil || got[1] != m[1] {
		t.Errorf("second pull digest = %v, want %s", got, m[1])
	}

	byDigest := env.run("pull", reg.Host+"/gvx/app@"+m[1]).mustSucceed(t, "pull by digest")
	if !strings.Contains(byDigest.stdout, m[1]+": Pulling from gvx/app") || !strings.Contains(byDigest.stdout, "Image is up to date") {
		t.Errorf("pull by digest output:\n%s", byDigest.stdout)
	}
}

func TestPullAcceptsTheRegistryURLOverride(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	out := env.run("pull", "-registry-url", reg.URL, "gvx/app:v1").mustSucceed(t, "pull with an override")
	if !strings.Contains(out.stdout, "Status: Downloaded newer image for "+reg.ref("v1")) {
		t.Errorf("output lacks the status line:\n%s", out.stdout)
	}
}

func TestPullRejectsABadReference(t *testing.T) {
	env := newCLIEnv(t)
	res := env.run("pull", "Bad/Name:v1")
	if res.code != 2 || !strings.Contains(res.stderr, "uppercase") {
		t.Errorf("pull of a bad reference = (%d, %q), want exit 2 and an uppercase message", res.code, res.stderr)
	}
}

func TestImagesListsAPulledImageInDockerColumns(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))

	out := env.run("images").mustSucceed(t, "images").stdout
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("images printed %d lines, want a header and one row:\n%s", len(lines), out)
	}
	if got := strings.Fields(lines[0]); !slices.Equal(got, []string{"REPOSITORY", "TAG", "IMAGE", "ID", "CREATED", "SIZE"}) {
		t.Errorf("header = %v", got)
	}
	row := strings.Fields(lines[1])
	if len(row) < 5 || row[0] != reg.Host+"/gvx/app" || row[1] != "v1" || !shortID.MatchString(row[2]) {
		t.Errorf("row = %v, want repository %s, tag v1, and a 12 digit ID", row, reg.Host+"/gvx/app")
	}

	digests := env.run("images", "--digests").mustSucceed(t, "images --digests").stdout
	if !strings.Contains(digests, "DIGEST") || !regexp.MustCompile(`sha256:[0-9a-f]{64}`).MatchString(digests) {
		t.Errorf("images --digests output lacks a digest column:\n%s", digests)
	}
}

func TestImagesQuietNoTruncAndFormat(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))
	short := strings.TrimSpace(env.run("images", "-q").mustSucceed(t, "images -q").stdout)
	if !shortID.MatchString(short) {
		t.Fatalf("images -q = %q, want one 12 digit ID", short)
	}
	full := strings.TrimSpace(env.run("images", "-q", "--no-trunc").mustSucceed(t, "images -q --no-trunc").stdout)
	if !strings.HasPrefix(full, "sha256:"+short) || len(full) != len("sha256:")+64 {
		t.Errorf("images -q --no-trunc = %q, want the full ID that starts with %s", full, short)
	}

	out := env.run("images", "--format", "json").mustSucceed(t, "images --format json").stdout
	var row map[string]string
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &row); err != nil {
		t.Fatalf("images --format json printed %q: %v", out, err)
	}
	if row["Repository"] != reg.Host+"/gvx/app" || row["Tag"] != "v1" || row["ID"] != short {
		t.Errorf("json row = %v", row)
	}
	if res := env.run("images", "--format", "{{.ID}}"); res.code != 2 {
		t.Errorf("images with a template = exit %d, want 2", res.code)
	}
}

func TestImagesFiltersByName(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))

	for name, want := range map[string]bool{
		reg.Host + "/gvx/app":     true,
		reg.ref("v1"):             true,
		reg.ref("other"):          false,
		reg.Host + "/gvx/nothing": false,
	} {
		out := env.run("images", "-q", name).mustSucceed(t, "images "+name).stdout
		if got := strings.TrimSpace(out) != ""; got != want {
			t.Errorf("images %s printed %q, want a row: %v", name, out, want)
		}
	}
}

func TestTagAddsNamesAndRmiRemovesThemOneByOne(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))
	env.run("tag", reg.ref("v1"), "mine:dev").mustSucceed(t, "tag into Docker Hub")
	env.run("tag", reg.ref("v1"), "localhost:5000/team/app:prod").mustSucceed(t, "tag into another registry")

	out := env.run("images").mustSucceed(t, "images").stdout
	for _, want := range []string{reg.Host + "/gvx/app", "mine", "localhost:5000/team/app"} {
		if !strings.Contains(out, want) {
			t.Errorf("images output lacks %q:\n%s", want, out)
		}
	}
	if ids := env.imageIDs(); len(ids) != 3 || ids[0] != ids[1] || ids[1] != ids[2] {
		t.Errorf("image IDs = %v, want one shared ID on three rows", ids)
	}

	res := env.run("rmi", "mine:dev").mustSucceed(t, "rmi mine:dev")
	if res.stdout != "Untagged: mine:dev\n" {
		t.Errorf("rmi mine:dev printed %q, want only the Untagged line because the ID lives on", res.stdout)
	}
	if env.run("inspect", "mine:dev").code == 0 {
		t.Error("inspect still finds mine:dev after rmi")
	}
}

func TestRmiOfTheLastNameDeletesTheImage(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))
	id := env.imageIDs()[0]

	res := env.run("rmi", reg.ref("v1")).mustSucceed(t, "rmi")
	for _, want := range []string{"Untagged: " + reg.ref("v1") + "\n", "Deleted: " + id + "\n"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("rmi output lacks %q:\n%s", want, res.stdout)
		}
	}
	if ids := env.imageIDs(); len(ids) != 0 {
		t.Errorf("images still lists %v after rmi", ids)
	}
	entries, err := os.ReadDir(env.cacheDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("the cache still holds %s after the last image went", e.Name())
	}
}

func TestRmiRefusesAnIDWithSeveralTagsUnlessForced(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))
	env.run("tag", reg.ref("v1"), "mine:dev").mustSucceed(t, "tag")
	id := env.imageIDs()[0]
	short := strings.TrimPrefix(id, "sha256:")[:12]

	res := env.run("rmi", short)
	if res.code != 1 || !strings.Contains(res.stderr, "must be forced") || res.stdout != "" {
		t.Fatalf("rmi of a shared ID = (%d, stdout %q, stderr %q), want exit 1, no output, and a force hint", res.code, res.stdout, res.stderr)
	}
	if len(env.imageIDs()) != 2 {
		t.Error("the refused rmi removed something")
	}

	forced := env.run("rmi", "-f", short).mustSucceed(t, "rmi -f")
	for _, want := range []string{"Untagged: mine:dev\n", "Untagged: " + reg.ref("v1") + "\n", "Deleted: " + id + "\n"} {
		if !strings.Contains(forced.stdout, want) {
			t.Errorf("rmi -f output lacks %q:\n%s", want, forced.stdout)
		}
	}
	if len(env.imageIDs()) != 0 {
		t.Error("images remain after rmi -f")
	}
}

func TestRmiOfAnUnknownImageFailsAndContinues(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))

	res := env.run("rmi", "nothing:1", reg.ref("v1"))
	if res.code != 1 || !strings.Contains(res.stderr, "no such image: nothing:1") {
		t.Errorf("rmi = (%d, %q), want exit 1 and a no-such-image message", res.code, res.stderr)
	}
	if !strings.Contains(res.stdout, "Untagged: "+reg.ref("v1")) {
		t.Errorf("rmi stopped at the unknown image; stdout %q", res.stdout)
	}
}

func TestInspectPrintsADockerShapedJSONArray(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))
	id := env.imageIDs()[0]

	out := env.run("inspect", reg.ref("v1"), id).mustSucceed(t, "inspect").stdout
	var got []struct {
		ID           string   `json:"Id"`
		RepoTags     []string `json:"RepoTags"`
		RepoDigests  []string `json:"RepoDigests"`
		Architecture string   `json:"Architecture"`
		Os           string   `json:"Os"`
		Config       struct {
			Env        []string
			Cmd        []string
			Entrypoint []string
			WorkingDir string
			User       string
		} `json:"Config"`
		RootFS struct {
			Type   string
			Layers []string
		} `json:"RootFS"`
		Size int64 `json:"Size"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("inspect printed invalid JSON: %v\n%s", err, out)
	}
	if len(got) != 2 {
		t.Fatalf("inspect printed %d objects, want 2", len(got))
	}
	for _, img := range got {
		if img.ID != id || !slices.Equal(img.RepoTags, []string{reg.ref("v1")}) || len(img.RepoDigests) != 1 ||
			!strings.HasPrefix(img.RepoDigests[0], reg.Host+"/gvx/app@sha256:") {
			t.Errorf("identity fields = %+v, want ID %s with tag and digest", img, id)
		}
		if img.Architecture != runtime.GOARCH || img.Os != "linux" || img.Size <= 0 {
			t.Errorf("platform = %s/%s size %d", img.Os, img.Architecture, img.Size)
		}
		if !slices.Equal(img.Config.Cmd, []string{"/bin/true"}) || !slices.Equal(img.Config.Env, []string{"A=1"}) ||
			img.Config.WorkingDir != "/w" || img.Config.Entrypoint == nil {
			t.Errorf("config = %+v, want Cmd, Env, WorkingDir, and a non-null Entrypoint", img.Config)
		}
		if img.RootFS.Type != "layers" || len(img.RootFS.Layers) != 2 {
			t.Errorf("rootfs = %+v, want two layers", img.RootFS)
		}
	}
}

func TestInspectOfAMissingImageReportsItAndPrintsTheRest(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))

	res := env.run("inspect", "nothing:1", reg.ref("v1"))
	if res.code != 1 || !strings.Contains(res.stderr, "no such image: nothing:1") {
		t.Errorf("inspect = (%d, %q), want exit 1 and a no-such-image message", res.code, res.stderr)
	}
	var got []map[string]any
	if err := json.Unmarshal([]byte(res.stdout), &got); err != nil || len(got) != 1 {
		t.Errorf("inspect stdout = %q (%v), want an array with the one found image", res.stdout, err)
	}
}

func TestSaveThenLoadRestoresTheImageInAnotherCache(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	src := newCLIEnv(t)
	src.pull(reg.ref("v1"))
	srcID := src.imageIDs()[0]
	archive := filepath.Join(t.TempDir(), "image.tar")

	src.run("save", "-o", archive, reg.ref("v1")).mustSucceed(t, "save")
	if entries, err := os.ReadDir(filepath.Dir(archive)); err != nil || len(entries) != 1 {
		t.Fatalf("the output directory holds %v (%v), want only the archive", entries, err)
	}

	dst := newCLIEnv(t)
	out := dst.run("load", "-i", archive).mustSucceed(t, "load -i").stdout
	if out != "Loaded image: "+reg.ref("v1")+"\n" {
		t.Errorf("load printed %q, want the Loaded image line", out)
	}
	if ids := dst.imageIDs(); !slices.Equal(ids, []string{srcID}) {
		t.Errorf("the loaded image ID = %v, want %s", ids, srcID)
	}
	if got := dst.run("images", "--digests").mustSucceed(t, "images").stdout; !strings.Contains(got, "<none>") {
		t.Errorf("a loaded image should show no registry digest:\n%s", got)
	}

	// The same archive loads from standard input, and -q is silent.
	raw, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	third := newCLIEnv(t)
	quiet := third.runWithStdin(bytes.NewReader(raw), "load", "-q").mustSucceed(t, "load -q from stdin")
	if quiet.stdout != "" {
		t.Errorf("load -q printed %q", quiet.stdout)
	}
	if ids := third.imageIDs(); !slices.Equal(ids, []string{srcID}) {
		t.Errorf("image IDs after the stdin load = %v, want %s", ids, srcID)
	}
}

func TestSaveWritesTheArchiveToStandardOutput(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	src := newCLIEnv(t)
	src.pull(reg.ref("v1"))

	res := src.run("save", reg.ref("v1")).mustSucceed(t, "save to stdout")
	dst := newCLIEnv(t)
	out := dst.runWithStdin(strings.NewReader(res.stdout), "load").mustSucceed(t, "load").stdout
	if out != "Loaded image: "+reg.ref("v1")+"\n" {
		t.Errorf("load printed %q", out)
	}
}

func TestSaveByIDLoadsAsAnImageWithoutAName(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	src := newCLIEnv(t)
	src.pull(reg.ref("v1"))
	id := src.imageIDs()[0]

	res := src.run("save", id).mustSucceed(t, "save by ID")
	dst := newCLIEnv(t)
	out := dst.runWithStdin(strings.NewReader(res.stdout), "load").mustSucceed(t, "load").stdout
	if out != "Loaded image ID: "+id+"\n" {
		t.Errorf("load printed %q, want the image ID line", out)
	}
	if got := dst.run("images", "-q").mustSucceed(t, "images").stdout; got != "" {
		t.Errorf("images listed the dangling image without -a: %q", got)
	}
	if got := dst.run("images", "-a").mustSucceed(t, "images -a").stdout; !strings.Contains(got, "<none>") {
		t.Errorf("images -a lacks the dangling image:\n%s", got)
	}
}

func TestSaveRefusesAnImageThatCameFromAnArchive(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	src := newCLIEnv(t)
	src.pull(reg.ref("v1"))
	archive := filepath.Join(t.TempDir(), "image.tar")
	src.run("save", "-o", archive, reg.ref("v1")).mustSucceed(t, "save")

	dst := newCLIEnv(t)
	dst.run("load", "-i", archive).mustSucceed(t, "load")
	again := filepath.Join(t.TempDir(), "again.tar")
	res := dst.run("save", "-o", again, reg.ref("v1"))
	if res.code != 1 || !strings.Contains(res.stderr, "registry") {
		t.Errorf("save of a loaded image = (%d, %q), want exit 1 and a message about the registry source", res.code, res.stderr)
	}
	if _, err := os.Stat(again); err == nil {
		t.Error("save wrote a file for an image that cannot be saved")
	}
}

func TestSaveLeavesNoFileWhenTheRegistryIsGone(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	src := newCLIEnv(t)
	src.pull(reg.ref("v1"))
	reg.Close()

	dir := t.TempDir()
	res := src.run("save", "-o", filepath.Join(dir, "image.tar"), reg.ref("v1"))
	if res.code != 1 {
		t.Fatalf("save with the registry down exited with %d, want 1", res.code)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Errorf("the output directory holds %v (%v), want it empty", entries, err)
	}
	toStdout := src.run("save", reg.ref("v1"))
	if toStdout.code != 1 || toStdout.stdout != "" {
		t.Errorf("save to stdout with the registry down = (%d, %d bytes), want exit 1 and no output", toStdout.code, len(toStdout.stdout))
	}
}

func TestSaveAndLoadReportUsageErrors(t *testing.T) {
	env := newCLIEnv(t)
	for _, tc := range []struct {
		name string
		res  cliResult
		code int
		want string
	}{
		{"save without images", env.run("save"), 2, "missing IMAGE"},
		{"save of an unknown image", env.run("save", "nothing:1"), 1, "no such image"},
		{"load without input", env.runWithStdin(nil, "load"), 2, "no archive"},
		{"load of a missing file", env.run("load", "-i", filepath.Join(t.TempDir(), "absent.tar")), 1, "absent.tar"},
		{"load of a text file", env.runWithStdin(strings.NewReader("not a tar"), "load"), 1, "rungv load"},
		{"rmi without images", env.run("rmi"), 2, "missing IMAGE"},
		{"inspect without images", env.run("inspect"), 2, "missing IMAGE"},
		{"tag with one argument", env.run("tag", "a"), 2, "SOURCE and TARGET"},
		{"tag of an unknown image", env.run("tag", "nothing:1", "other:1"), 1, "no such image"},
		{"images with two names", env.run("images", "a", "b"), 2, "at most one"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.res.code != tc.code || !strings.Contains(tc.res.stderr, tc.want) {
				t.Errorf("exit %d, stderr %q, want exit %d and a message with %q", tc.res.code, tc.res.stderr, tc.code, tc.want)
			}
		})
	}
}

func TestTagRejectsADigestTargetAndABadName(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.pull(reg.ref("v1"))
	digest := digestLine.FindStringSubmatch(env.run("pull", reg.ref("v1")).stdout)[1]

	if res := env.run("tag", reg.ref("v1"), "other@"+digest); res.code != 2 {
		t.Errorf("tag with a digest target exited with %d, want 2", res.code)
	}
	if res := env.run("tag", reg.ref("v1"), "Upper:1"); res.code != 2 {
		t.Errorf("tag with an uppercase target exited with %d, want 2", res.code)
	}
}

func TestLoginStoresCredentialsAndLogoutRemovesThem(t *testing.T) {
	registry := basicRegistry(t, "alice", "s3cret")
	host := strings.TrimPrefix(registry.URL, "http://")
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)

	res := runCLIArgs(t, strings.NewReader("s3cret\n"), "login", "-u", "alice", "--password-stdin", registry.URL)
	if res.code != 0 || strings.TrimSpace(res.stdout) != "Login Succeeded" {
		t.Fatalf("login = (%d, %q, %q), want Login Succeeded", res.code, res.stdout, res.stderr)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatalf("config.json: %v", err)
	}
	var cfg struct {
		Auths map[string]struct{ Auth string } `json:"auths"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if got := cfg.Auths[host].Auth; got != base64.StdEncoding.EncodeToString([]byte("alice:s3cret")) {
		t.Errorf("auths[%s] = %q, want base64 of alice:s3cret", host, got)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(filepath.Join(dir, "config.json")); err != nil || info.Mode().Perm() != 0o600 {
			t.Errorf("config.json mode = %v (%v), want 0600", info.Mode(), err)
		}
	}

	out := runCLIArgs(t, nil, "logout", registry.URL)
	if out.code != 0 || out.stdout != "Removing login credentials for "+host+"\n" {
		t.Errorf("logout = (%d, %q, %q)", out.code, out.stdout, out.stderr)
	}
	again := runCLIArgs(t, nil, "logout", registry.URL)
	if again.code != 0 || again.stdout != "Not logged in to "+host+"\n" {
		t.Errorf("second logout = (%d, %q, %q)", again.code, again.stdout, again.stderr)
	}
}

func TestLoginReadsUserAndPasswordLinesWhenStandardInputIsNotATerminal(t *testing.T) {
	registry := basicRegistry(t, "bob", "pw")
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	res := runCLIArgs(t, strings.NewReader("bob\npw\n"), "login", registry.URL)
	if res.code != 0 || strings.TrimSpace(res.stdout) != "Login Succeeded" {
		t.Errorf("login = (%d, %q, %q), want Login Succeeded", res.code, res.stdout, res.stderr)
	}
}

func TestLoginWithAWrongPasswordStoresNothing(t *testing.T) {
	registry := basicRegistry(t, "alice", "s3cret")
	dir := t.TempDir()
	t.Setenv("DOCKER_CONFIG", dir)

	res := runCLIArgs(t, strings.NewReader("wrong\n"), "login", "-u", "alice", "--password-stdin", registry.URL)
	if res.code != 1 || res.stdout != "" || res.stderr == "" {
		t.Errorf("login = (%d, %q, %q), want exit 1 with an error and no success line", res.code, res.stdout, res.stderr)
	}
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		t.Error("a failed login wrote config.json")
	}
}

func TestLoginReportsUsageErrors(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	for name, tc := range map[string]struct {
		args  []string
		stdin string
		want  string
	}{
		"password and stdin together": {[]string{"-u", "a", "-p", "x", "--password-stdin"}, "x\n", "mutually exclusive"},
		"stdin without a user":        {[]string{"--password-stdin"}, "x\n", "--username"},
		"empty password":              {[]string{"-u", "a"}, "\n", "required"},
		"two registries":              {[]string{"-u", "a", "-p", "x", "one", "two"}, "", "at most one"},
		"bad registry":                {[]string{"-u", "a", "-p", "x", "bad_host"}, "", "bad_host"},
	} {
		t.Run(name, func(t *testing.T) {
			res := runCLIArgs(t, strings.NewReader(tc.stdin), append([]string{"login"}, tc.args...)...)
			if res.code == 0 || !strings.Contains(res.stderr, tc.want) {
				t.Errorf("login %v = (%d, %q), want a failure that mentions %q", tc.args, res.code, res.stderr, tc.want)
			}
		})
	}
}

func TestHelpListsTheImageCommands(t *testing.T) {
	res := runCLIArgs(t, nil, "help")
	for _, want := range []string{"rungv images", "rungv rmi", "rungv tag", "rungv inspect", "rungv save", "rungv load", "rungv login", "rungv logout"} {
		if !strings.Contains(res.stdout, want) {
			t.Errorf("help lacks %q", want)
		}
	}
}
