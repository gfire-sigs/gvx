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

package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// helperCall is one run of a fake credential helper.
type helperCall struct {
	helper, action, input string
}

// fakeHelper is a HelperRunner that answers from a table and records its calls.
type fakeHelper struct {
	mu    sync.Mutex
	calls []helperCall
	// reply maps "<helper> <action>" to the answer.
	reply map[string]helperAnswer
}

type helperAnswer struct {
	out string
	err error
}

func (f *fakeHelper) run(_ context.Context, helper, action string, input []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, helperCall{helper, action, string(input)})
	a, ok := f.reply[helper+" "+action]
	if !ok {
		return nil, fmt.Errorf("fake helper has no answer for %s %s: %w", helper, action, exec.ErrNotFound)
	}
	return []byte(a.out), a.err
}

func (f *fakeHelper) recorded() []helperCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]helperCall(nil), f.calls...)
}

func writeConfigJSON(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
	return dir
}

func readConfigFields(t *testing.T, dir string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("config.json is not valid JSON: %v\n%s", err, raw)
	}
	return fields
}

func basicAuth(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

func TestLookupAsksTheCredsStoreHelper(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"fake"}`)
	helper := &fakeHelper{reply: map[string]helperAnswer{
		"fake get": {out: `{"ServerURL":"ghcr.io","Username":"alice","Secret":"s3cret"}`},
	}}
	store := CredentialStore{Dir: dir, Run: helper.run}

	cred, ok, err := store.Lookup(t.Context(), "https://ghcr.io")
	if err != nil || !ok {
		t.Fatalf("Lookup = (%+v, %v, %v), want credentials", cred, ok, err)
	}
	if cred != (Credentials{Username: "alice", Password: "s3cret"}) {
		t.Errorf("credentials = %+v, want alice with s3cret", cred)
	}
	want := []helperCall{{"fake", "get", "ghcr.io"}}
	if got := helper.recorded(); !reflect.DeepEqual(got, want) {
		t.Errorf("helper calls = %+v, want %+v", got, want)
	}
}

func TestLookupPrefersCredHelpersOverCredsStore(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"global","credHelpers":{"ghcr.io":"special"}}`)
	helper := &fakeHelper{reply: map[string]helperAnswer{
		"special get": {out: `{"Username":"bob","Secret":"pw"}`},
		"global get":  {out: `{"Username":"wrong","Secret":"wrong"}`},
	}}
	cred, ok, err := CredentialStore{Dir: dir, Run: helper.run}.Lookup(t.Context(), "https://ghcr.io")
	if err != nil || !ok || cred.Username != "bob" {
		t.Fatalf("Lookup = (%+v, %v, %v), want the credHelpers answer for bob", cred, ok, err)
	}
	for _, c := range helper.recorded() {
		if c.helper == "global" {
			t.Errorf("the credsStore helper ran although credHelpers names one: %+v", c)
		}
	}
}

func TestLookupTreatsTokenUserAsIdentityToken(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"fake"}`)
	helper := &fakeHelper{reply: map[string]helperAnswer{
		"fake get": {out: `{"Username":"<token>","Secret":"refresh-me"}`},
	}}
	cred, ok, err := CredentialStore{Dir: dir, Run: helper.run}.Lookup(t.Context(), "https://ghcr.io")
	if err != nil || !ok {
		t.Fatalf("Lookup = (%+v, %v, %v)", cred, ok, err)
	}
	if cred != (Credentials{IdentityToken: "refresh-me"}) {
		t.Errorf("credentials = %+v, want only the identity token", cred)
	}
}

func TestLookupAsksHelpersForDockerHubWithTheHubKey(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"fake"}`)
	helper := &fakeHelper{reply: map[string]helperAnswer{
		"fake get": {out: `{"Username":"hubuser","Secret":"pw"}`},
	}}
	_, ok, err := CredentialStore{Dir: dir, Run: helper.run}.Lookup(t.Context(), DefaultRegistryBaseURL)
	if err != nil || !ok {
		t.Fatalf("Lookup = (%v, %v)", ok, err)
	}
	if got := helper.recorded(); len(got) != 1 || got[0].input != DockerHubConfigKey {
		t.Errorf("helper calls = %+v, want one call with input %q", got, DockerHubConfigKey)
	}
}

func TestLookupFallsBackToAuthsWhenTheHelperProgramIsMissing(t *testing.T) {
	dir := writeConfigJSON(t, fmt.Sprintf(`{"credsStore":"absent","auths":{"ghcr.io":{"auth":%q}}}`, basicAuth("carol", "pw")))
	helper := &fakeHelper{} // every call fails with exec.ErrNotFound
	cred, ok, err := CredentialStore{Dir: dir, Run: helper.run}.Lookup(t.Context(), "https://ghcr.io")
	if err != nil {
		t.Fatalf("Lookup failed for a missing helper: %v", err)
	}
	if !ok || cred.Username != "carol" {
		t.Errorf("Lookup = (%+v, %v), want the auths entry for carol", cred, ok)
	}
}

func TestLookupMissingHelperWithoutAuthsMeansNoCredentials(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"absent"}`)
	helper := &fakeHelper{}
	_, ok, err := CredentialStore{Dir: dir, Run: helper.run}.Lookup(t.Context(), "https://ghcr.io")
	if err != nil || ok {
		t.Errorf("Lookup = (%v, %v), want no credentials and no error", ok, err)
	}
}

func TestLookupHelperWithoutAnEntryMeansNoCredentials(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"fake"}`)
	helper := &fakeHelper{reply: map[string]helperAnswer{
		"fake get": {out: "credentials not found in native keychain\n", err: errors.New("exit status 1")},
	}}
	_, ok, err := CredentialStore{Dir: dir, Run: helper.run}.Lookup(t.Context(), "https://ghcr.io")
	if err != nil || ok {
		t.Errorf("Lookup = (%v, %v), want no credentials and no error", ok, err)
	}
}

func TestLookupReportsAHelperFailureWithoutLeakingSecrets(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"fake"}`)
	for name, answer := range map[string]helperAnswer{
		"nonzero exit": {out: "keychain is locked", err: errors.New("exit status 1")},
		"invalid JSON": {out: `{"Username":"u","Secret":"topsecret"`},
	} {
		t.Run(name, func(t *testing.T) {
			helper := &fakeHelper{reply: map[string]helperAnswer{"fake get": answer}}
			_, ok, err := CredentialStore{Dir: dir, Run: helper.run}.Lookup(t.Context(), "https://ghcr.io")
			if err == nil || ok {
				t.Fatalf("Lookup = (%v, %v), want an error", ok, err)
			}
			if strings.Contains(err.Error(), "topsecret") {
				t.Errorf("error %q leaks the helper output", err)
			}
		})
	}
}

func TestLookupPrefersTheCanonicalAuthsKey(t *testing.T) {
	dir := writeConfigJSON(t, fmt.Sprintf(`{"auths":{"https://ghcr.io":{"auth":%q},"ghcr.io":{"auth":%q}}}`,
		basicAuth("legacy", "x"), basicAuth("canonical", "y")))
	for range 20 { // map order is random, so repeat
		cred, ok, err := CredentialStore{Dir: dir}.Lookup(t.Context(), "https://ghcr.io")
		if err != nil || !ok || cred.Username != "canonical" {
			t.Fatalf("Lookup = (%+v, %v, %v), want the entry under the key ghcr.io", cred, ok, err)
		}
	}
}

func TestSaveWritesAuthsAndKeepsUnknownFields(t *testing.T) {
	const original = `{
  "currentContext": "desk",
  "proxies": {"default": {"httpProxy": "http://proxy:3128"}},
  "auths": {
    "other.io": {"auth": "b3RoZXI6cHc=", "email": "o@example.com"},
    "ghcr.io": {"email": "me@example.com", "password": "old", "username": "old"}
  },
  "futureField": [1, 2, {"deep": true}]
}`
	dir := writeConfigJSON(t, original)
	var before map[string]any
	if err := json.Unmarshal([]byte(original), &before); err != nil {
		t.Fatal(err)
	}

	store := CredentialStore{Dir: dir}
	if err := store.Save(t.Context(), "https://ghcr.io", Credentials{Username: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	after := readConfigFields(t, dir)
	for _, key := range []string{"currentContext", "proxies", "futureField"} {
		if !reflect.DeepEqual(after[key], before[key]) {
			t.Errorf("unknown field %q = %v, want %v", key, after[key], before[key])
		}
	}
	auths := after["auths"].(map[string]any)
	if !reflect.DeepEqual(auths["other.io"], before["auths"].(map[string]any)["other.io"]) {
		t.Errorf("the entry of another registry changed: %v", auths["other.io"])
	}
	entry := auths["ghcr.io"].(map[string]any)
	if entry["auth"] != basicAuth("alice", "s3cret") {
		t.Errorf("auth = %v, want base64 of alice:s3cret", entry["auth"])
	}
	if entry["email"] != "me@example.com" {
		t.Errorf("email = %v, want the unknown entry field kept", entry["email"])
	}
	if _, ok := entry["password"]; ok {
		t.Errorf("the old plain password stayed in the entry: %v", entry)
	}
	if _, ok := entry["username"]; ok {
		t.Errorf("the old plain user name stayed in the entry: %v", entry)
	}

	cred, ok, err := store.Lookup(t.Context(), "https://ghcr.io")
	if err != nil || !ok || cred != (Credentials{Username: "alice", Password: "s3cret"}) {
		t.Errorf("Lookup after Save = (%+v, %v, %v)", cred, ok, err)
	}
	assertNoTempFiles(t, dir)
}

func TestSaveCreatesTheFileWithMode0600(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "docker-config")
	t.Setenv("DOCKER_CONFIG", dir)
	if err := (CredentialStore{}).Save(t.Context(), DefaultRegistryBaseURL, Credentials{Username: "hub", Password: "pw"}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	auths := readConfigFields(t, dir)["auths"].(map[string]any)
	if _, ok := auths[DockerHubConfigKey]; !ok {
		t.Errorf("auths keys = %v, want the Docker Hub key %q", auths, DockerHubConfigKey)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("config.json mode = %o, want 600", mode)
	}
}

func TestSaveRewritesAWorldReadableConfigWithMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has no POSIX file modes")
	}
	dir := writeConfigJSON(t, `{}`)
	if err := os.Chmod(filepath.Join(dir, "config.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (CredentialStore{Dir: dir}).Save(t.Context(), "https://ghcr.io", Credentials{Username: "a", Password: "b"}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("config.json mode = %o, want 600", mode)
	}
}

func TestSaveUsesTheHelperAndLeavesConfigAlone(t *testing.T) {
	const original = `{"credsStore":"fake","extra":1}`
	dir := writeConfigJSON(t, original)
	helper := &fakeHelper{reply: map[string]helperAnswer{"fake store": {}}}
	store := CredentialStore{Dir: dir, Run: helper.run}

	if err := store.Save(t.Context(), "https://ghcr.io", Credentials{Username: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	calls := helper.recorded()
	if len(calls) != 1 || calls[0].helper != "fake" || calls[0].action != "store" {
		t.Fatalf("helper calls = %+v, want one store call", calls)
	}
	var sent helperReply
	if err := json.Unmarshal([]byte(calls[0].input), &sent); err != nil {
		t.Fatalf("store input is not JSON: %v", err)
	}
	if sent != (helperReply{ServerURL: "ghcr.io", Username: "alice", Secret: "s3cret"}) {
		t.Errorf("store input = %+v", sent)
	}
	got, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("config.json = %q, want it unchanged", got)
	}
}

func TestSaveFailsWhenTheConfiguredHelperIsMissing(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"absent"}`)
	helper := &fakeHelper{}
	err := CredentialStore{Dir: dir, Run: helper.run}.Save(t.Context(), "https://ghcr.io", Credentials{Username: "a", Password: "b"})
	if err == nil {
		t.Fatal("Save succeeded without a helper program")
	}
	if fields := readConfigFields(t, dir); fields["auths"] != nil {
		t.Errorf("Save wrote secrets to config.json although a helper is configured: %v", fields)
	}
}

func TestSaveRefusesToReplaceAConfigItCannotParse(t *testing.T) {
	const broken = `{"auths": [`
	dir := writeConfigJSON(t, broken)
	err := CredentialStore{Dir: dir}.Save(t.Context(), "https://ghcr.io", Credentials{Username: "a", Password: "b"})
	if err == nil {
		t.Fatal("Save succeeded on a broken config.json")
	}
	got, readErr := os.ReadFile(filepath.Join(dir, "config.json"))
	if readErr != nil || string(got) != broken {
		t.Errorf("config.json = %q, %v, want it untouched", got, readErr)
	}
}

func TestSaveKeepsASymbolicLinkToTheConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating symbolic links needs a privilege on Windows")
	}
	real := filepath.Join(t.TempDir(), "real.json")
	if err := os.WriteFile(real, []byte(`{"keep":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(real, filepath.Join(dir, "config.json")); err != nil {
		t.Fatal(err)
	}
	if err := (CredentialStore{Dir: dir}).Save(t.Context(), "https://ghcr.io", Credentials{Username: "a", Password: "b"}); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Lstat(filepath.Join(dir, "config.json")); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("config.json is no longer a symbolic link: %v, %v", info, err)
	}
	raw, err := os.ReadFile(real)
	if err != nil || !strings.Contains(string(raw), "ghcr.io") || !strings.Contains(string(raw), "keep") {
		t.Errorf("link target = %q, %v, want the new entry and the old field", raw, err)
	}
}

func TestEraseRemovesEveryAuthsEntryOfTheRegistry(t *testing.T) {
	dir := writeConfigJSON(t, `{"keep":"me","auths":{"ghcr.io":{"auth":"YTpi"},"https://ghcr.io":{"auth":"YTpi"},"other.io":{"auth":"YTpi","email":"e"}}}`)
	store := CredentialStore{Dir: dir}

	found, err := store.Erase(t.Context(), "https://ghcr.io")
	if err != nil || !found {
		t.Fatalf("Erase = (%v, %v), want found", found, err)
	}
	fields := readConfigFields(t, dir)
	auths := fields["auths"].(map[string]any)
	if len(auths) != 1 || auths["other.io"] == nil {
		t.Errorf("auths = %v, want only other.io", auths)
	}
	if fields["keep"] != "me" {
		t.Errorf("unknown field keep = %v, want it kept", fields["keep"])
	}
	if _, ok, _ := store.Lookup(t.Context(), "https://ghcr.io"); ok {
		t.Errorf("Lookup still finds credentials after Erase")
	}
}

func TestEraseOfAnUnknownRegistryLeavesTheFileAlone(t *testing.T) {
	const original = `{"auths":{"other.io":{"auth":"YTpi"}}}`
	dir := writeConfigJSON(t, original)
	found, err := CredentialStore{Dir: dir}.Erase(t.Context(), "https://ghcr.io")
	if err != nil || found {
		t.Fatalf("Erase = (%v, %v), want not found", found, err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "config.json")); string(got) != original {
		t.Errorf("config.json = %q, want it unchanged", got)
	}
}

func TestEraseAsksTheHelperToErase(t *testing.T) {
	dir := writeConfigJSON(t, `{"credHelpers":{"ghcr.io":"fake"}}`)
	helper := &fakeHelper{reply: map[string]helperAnswer{
		"fake get":   {out: `{"Username":"alice","Secret":"pw"}`},
		"fake erase": {},
	}}
	found, err := CredentialStore{Dir: dir, Run: helper.run}.Erase(t.Context(), "https://ghcr.io")
	if err != nil || !found {
		t.Fatalf("Erase = (%v, %v), want found", found, err)
	}
	var erase *helperCall
	for _, c := range helper.recorded() {
		if c.action == "erase" {
			erase = &c
		}
	}
	if erase == nil || erase.input != "ghcr.io" {
		t.Errorf("erase call = %+v, want input ghcr.io", erase)
	}
}

// loginRegistry serves /v2/ behind basic authentication.
func loginRegistry(t *testing.T, user, pass string) *httptest.Server {
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

func TestLoginStoresCredentialsAfterTheRegistryAcceptsThem(t *testing.T) {
	dir := t.TempDir()
	srv := loginRegistry(t, "alice", "s3cret")
	store := CredentialStore{Dir: dir}

	if err := Login(t.Context(), store, nil, srv.URL, Credentials{Username: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	cred, ok, err := store.Lookup(t.Context(), srv.URL)
	if err != nil || !ok || cred != (Credentials{Username: "alice", Password: "s3cret"}) {
		t.Errorf("Lookup after Login = (%+v, %v, %v)", cred, ok, err)
	}
}

func TestLoginStoresNothingWhenTheRegistryRejectsTheCredentials(t *testing.T) {
	dir := t.TempDir()
	srv := loginRegistry(t, "alice", "s3cret")

	err := Login(t.Context(), CredentialStore{Dir: dir}, nil, srv.URL, Credentials{Username: "alice", Password: "wrong"})
	if !errors.Is(err, ErrLoginRejected) {
		t.Fatalf("Login error = %v, want ErrLoginRejected", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "config.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("config.json exists after a failed login: %v", statErr)
	}
}

func TestLoginAnswersABearerChallengeWithBasicCredentials(t *testing.T) {
	var tokenAuth string
	var mu sync.Mutex
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		tokenAuth = r.Header.Get("Authorization")
		mu.Unlock()
		if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "s3cret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = fmt.Fprint(w, `{"token":"tok"}`)
	})
	mux.HandleFunc("/v2/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="reg"`, srv.URL+"/token"))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()

	if err := Login(t.Context(), CredentialStore{Dir: dir}, nil, srv.URL, Credentials{Username: "alice", Password: "s3cret"}); err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	mu.Lock()
	gotAuth := tokenAuth
	mu.Unlock()
	if want := "Basic " + basicAuth("alice", "s3cret"); gotAuth != want {
		t.Errorf("token request Authorization = %q, want %q", gotAuth, want)
	}

	err := Login(t.Context(), CredentialStore{Dir: t.TempDir()}, nil, srv.URL, Credentials{Username: "alice", Password: "bad"})
	if !errors.Is(err, ErrLoginRejected) {
		t.Errorf("Login with a bad password = %v, want ErrLoginRejected", err)
	}
}

func TestLoginSendsNoCredentialsToAForeignTokenRealm(t *testing.T) {
	var seen []string
	var mu sync.Mutex
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = fmt.Fprint(w, `{"token":"anon"}`)
	}))
	t.Cleanup(foreign.Close)
	registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// localhost and 127.0.0.1 are different hosts for the realm policy.
		realm := strings.Replace(foreign.URL, "127.0.0.1", "localhost", 1) + "/token"
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="reg"`, realm))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(registry.Close)

	err := Login(t.Context(), CredentialStore{Dir: t.TempDir()}, nil, registry.URL, Credentials{Username: "alice", Password: "s3cret"})
	if !errors.Is(err, ErrLoginRejected) {
		t.Errorf("Login = %v, want ErrLoginRejected because the anonymous token does not open /v2/", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) == 0 {
		t.Fatal("the foreign realm was never asked")
	}
	for _, auth := range seen {
		if auth != "" {
			t.Errorf("the foreign realm received Authorization %q", auth)
		}
	}
}

func TestLogoutRemovesTheStoredLogin(t *testing.T) {
	dir := t.TempDir()
	srv := loginRegistry(t, "alice", "pw")
	store := CredentialStore{Dir: dir}
	if err := Login(t.Context(), store, nil, srv.URL, Credentials{Username: "alice", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	found, err := Logout(t.Context(), store, srv.URL)
	if err != nil || !found {
		t.Fatalf("Logout = (%v, %v), want found", found, err)
	}
	if _, ok, _ := store.Lookup(t.Context(), srv.URL); ok {
		t.Errorf("credentials remain after Logout")
	}
	if found, err := Logout(t.Context(), store, srv.URL); err != nil || found {
		t.Errorf("second Logout = (%v, %v), want not found", found, err)
	}
}

func TestRegistryBaseURLAndConfigKey(t *testing.T) {
	for _, tc := range []struct {
		server  string
		wantURL string
		wantKey string
	}{
		{"", DefaultRegistryBaseURL, DockerHubConfigKey},
		{"docker.io", DefaultRegistryBaseURL, DockerHubConfigKey},
		{"index.docker.io", DefaultRegistryBaseURL, DockerHubConfigKey},
		{"https://index.docker.io/v1/", DefaultRegistryBaseURL, DockerHubConfigKey},
		{"ghcr.io", "https://ghcr.io", "ghcr.io"},
		{"GHCR.io/org", "https://ghcr.io", "ghcr.io"},
		{"localhost:5000", "http://localhost:5000", "localhost:5000"},
		{"http://127.0.0.1:1234", "http://127.0.0.1:1234", "127.0.0.1:1234"},
		{"https://reg.example:8443/", "https://reg.example:8443", "reg.example:8443"},
	} {
		gotURL, err := RegistryBaseURL(tc.server)
		if err != nil || gotURL != tc.wantURL {
			t.Errorf("RegistryBaseURL(%q) = %q, %v, want %q", tc.server, gotURL, err, tc.wantURL)
		}
		gotKey, err := RegistryConfigKey(tc.server)
		if err != nil || gotKey != tc.wantKey {
			t.Errorf("RegistryConfigKey(%q) = %q, %v, want %q", tc.server, gotKey, err, tc.wantKey)
		}
	}
	for _, bad := range []string{"bad_host", "ftp://x.example", "host:99999"} {
		if _, err := RegistryBaseURL(bad); err == nil {
			t.Errorf("RegistryBaseURL(%q) succeeded, want an error", bad)
		}
	}
}

func TestRegistryClientAnswersABasicChallengeWithHelperCredentials(t *testing.T) {
	dir := writeConfigJSON(t, `{"credsStore":"fake"}`)
	helper := &fakeHelper{reply: map[string]helperAnswer{
		"fake get": {out: `{"Username":"alice","Secret":"s3cret"}`},
	}}
	srv := loginRegistry(t, "alice", "s3cret")
	rc, err := newRegistryClient(nil, srv.URL, testRepo, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.close()
	rc.store = CredentialStore{Dir: dir, Run: helper.run}

	resp, err := rc.do(t.Context(), http.MethodGet, srv.URL+"/v2/", "")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200 after the helper credentials answered the challenge", resp.StatusCode)
	}
}

func writeHelperScript(t *testing.T, name, body string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the helper script needs a POSIX shell")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\n" + body + "\n"
	if err := os.WriteFile(filepath.Join(dir, "docker-credential-"+name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
}

func TestExecHelperRunsTheProgramWithActionAndInput(t *testing.T) {
	writeHelperScript(t, "echoer", `read line; printf '{"Username":"%s","Secret":"%s"}' "$1" "$line"`)
	out, err := execHelper(t.Context(), "echoer", "get", []byte("ghcr.io\n"))
	if err != nil {
		t.Fatalf("execHelper failed: %v", err)
	}
	if want := `{"Username":"get","Secret":"ghcr.io"}`; string(out) != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestExecHelperReportsAMissingProgramAsNotFound(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	_, err := execHelper(t.Context(), "absent", "get", nil)
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("error = %v, want one that wraps exec.ErrNotFound", err)
	}
}

func TestExecHelperRejectsPathsAsHelperNames(t *testing.T) {
	for _, name := range []string{"", "../evil", "a/b", `a\b`, ".hidden"} {
		if _, err := execHelper(t.Context(), name, "get", nil); err == nil {
			t.Errorf("execHelper accepted the helper name %q", name)
		}
	}
}

func TestExecHelperLimitsOutput(t *testing.T) {
	writeHelperScript(t, "flood", `exec /usr/bin/head -c 5000 /dev/zero`)
	_, err := execHelperWithLimits(10*time.Second, 1000)(t.Context(), "flood", "get", nil)
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("error = %v, want an output limit error", err)
	}
	out, err := execHelperWithLimits(10*time.Second, 5000)(t.Context(), "flood", "get", nil)
	if err != nil || len(out) != 5000 {
		t.Errorf("output at the limit = %d bytes, %v, want 5000 bytes and no error", len(out), err)
	}
}

func TestExecHelperStopsAHelperThatRunsTooLong(t *testing.T) {
	writeHelperScript(t, "slow", `exec /bin/sleep 30`)
	start := time.Now()
	_, err := execHelperWithLimits(200*time.Millisecond, 1000)(t.Context(), "slow", "get", nil)
	if err == nil || !strings.Contains(err.Error(), "ran longer") {
		t.Errorf("error = %v, want a timeout error", err)
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Errorf("the helper ran for %s, want it killed near the limit", elapsed)
	}
}
