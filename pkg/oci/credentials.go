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
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	// DockerHubConfigKey is the key of Docker Hub in config.json and in
	// credential helpers.
	DockerHubConfigKey = "https://index.docker.io/v1/"

	// helperTimeout bounds one run of a credential helper.
	helperTimeout = 30 * time.Second
	// maxHelperOutput bounds the standard output of a credential helper.
	maxHelperOutput = 1 << 20
	// identityTokenUser is the user name that a helper uses for an identity token.
	identityTokenUser = "<token>"
	configFileName    = "config.json"
)

// ErrLoginRejected reports that a registry refused the credentials of a login.
var ErrLoginRejected = errors.New("oci: the registry rejected the credentials")

// Credentials are the secrets for one registry. A user name with a password
// is the usual form. An identity token is a refresh token that a registry
// exchanges for access tokens.
type Credentials struct {
	Username      string
	Password      string
	IdentityToken string
}

func (c Credentials) isZero() bool { return c == Credentials{} }

// HelperRunner starts the program "docker-credential-<helper>" with action
// as its argument and input on standard input. It returns the standard
// output. On failure it returns the output that it has read together with the
// error. An error that wraps exec.ErrNotFound means that the program is not
// installed.
type HelperRunner func(ctx context.Context, helper, action string, input []byte) ([]byte, error)

// CredentialStore reads and writes Docker registry credentials in the Docker
// config directory. It follows the Docker rules: a credHelpers entry for the
// registry wins, then credsStore, then the auths table of config.json.
// The zero value is ready to use.
type CredentialStore struct {
	// Dir is the Docker config directory. Empty selects DOCKER_CONFIG, then
	// ~/.docker.
	Dir string
	// Run starts credential helpers. Nil starts real processes with a limit of
	// 30 seconds and 1 MiB of output.
	Run HelperRunner
}

func (s CredentialStore) runner() HelperRunner {
	if s.Run != nil {
		return s.Run
	}
	return execHelper
}

func (s CredentialStore) configPath() (string, error) {
	dir := s.Dir
	if dir == "" {
		dir = os.Getenv("DOCKER_CONFIG")
	}
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", errors.New("oci: cannot locate the Docker config directory: set DOCKER_CONFIG")
		}
		dir = filepath.Join(home, ".docker")
	}
	return filepath.Join(dir, configFileName), nil
}

// authEntry is one entry of the auths table.
type authEntry struct {
	Auth          string `json:"auth"`
	Username      string `json:"username"`
	Password      string `json:"password"`
	IdentityToken string `json:"identitytoken"`
}

// dockerConfig holds the fields of config.json that credential lookup reads.
type dockerConfig struct {
	Auths       map[string]authEntry `json:"auths"`
	CredsStore  string               `json:"credsStore"`
	CredHelpers map[string]string    `json:"credHelpers"`
}

// readConfig returns the credential fields of config.json. A missing or
// malformed file has no credentials.
func (s CredentialStore) readConfig() (dockerConfig, bool) {
	path, err := s.configPath()
	if err != nil {
		return dockerConfig{}, false
	}
	raw, err := readFileShared(path)
	if err != nil {
		return dockerConfig{}, false
	}
	var cfg dockerConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return dockerConfig{}, false
	}
	return cfg, true
}

// configKeyHost returns the canonical host of a docker config key.
func configKeyHost(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	if strings.Contains(k, "://") {
		if u, err := url.Parse(k); err == nil && u.Host != "" {
			return canonicalHost(u)
		}
	}
	if slash := strings.IndexByte(k, '/'); slash >= 0 {
		k = k[:slash]
	}
	return strings.TrimSuffix(k, ":443")
}

// configKeyMatches reports whether a config key names the registry at target.
// Docker Hub has several host names, which all match each other.
func configKeyMatches(key string, target *url.URL) bool {
	keyHost := configKeyHost(key)
	if keyHost == canonicalHost(target) {
		return true
	}
	return dockerHubHosts[strings.ToLower(target.Hostname())] && dockerHubHosts[strings.TrimSuffix(keyHost, ":443")]
}

// configKeyFor returns the key under which credentials of target are kept.
func configKeyFor(target *url.URL) string {
	if dockerHubHosts[strings.ToLower(target.Hostname())] {
		return DockerHubConfigKey
	}
	return canonicalHost(target)
}

// matchingKeys lists the keys of a table that name target. The canonical key
// comes first and the rest follow in sorted order, so that the answer does not
// depend on map order.
func matchingKeys[V any](table map[string]V, target *url.URL) []string {
	canonical := configKeyFor(target)
	var keys []string
	for key := range table {
		if key != canonical && configKeyMatches(key, target) {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	if _, ok := table[canonical]; ok {
		keys = append([]string{canonical}, keys...)
	}
	return keys
}

// helperFor returns the credential helper for target, or an empty string.
func (c dockerConfig) helperFor(target *url.URL) string {
	if keys := matchingKeys(c.CredHelpers, target); len(keys) > 0 {
		return c.CredHelpers[keys[0]]
	}
	return c.CredsStore
}

// authsCredentials returns the inline credentials of target.
func (c dockerConfig) authsCredentials(target *url.URL) (Credentials, bool) {
	for _, key := range matchingKeys(c.Auths, target) {
		entry := c.Auths[key]
		if entry.Username != "" || entry.Password != "" {
			return Credentials{Username: entry.Username, Password: entry.Password, IdentityToken: entry.IdentityToken}, true
		}
		if entry.Auth != "" {
			if decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(entry.Auth)); err == nil {
				if user, pass, found := strings.Cut(string(decoded), ":"); found {
					return Credentials{Username: user, Password: pass, IdentityToken: entry.IdentityToken}, true
				}
			}
		}
		if entry.IdentityToken != "" {
			return Credentials{IdentityToken: entry.IdentityToken}, true
		}
	}
	return Credentials{}, false
}

// Lookup returns the credentials for the registry at serverURL, such as
// "https://ghcr.io". The credentials go only to that registry and to its
// token realm; the registry client enforces that. A missing helper program
// and a helper that has no entry mean no credentials. A helper that fails in
// another way is an error.
func (s CredentialStore) Lookup(ctx context.Context, serverURL string) (Credentials, bool, error) {
	target, err := url.Parse(serverURL)
	if err != nil || target.Host == "" {
		return Credentials{}, false, nil
	}
	cfg, ok := s.readConfig()
	if !ok {
		return Credentials{}, false, nil
	}
	if helper := cfg.helperFor(target); helper != "" {
		cred, found, err := s.helperGet(ctx, helper, configKeyFor(target))
		if err != nil {
			return Credentials{}, false, err
		}
		if found {
			return cred, true, nil
		}
	}
	cred, found := cfg.authsCredentials(target)
	return cred, found, nil
}

// helperReply is the JSON that "docker-credential-<name> get" prints.
type helperReply struct {
	ServerURL string
	Username  string
	Secret    string
}

func isNotFoundOutput(out []byte) bool {
	return strings.Contains(strings.ToLower(string(out)), "credentials not found")
}

func (s CredentialStore) helperGet(ctx context.Context, helper, key string) (Credentials, bool, error) {
	out, err := s.runner()(ctx, helper, "get", []byte(key))
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) || isNotFoundOutput(out) {
			return Credentials{}, false, nil
		}
		return Credentials{}, false, fmt.Errorf("oci: credential helper %q failed to get credentials for %s: %w", helper, key, err)
	}
	var reply helperReply
	if err := json.Unmarshal(out, &reply); err != nil {
		return Credentials{}, false, fmt.Errorf("oci: credential helper %q returned invalid JSON for %s", helper, key)
	}
	switch {
	case reply.Username == identityTokenUser && reply.Secret != "":
		return Credentials{IdentityToken: reply.Secret}, true, nil
	case reply.Username == "" && reply.Secret == "":
		return Credentials{}, false, nil
	}
	return Credentials{Username: reply.Username, Password: reply.Secret}, true, nil
}

// Save stores cred for the registry at serverURL. It uses the credential
// helper of the registry when config.json names one. Otherwise it writes the
// auths table, keeps every other field of config.json, and replaces the file
// atomically with mode 0600.
func (s CredentialStore) Save(ctx context.Context, serverURL string, cred Credentials) error {
	target, err := parseServerURL(serverURL)
	if err != nil {
		return err
	}
	if cred.isZero() {
		return errors.New("oci: no credentials to store")
	}
	key := configKeyFor(target)
	file, err := s.readRawConfig()
	if err != nil {
		return err
	}
	if helper := file.typed.helperFor(target); helper != "" {
		reply := helperReply{ServerURL: key, Username: cred.Username, Secret: cred.Password}
		if cred.IdentityToken != "" {
			reply.Username, reply.Secret = identityTokenUser, cred.IdentityToken
		}
		input, err := json.Marshal(reply)
		if err != nil {
			return fmt.Errorf("oci: encode credentials for helper %q: %w", helper, err)
		}
		if out, err := s.runner()(ctx, helper, "store", input); err != nil {
			return fmt.Errorf("oci: credential helper %q failed to store credentials for %s: %w%s", helper, key, err, outputSuffix(out))
		}
		return nil
	}

	entry, err := file.entry(key)
	if err != nil {
		return err
	}
	for _, field := range []string{"auth", "username", "password", "identitytoken"} {
		delete(entry, field)
	}
	if cred.IdentityToken != "" && cred.Username == "" && cred.Password == "" {
		entry["identitytoken"] = mustJSON(cred.IdentityToken)
	} else {
		entry["auth"] = mustJSON(base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password)))
	}
	if err := file.setEntry(key, entry); err != nil {
		return err
	}
	return file.write()
}

// Erase removes the credentials of the registry at serverURL. It reports
// whether any credentials existed. It asks the credential helper of the
// registry to erase them. It also removes every auths entry for the registry,
// so that an old entry cannot return through Lookup.
func (s CredentialStore) Erase(ctx context.Context, serverURL string) (bool, error) {
	target, err := parseServerURL(serverURL)
	if err != nil {
		return false, err
	}
	key := configKeyFor(target)
	file, err := s.readRawConfig()
	if err != nil {
		return false, err
	}
	found := false
	if helper := file.typed.helperFor(target); helper != "" {
		if _, ok, err := s.helperGet(ctx, helper, key); err != nil {
			return false, err
		} else if ok {
			found = true
			if out, err := s.runner()(ctx, helper, "erase", []byte(key)); err != nil && !isNotFoundOutput(out) {
				return false, fmt.Errorf("oci: credential helper %q failed to erase credentials for %s: %w%s", helper, key, err, outputSuffix(out))
			}
		}
	}
	removed, err := file.removeAuths(target)
	if err != nil {
		return false, err
	}
	if removed {
		found = true
		if err := file.write(); err != nil {
			return false, err
		}
	}
	return found, nil
}

func outputSuffix(out []byte) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return ""
	}
	if len(text) > 256 {
		text = text[:256]
	}
	return ": " + text
}

func parseServerURL(serverURL string) (*url.URL, error) {
	target, err := url.Parse(serverURL)
	if err != nil || target.Host == "" {
		return nil, fmt.Errorf("oci: %q is not a registry URL", serverURL)
	}
	return target, nil
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic("oci: marshal " + fmt.Sprintf("%T", v) + ": " + err.Error())
	}
	return raw
}

// rawConfig is config.json with every unknown field kept as raw JSON.
type rawConfig struct {
	path   string
	fields map[string]json.RawMessage
	typed  dockerConfig
}

// readRawConfig reads config.json for a change. A missing file is an empty
// config. A file that is not a JSON object is an error, so that a write never
// replaces a file that the tool cannot understand.
func (s CredentialStore) readRawConfig() (*rawConfig, error) {
	path, err := s.configPath()
	if err != nil {
		return nil, err
	}
	cfg := &rawConfig{path: path, fields: map[string]json.RawMessage{}}
	raw, err := readFileShared(path)
	if errors.Is(err, os.ErrNotExist) {
		return cfg, nil
	}
	if err != nil {
		return nil, fmt.Errorf("oci: read %s: %w", path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg.fields); err != nil {
		return nil, fmt.Errorf("oci: %s is not a JSON object: %w", path, err)
	}
	if cfg.fields == nil {
		cfg.fields = map[string]json.RawMessage{}
	}
	if err := json.Unmarshal(raw, &cfg.typed); err != nil {
		return nil, fmt.Errorf("oci: parse %s: %w", path, err)
	}
	return cfg, nil
}

func (c *rawConfig) auths() (map[string]json.RawMessage, error) {
	auths := map[string]json.RawMessage{}
	if raw, ok := c.fields["auths"]; ok && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, &auths); err != nil {
			return nil, fmt.Errorf("oci: the auths field of %s is not an object: %w", c.path, err)
		}
	}
	return auths, nil
}

// entry returns the fields of one auths entry. A missing entry is empty.
func (c *rawConfig) entry(key string) (map[string]json.RawMessage, error) {
	auths, err := c.auths()
	if err != nil {
		return nil, err
	}
	entry := map[string]json.RawMessage{}
	if raw, ok := auths[key]; ok && string(bytes.TrimSpace(raw)) != "null" {
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, fmt.Errorf("oci: the auths entry %q of %s is not an object: %w", key, c.path, err)
		}
	}
	return entry, nil
}

func (c *rawConfig) setEntry(key string, entry map[string]json.RawMessage) error {
	auths, err := c.auths()
	if err != nil {
		return err
	}
	auths[key] = mustJSON(entry)
	c.fields["auths"] = mustJSON(auths)
	return nil
}

// removeAuths deletes the auths entries for target and reports whether any existed.
func (c *rawConfig) removeAuths(target *url.URL) (bool, error) {
	auths, err := c.auths()
	if err != nil {
		return false, err
	}
	removed := false
	for key := range auths {
		if configKeyMatches(key, target) {
			delete(auths, key)
			removed = true
		}
	}
	if removed {
		c.fields["auths"] = mustJSON(auths)
	}
	return removed, nil
}

// write replaces config.json atomically with mode 0600. A symbolic link is
// followed, so that a config managed by a dotfile tool stays a link.
func (c *rawConfig) write() error {
	raw, err := json.MarshalIndent(c.fields, "", "\t")
	if err != nil {
		return fmt.Errorf("oci: encode %s: %w", c.path, err)
	}
	path := c.path
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("oci: create %s: %w", dir, err)
	}
	return writeFileAtomic(dir, filepath.Base(path), append(raw, '\n'))
}

// RegistryBaseURL returns the endpoint of the registry that a user names in
// "login" and "logout". It accepts a host with an optional port, a URL, and
// the Docker Hub names. An empty server means Docker Hub.
func RegistryBaseURL(server string) (string, error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return DefaultRegistryBaseURL, nil
	}
	if strings.Contains(server, "://") {
		u, err := url.Parse(server)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
			return "", fmt.Errorf("oci: %q is not an http or https registry URL", server)
		}
		if dockerHubHosts[strings.ToLower(u.Hostname())] {
			return DefaultRegistryBaseURL, nil
		}
		return u.Scheme + "://" + strings.ToLower(u.Host), nil
	}
	host, _, _ := strings.Cut(server, "/")
	host = strings.ToLower(host)
	if err := validateRegistryHost(host); err != nil {
		return "", fmt.Errorf("oci: %w", err)
	}
	if dockerHubAliases[host] || host == "registry.docker.io" {
		return DefaultRegistryBaseURL, nil
	}
	return Reference{Registry: host}.BaseURL(), nil
}

// RegistryConfigKey returns the key that config.json and credential helpers
// use for a registry named as in RegistryBaseURL.
func RegistryConfigKey(server string) (string, error) {
	base, err := RegistryBaseURL(server)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("oci: parse registry URL %q: %w", base, err)
	}
	return configKeyFor(u), nil
}

// Login proves cred to the registry named by server and then stores it in
// store. It sends GET /v2/ and answers the registry challenge with cred, and
// it stores the credentials only if the registry accepts them. The
// credentials go only to the registry and to its token realm. A nil client
// selects a default HTTP client. A refusal wraps ErrLoginRejected.
func Login(ctx context.Context, store CredentialStore, client *http.Client, server string, cred Credentials) error {
	if cred.isZero() {
		return errors.New("oci: login needs a user name and a password")
	}
	baseURL, err := RegistryBaseURL(server)
	if err != nil {
		return err
	}
	rc, err := newRegistryClient(client, baseURL, "", DefaultLimits())
	if err != nil {
		return err
	}
	defer rc.close()
	rc.fixed = &cred

	ping := strings.TrimRight(rc.baseURL.String(), "/") + "/v2/"
	resp, err := rc.do(ctx, http.MethodGet, ping, "")
	if err != nil {
		var status *StatusError
		if errors.As(err, &status) && status.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("%w: %s", ErrLoginRejected, rc.baseURL.Host)
		}
		return fmt.Errorf("oci: log in to %s: %w", rc.baseURL.Host, err)
	}
	status := resp.StatusCode
	if err := resp.Body.Close(); err != nil {
		return fmt.Errorf("oci: close response of %s: %w", ping, err)
	}
	switch {
	case status == http.StatusOK:
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return fmt.Errorf("%w: %s answered HTTP %d", ErrLoginRejected, rc.baseURL.Host, status)
	default:
		return &StatusError{URL: ping, StatusCode: status}
	}
	return store.Save(ctx, baseURL, cred)
}

// Logout removes the stored credentials of the registry named by server. It
// reports whether credentials existed.
func Logout(ctx context.Context, store CredentialStore, server string) (bool, error) {
	baseURL, err := RegistryBaseURL(server)
	if err != nil {
		return false, err
	}
	return store.Erase(ctx, baseURL)
}

// limitedWriter keeps at most max bytes and calls overflow once when more
// arrive. It discards the excess, so that the writing process never blocks.
type limitedWriter struct {
	buf      bytes.Buffer
	max      int
	over     bool
	overflow func()
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if room := w.max - w.buf.Len(); len(p) <= room {
		w.buf.Write(p)
		return len(p), nil
	} else if room > 0 {
		w.buf.Write(p[:room])
	}
	if !w.over {
		w.over = true
		w.overflow()
	}
	return len(p), nil
}

// execHelper is the HelperRunner that starts real processes with the default
// limits.
var execHelper = execHelperWithLimits(helperTimeout, maxHelperOutput)

// execHelperWithLimits returns a HelperRunner that starts real processes. It
// kills a helper that runs longer than timeout or writes more than maxOutput
// bytes. The helper name must be a plain program name, so that config.json
// cannot name a path.
func execHelperWithLimits(timeout time.Duration, maxOutput int) HelperRunner {
	return func(ctx context.Context, helper, action string, input []byte) ([]byte, error) {
		if helper == "" || strings.ContainsAny(helper, `/\:`) || strings.HasPrefix(helper, ".") {
			return nil, fmt.Errorf("oci: %q is not a valid credential helper name", helper)
		}
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker-credential-"+helper, action)
		cmd.Stdin = bytes.NewReader(input)
		cmd.WaitDelay = time.Second
		out := &limitedWriter{max: maxOutput, overflow: cancel}
		cmd.Stdout = out
		err := cmd.Run()
		switch {
		case out.over:
			return nil, fmt.Errorf("oci: credential helper %q wrote more than %d bytes", helper, maxOutput)
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return out.buf.Bytes(), fmt.Errorf("oci: credential helper %q ran longer than %s", helper, timeout)
		case err != nil:
			return out.buf.Bytes(), fmt.Errorf("oci: credential helper %q: %w", helper, err)
		}
		return out.buf.Bytes(), nil
	}
}
