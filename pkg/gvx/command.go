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

package gvx

import (
	"errors"
	"fmt"
	"strings"

	"z.gfire.dev/gvx/pkg/oci"
)

// errNoCommand reports that neither the caller nor the image names a command.
var errNoCommand = errors.New("gvx: no command: the image has no Entrypoint or Cmd, and the caller gave none")

// commandSource holds the command inputs of a Config.
type commandSource struct {
	// Argv is the full command vector. It replaces the image Entrypoint and Cmd.
	Argv []string
	// Entrypoint replaces the image Entrypoint when EntrypointSet is true. An
	// empty Entrypoint with EntrypointSet clears the image Entrypoint.
	Entrypoint    []string
	EntrypointSet bool
	// Cmd replaces the image Cmd.
	Cmd []string
}

// composeCommand returns the command vector of the guest, with Docker rules.
//
// A non-empty Argv wins and the image is not consulted. Otherwise the vector is
// the Entrypoint followed by the Cmd. The Entrypoint is the override or the
// image Entrypoint. The Cmd is the override, or the image Cmd unless the caller
// overrode the Entrypoint: Docker drops the image Cmd then.
func composeCommand(img oci.RuntimeConfig, src commandSource) ([]string, error) {
	if len(src.Argv) > 0 {
		return append([]string(nil), src.Argv...), nil
	}
	entrypoint := img.Entrypoint
	cmd := img.Cmd
	if src.EntrypointSet {
		entrypoint = src.Entrypoint
		cmd = nil
	}
	if len(src.Cmd) > 0 {
		cmd = src.Cmd
	}
	argv := make([]string, 0, len(entrypoint)+len(cmd))
	argv = append(argv, entrypoint...)
	argv = append(argv, cmd...)
	if len(argv) == 0 {
		return nil, errNoCommand
	}
	return argv, nil
}

// mergeEnv returns base with every KEY=VALUE of overrides applied. An override
// replaces the first entry that has the same key and keeps its position. A new
// key goes at the end. It returns an error for an entry without "=" or with an
// empty key. Later overrides win over earlier ones.
func mergeEnv(base, overrides []string) ([]string, error) {
	out := append([]string(nil), base...)
	index := make(map[string]int, len(out))
	for i, kv := range out {
		if key, _, ok := strings.Cut(kv, "="); ok {
			if _, dup := index[key]; !dup {
				index[key] = i
			}
		}
	}
	for _, kv := range overrides {
		key, _, ok := strings.Cut(kv, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("gvx: invalid environment entry %q: want KEY=VALUE", kv)
		}
		if i, found := index[key]; found {
			out[i] = kv
			continue
		}
		index[key] = len(out)
		out = append(out, kv)
	}
	return out, nil
}

// defaultPath is the search path that a guest gets when nothing sets PATH.
const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// guestEnvDefaults names the values that finalizeEnv adds when the key is absent.
type guestEnvDefaults struct {
	Home     string
	Hostname string
	// TTY adds TERM=xterm.
	TTY bool
}

// finalizeEnv adds PATH, HOME, HOSTNAME, and, for a terminal, TERM when env has
// none of them. It never changes a key that env already has.
func finalizeEnv(env []string, d guestEnvDefaults) []string {
	has := make(map[string]bool, len(env))
	for _, kv := range env {
		if key, _, ok := strings.Cut(kv, "="); ok {
			has[key] = true
		}
	}
	out := append([]string(nil), env...)
	add := func(key, value string) {
		if !has[key] && value != "" {
			out = append(out, key+"="+value)
		}
	}
	add("PATH", defaultPath)
	add("HOME", d.Home)
	add("HOSTNAME", d.Hostname)
	if d.TTY {
		add("TERM", "xterm")
	}
	return out
}
