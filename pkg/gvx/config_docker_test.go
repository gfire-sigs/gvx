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
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeDefaultsHostname(t *testing.T) {
	cfg := Config{}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if cfg.Hostname != "gvx" {
		t.Errorf("Hostname = %q, want the default gvx", cfg.Hostname)
	}
}

func TestNormalizeRejectsInvalidRunSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		{"name with a leading dot", Config{Name: ".web"}, "container name"},
		{"name of one character", Config{Name: "a"}, "container name"},
		{"name with a slash", Config{Name: "a/b"}, "container name"},
		{"hostname with an underscore", Config{Hostname: "my_host"}, "hostname"},
		{"hostname of 65 characters", Config{Hostname: strings.Repeat("a", 65)}, "hostname"},
		{"memory below the minimum", Config{Resources: Resources{MemoryBytes: MinMemoryLimit - 1}}, "memory limit"},
		{"negative memory", Config{Resources: Resources{MemoryBytes: -1}}, "memory limit"},
		{"negative CPU quota", Config{Resources: Resources{CPUMillis: -1}}, "CPU quota"},
		{"CPU quota above the host", Config{Resources: Resources{CPUMillis: int64(runtime.NumCPU())*1000 + 1}}, "CPU quota"},
		{"user with an empty group", Config{User: "bob:"}, "user specification"},
		{"publish all without nat", Config{PublishAll: true, NetworkMode: NetModeNone}, "exposed ports"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.normalize()
			if !errors.Is(err, ErrInvalidConfig) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("normalize = %v, want an ErrInvalidConfig error that mentions %q", err, tc.want)
			}
		})
	}
}

func TestNormalizeAcceptsDockerRunSettings(t *testing.T) {
	cfg := Config{
		Name:      "web-1.a_b",
		Hostname:  "box.example",
		User:      "1000:1000",
		Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 1000},
	}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
}
