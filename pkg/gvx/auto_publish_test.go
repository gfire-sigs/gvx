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
	"testing"
)

func TestConfigAutoPublishRequiresNAT(t *testing.T) {
	cfg := Config{
		NetworkMode:      NetModeNone,
		AutoPublishPorts: true,
	}
	err := cfg.normalize()
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalize(NetModeNone, AutoPublishPorts=true) = %v, want ErrInvalidConfig", err)
	}

	cfgNAT := Config{
		NetworkMode:      NetModeNAT,
		AutoPublishPorts: true,
	}
	if err := cfgNAT.normalize(); err != nil {
		t.Fatalf("normalize(NetModeNAT, AutoPublishPorts=true) = %v, want nil", err)
	}
}
