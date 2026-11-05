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
	"bytes"
	"errors"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/oci"
)

// pkg/oci does not import the registry, so DefaultLimits repeats its defaults.
func TestOCIDefaultLimitsMatchTheRegistry(t *testing.T) {
	if got, want := oci.DefaultLimits(), limitsFromTuning(tuning.Values{}); got != want {
		t.Errorf("oci.DefaultLimits() = %+v, want the registry defaults %+v", got, want)
	}
}

func TestOCILimitsFollowTheTunables(t *testing.T) {
	tuned, err := tuning.Parse(map[string]string{"oci.max_entries": "2", "oci.max_json_bytes": "1MiB"})
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewLayerCacheWithTuning(t.TempDir(), tuned)
	if err != nil {
		t.Fatal(err)
	}
	layer := func(names ...string) []byte {
		var files []testimage.File
		for _, n := range names {
			files = append(files, testimage.File{Name: n, Data: []byte("x"), Mode: 0o644})
		}
		raw, err := testimage.Tar(files...)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if _, _, err := cache.CompileAndStore("", bytes.NewReader(layer("a", "b"))); err != nil {
		t.Errorf("a layer with 2 entries failed under the limit of 2: %v", err)
	}
	_, _, err = cache.CompileAndStore("", bytes.NewReader(layer("a", "b", "c")))
	if !errors.Is(err, oci.ErrLimitExceeded) {
		t.Errorf("a layer with 3 entries gave %v, want ErrLimitExceeded", err)
	}
	plain, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := plain.CompileAndStore("", bytes.NewReader(layer("a", "b", "c"))); err != nil {
		t.Errorf("the default limit refused 3 entries: %v", err)
	}
}

func TestPortRangeLimitFollowsTheTunable(t *testing.T) {
	if _, err := ParsePortForwards("30000-32767"); err == nil || !strings.Contains(err.Error(), "net.forward.max_port_range") {
		t.Errorf("default limit: error = %v, want one that names net.forward.max_port_range", err)
	}
	tuned, err := tuning.Values{}.WithInt(tuning.ForwardMaxPortRange, 3000)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParsePortForwardsWith("30000-32767", tuned)
	if err != nil || len(got) != 2768 {
		t.Errorf("tuned limit: %d forwards, error %v, want 2768 forwards", len(got), err)
	}
}
