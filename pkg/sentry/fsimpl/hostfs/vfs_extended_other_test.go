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

//go:build !linux

package hostfs

import (
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestMacAndWindowsKeepEveryXattrInTheMetaStore(t *testing.T) {
	e := newEnv(t)
	if e.ws.caps.NativeXattr {
		t.Fatalf("caps = %+v: only a Linux volume stores xattrs natively", e.ws.caps)
	}
	e.writeFile("f", []byte("data"))
	e.mustMkdir("d")
	e.mustSetXattr("f", "user.k", "v")
	e.mustSetXattr("d", "user.d", "dv")
	for _, tc := range []struct{ path, name, want string }{{"f", "user.k", "v"}, {"d", "user.d", "dv"}} {
		e.ws.mu.RLock()
		got := e.ws.meta[tc.path].Xattrs[tc.name]
		e.ws.mu.RUnlock()
		if string(got) != tc.want {
			t.Errorf("record of %s holds %q for %s, want %q", tc.path, got, tc.name, tc.want)
		}
	}
}

func TestNativeCapWithoutHostSupportFallsBackToTheMetaStore(t *testing.T) {
	// A test can set the flag on any host. The native calls then report that
	// the host refuses them, which sends each attribute to the meta store.
	e := newEnv(t)
	e.ws.caps.NativeXattr = true
	e.writeFile("f", nil)
	e.mustMkdir("d")
	for _, p := range []string{"f", "d"} {
		e.mustSetXattr(p, "user.k", "v")
		if got := e.mustGetXattr(p, "user.k"); got != "v" {
			t.Fatalf("getxattr %s = %q", p, got)
		}
		if got := e.listXattr(p); !slices.Equal(got, []string{"user.k"}) {
			t.Fatalf("listxattr %s = %v", p, got)
		}
		if err := e.setXattr(p, "user.k", "w", 1); !linuxerr.Equals(linuxerr.EEXIST, err) {
			t.Fatalf("CREATE of an existing name on %s = %v, want EEXIST", p, err)
		}
		if err := e.removeXattr(p, "user.k"); err != nil {
			t.Fatal(err)
		}
		_, err := e.getXattr(p, "user.k")
		wantErrno(t, "getxattr after remove", err, linuxerr.ENODATA)
	}
}
