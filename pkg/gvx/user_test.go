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
	"reflect"
	"testing"
)

const (
	testPasswd = `# comment
root:x:0:0:root:/root:/bin/sh
bob:x:1000:1000:Bob:/home/bob:/bin/sh
carol:x:1001:50::/home/carol:/bin/sh
broken line
nobody:x:65534:65534:nobody:/:/sbin/nologin
`
	testGroup = `root:x:0:root
staff:x:50:bob,dave
bob:x:1000:
wheel:x:10:bob, carol
dup:x:50:bob
`
)

func TestResolveExecUser(t *testing.T) {
	for _, tc := range []struct {
		name string
		spec string
		want execUser
	}{
		{"empty is root", "", execUser{Home: "/root"}},
		{"name uses passwd gid and home", "carol", execUser{UID: 1001, GID: 50, Home: "/home/carol", ExtraGIDs: []uint32{10}}},
		{"name adds groups that list it, once each", "bob", execUser{UID: 1000, GID: 1000, Home: "/home/bob", ExtraGIDs: []uint32{50, 10}}},
		{"uid in passwd behaves like the name", "1000", execUser{UID: 1000, GID: 1000, Home: "/home/bob", ExtraGIDs: []uint32{50, 10}}},
		{"unlisted uid gets group 0 and home slash", "4242", execUser{UID: 4242, Home: "/"}},
		{"explicit group adds no supplementary group", "bob:staff", execUser{UID: 1000, GID: 50, Home: "/home/bob"}},
		{"numeric group need not exist", "bob:777", execUser{UID: 1000, GID: 777, Home: "/home/bob"}},
		{"unlisted uid with numeric group", "4242:4243", execUser{UID: 4242, GID: 4243, Home: "/"}},
		{"largest valid id", "4294967294", execUser{UID: 4294967294, Home: "/"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveExecUser(tc.spec, []byte(testPasswd), []byte(testGroup))
			if err != nil {
				t.Fatalf("resolveExecUser(%q): %v", tc.spec, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("resolveExecUser(%q) = %+v, want %+v", tc.spec, got, tc.want)
			}
		})
	}
}

func TestResolveExecUserRejectsBadSpecifications(t *testing.T) {
	for _, tc := range []struct {
		name    string
		spec    string
		wantErr error
	}{
		{"unknown user name", "alice", errUnknownUser},
		{"unknown group name", "bob:nogroup", errUnknownGroup},
		{"empty user", ":staff", nil},
		{"empty group", "bob:", nil},
		{"three parts", "bob:staff:x", nil},
		{"user id past the valid range", "4294967295", nil},
		{"group id past the valid range", "bob:4294967295", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := resolveExecUser(tc.spec, []byte(testPasswd), []byte(testGroup))
			if err == nil {
				t.Fatalf("resolveExecUser(%q) succeeded, want an error", tc.spec)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("resolveExecUser(%q) = %v, want %v", tc.spec, err, tc.wantErr)
			}
		})
	}
}

func TestResolveExecUserWithoutGuestFiles(t *testing.T) {
	got, err := resolveExecUser("", nil, nil)
	if err != nil || got.UID != 0 || got.GID != 0 || got.Home != "/root" {
		t.Fatalf("resolveExecUser(\"\", nil, nil) = (%+v, %v), want root with home /root", got, err)
	}
	if _, err := resolveExecUser("bob", nil, nil); !errors.Is(err, errUnknownUser) {
		t.Fatalf("resolveExecUser(bob) without files = %v, want %v", err, errUnknownUser)
	}
	got, err = resolveExecUser("1000", nil, nil)
	if err != nil || got.UID != 1000 || got.GID != 0 || got.Home != "/" {
		t.Fatalf("resolveExecUser(1000) without files = (%+v, %v), want uid 1000, gid 0, home /", got, err)
	}
}
