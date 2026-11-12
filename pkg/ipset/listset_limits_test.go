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

package ipset

import (
	"fmt"
	"slices"
	"testing"
)

// newFullListSet returns a list:set of size 4 that holds the hash:ip sets
// m0 to m3, and a fifth hash:ip set named "extra".
func newFullListSet(t *testing.T, r *Registry, forceadd bool) {
	t.Helper()
	for i := range 4 {
		create(t, r, fmt.Sprintf("m%d", i), "hash:ip", FamilyIPv4, nil)
	}
	create(t, r, "extra", "hash:ip", FamilyIPv4, nil)
	create(t, r, "list", "list:set", FamilyUnspec, func(p *CreateParams) {
		p.Given |= GivenSize
		p.Size = 4
		if forceadd {
			p.Given |= GivenCadtFlags
			p.CadtFlags = CadtWithForceadd
		}
	})
	for i := range 4 {
		if got := uadt(r, "list", AdtAdd, Element{Has: HasName, Name: fmt.Sprintf("m%d", i)}, 0); got != 0 {
			t.Fatalf("add m%d = %d", i, got)
		}
	}
}

func memberNames(t *testing.T, r *Registry, name string) []string {
	t.Helper()
	var names []string
	for _, e := range listAll(t, r, name) {
		names = append(names, e.Name)
	}
	return names
}

func TestListSetRejectsAddToFullListAndReleasesReference(t *testing.T) {
	r, _ := newTestRegistry(t)
	newFullListSet(t, r, false)

	if got := uadt(r, "list", AdtAdd, Element{Has: HasName, Name: "extra"}, 0); got != -ErrListFull {
		t.Fatalf("add to a full list = %d, want -ErrListFull", got)
	}
	if got, want := memberNames(t, r, "list"), []string{"m0", "m1", "m2", "m3"}; !slices.Equal(got, want) {
		t.Errorf("members after the failed add = %v, want %v", got, want)
	}
	if err := r.Destroy("extra", false, false); err != nil {
		t.Errorf("destroy of the set that the failed add named: %v", err)
	}
	// A member that is already in the list can still be refreshed.
	if got := uadt(r, "list", AdtAdd, Element{Has: HasName, Name: "m2"}, FlagExist); got != 0 {
		t.Errorf("re-add of a member to a full list = %d, want 0", got)
	}
}

func TestListSetForceaddPushesOutLastMember(t *testing.T) {
	r, _ := newTestRegistry(t)
	newFullListSet(t, r, true)

	if got := uadt(r, "list", AdtAdd, Element{Has: HasName, Name: "extra"}, 0); got != 0 {
		t.Fatalf("forceadd to a full list = %d, want 0", got)
	}
	if got, want := memberNames(t, r, "list"), []string{"m0", "m1", "m2", "extra"}; !slices.Equal(got, want) {
		t.Errorf("members after forceadd = %v, want %v", got, want)
	}
	if err := r.Destroy("m3", false, false); err != nil {
		t.Errorf("destroy of the member that forceadd pushed out: %v", err)
	}
	if got := code(r.Destroy("extra", false, false)); got != ErrBusy {
		t.Errorf("destroy of the new member = %d, want ErrBusy", got)
	}
}

func TestListSetForceaddKeepsReferenceMember(t *testing.T) {
	r, _ := newTestRegistry(t)
	newFullListSet(t, r, true)

	// The last member is the reference of the new position, so no room opens.
	e := Element{Has: HasName | HasNameRef, Name: "extra", NameRef: "m3"}
	if got := uadt(r, "list", AdtAdd, e, 0); got != -ErrListFull {
		t.Fatalf("forceadd after the last member = %d, want -ErrListFull", got)
	}
	if got, want := memberNames(t, r, "list"), []string{"m0", "m1", "m2", "m3"}; !slices.Equal(got, want) {
		t.Errorf("members after the refused add = %v, want %v", got, want)
	}
}

func TestListSetSizeStaysInRange(t *testing.T) {
	r, _ := newTestRegistry(t)
	for _, tc := range []struct {
		name string
		size uint32
		want uint32
	}{
		{"small", 1, listMinSize},
		{"exact", 100, 100},
		{"huge", 1 << 30, listMaxSize},
	} {
		create(t, r, tc.name, "list:set", FamilyUnspec, func(p *CreateParams) {
			p.Given |= GivenSize
			p.Size = tc.size
		})
		d, err := r.NewDump(tc.name, true)
		if err != nil {
			t.Fatalf("NewDump(%s): %v", tc.name, err)
		}
		_, head, ok, _ := d.Next()
		d.Close()
		if !ok || !head.HasSize || head.Size != tc.want {
			t.Errorf("%s: header size = %d (present %v), want %d", tc.name, head.Size, head.HasSize, tc.want)
		}
	}
}

func TestListSetPositionTestSkipsTimedOutMembers(t *testing.T) {
	r, clock := newTestRegistry(t)
	for _, name := range []string{"a", "b", "c"} {
		create(t, r, name, "hash:ip", FamilyIPv4, nil)
	}
	create(t, r, "list", "list:set", FamilyUnspec, func(p *CreateParams) {
		p.Given |= GivenTimeout
		p.Timeout = 1000
	})
	add := func(name string, timeout uint32) {
		t.Helper()
		e := Element{Has: HasName | HasTimeout, Name: name, Timeout: timeout}
		if got := uadt(r, "list", AdtAdd, e, 0); got != 0 {
			t.Fatalf("add %s = %d", name, got)
		}
	}
	add("a", 1000)
	add("b", 5)
	add("c", 1000)

	before := Element{Has: HasName | HasNameRef | HasCadtFlags, Name: "a", NameRef: "c", CadtFlags: CadtBefore}
	if got := uadt(r, "list", AdtTest, before, 0); got != 0 {
		t.Fatalf("test of a before c while b lives = %d, want 0", got)
	}
	clock.now += 10 * 1e9
	if got := uadt(r, "list", AdtTest, before, 0); got != 1 {
		t.Errorf("test of a before c after b timed out = %d, want 1", got)
	}
}
