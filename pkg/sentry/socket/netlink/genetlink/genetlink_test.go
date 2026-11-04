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

package genetlink

import (
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/syserr"
)

func noop(context.Context, *Request, *Reply) *syserr.Error { return nil }

// testRuns makes the family names unique for each run, so that -count=2 does
// not register a name twice.
var testRuns atomic.Int32

// uniqueName returns a family name that no other run of the tests uses.
func uniqueName(base string) string {
	return fmt.Sprintf("%s-%d", base, testRuns.Add(1))
}

// registerTestFamily registers f and removes it when the test ends.
func registerTestFamily(t *testing.T, f *Family) {
	t.Helper()
	RegisterFamily(f)
	t.Cleanup(func() {
		registryMu.Lock()
		defer registryMu.Unlock()
		delete(byID, f.id)
		delete(byName, f.Name)
	})
}

func TestRegisterFamilyAssignsIDsAfterTheController(t *testing.T) {
	f := &Family{Name: uniqueName("test-assign"), Version: 3, Ops: []Op{{Cmd: 1, Do: noop}}}
	registerTestFamily(t, f)
	if f.ID() <= ControllerID {
		t.Errorf("ID = %#x, want an ID above %#x", f.ID(), ControllerID)
	}
	if lookupID(f.ID()) != f || lookupName(f.Name) != f {
		t.Error("the registry does not find the family by ID and by name")
	}
	if c := lookupName("nlctrl"); c == nil || c.ID() != ControllerID {
		t.Errorf("nlctrl = %+v, want the ID %#x", c, ControllerID)
	}
	ids := map[uint16]bool{}
	for _, fam := range families() {
		if ids[fam.ID()] {
			t.Errorf("family ID %#x appears twice", fam.ID())
		}
		ids[fam.ID()] = true
	}
}

func TestRegisterFamilyRejectsInvalidFamilies(t *testing.T) {
	twice := uniqueName("test-twice")
	registerTestFamily(t, &Family{Name: twice})
	for name, f := range map[string]*Family{
		"duplicate name":  {Name: twice},
		"empty name":      {},
		"name too long":   {Name: strings.Repeat("x", maxNameLen)},
		"command no code": {Name: uniqueName("test-nocode"), Ops: []Op{{Cmd: 1}}},
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Error("RegisterFamily did not panic")
				}
			}()
			RegisterFamily(f)
		})
	}
}

func TestFillFamilyEncodesTheAttributesOfTheController(t *testing.T) {
	f := &Family{Name: "test-fill", Version: 4, HdrSize: 8, MaxAttr: 9, id: 0x42, Ops: []Op{
		{Cmd: 0, Flags: OpNetAdmin, Dump: nil, Do: noop},
		{Cmd: 5, Flags: OpNetAdmin, Do: nil, Dump: func(context.Context, *Request, *Dump) *syserr.Error { return nil }},
	}}
	m := nlmsg.NewMessage(linux.NetlinkMessageHeader{})
	fillFamily(m, f)
	attrs, ok := ParseAttrs(nlmsg.AttrsView(m.Buffer()[linux.NetlinkMessageHeaderSize:]))
	if !ok {
		t.Fatal("ParseAttrs failed")
	}
	u32 := func(typ uint16) uint32 {
		v := attrs[typ]
		n, ok := v.Uint32()
		if !ok {
			t.Fatalf("attribute %d is not a u32", typ)
		}
		return n
	}
	id := attrs[ctrlAttrFamilyID]
	if got, _ := id.Uint16(); got != 0x42 {
		t.Errorf("family ID = %#x, want 0x42", got)
	}
	name := attrs[ctrlAttrFamilyName]
	if name.String() != "test-fill" {
		t.Errorf("family name = %q", name.String())
	}
	if u32(ctrlAttrVersion) != 4 || u32(ctrlAttrHdrSize) != 8 || u32(ctrlAttrMaxAttr) != 9 {
		t.Errorf("version, header size, and max attr = %d, %d, %d", u32(ctrlAttrVersion), u32(ctrlAttrHdrSize), u32(ctrlAttrMaxAttr))
	}
	entries, ok := ParseAttrs(nlmsg.AttrsView(attrs[ctrlAttrOps]))
	if !ok || len(entries) != 2 {
		t.Fatalf("ops = %v, %v, want two entries", entries, ok)
	}
	// Each entry has the 1-based position as its type.
	for pos, want := range map[uint16][2]uint32{1: {0, uint32(OpNetAdmin | opCapDo)}, 2: {5, uint32(OpNetAdmin | opCapDump)}} {
		op, ok := ParseAttrs(nlmsg.AttrsView(entries[pos]))
		if !ok {
			t.Fatalf("entry %d does not parse", pos)
		}
		idAttr, flagsAttr := op[ctrlAttrOpID], op[ctrlAttrOpFlags]
		gotID, _ := idAttr.Uint32()
		gotFlags, _ := flagsAttr.Uint32()
		if gotID != want[0] || gotFlags != want[1] {
			t.Errorf("entry %d = command %d with flags %#x, want command %d with flags %#x", pos, gotID, gotFlags, want[0], want[1])
		}
	}
}

func TestParseAttrsClearsTheNestedFlag(t *testing.T) {
	var n nlmsg.NestedAttr
	n.PutAttr(7|linux.NLA_F_NESTED, nlmsg.PutU8(1))
	attrs, ok := ParseAttrs(nlmsg.AttrsView(n))
	if _, found := attrs[7]; !ok || !found {
		t.Errorf("ParseAttrs = %v, %v, want an attribute of type 7", attrs, ok)
	}
	if _, ok := ParseAttrs(nlmsg.AttrsView([]byte{9, 0, 1})); ok {
		t.Error("ParseAttrs accepted a truncated attribute")
	}
}
