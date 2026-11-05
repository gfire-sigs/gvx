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
	"z.gfire.dev/gvx/pkg/marshal/primitive"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink"
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
		{Cmd: 5, Flags: OpNetAdmin, Do: nil, Dump: func(context.Context, *Request) (Dumper, *syserr.Error) { return nil, nil }},
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

// countDump is a Dumper that adds messages of 200 bytes, numbered from zero,
// and records the size of each chunk.
type countDump struct {
	total, next int
	sizes       []int
	done        int
}

func (d *countDump) DumpChunk(_ context.Context, chunk *Chunk) (bool, *syserr.Error) {
	for d.next < d.total {
		m := chunk.Message(1)
		payload := make([]byte, 200)
		payload[0], payload[1], payload[2], payload[3] = byte(d.next), byte(d.next>>8), byte(d.next>>16), byte(d.next>>24)
		m.Put(primitive.AsByteSlice(payload))
		if chunk.Size() > chunk.Limit() && chunk.Count() > 1 {
			chunk.Discard()
			break
		}
		d.next++
	}
	d.sizes = append(d.sizes, chunk.Size())
	return d.next < d.total, nil
}

func (d *countDump) DumpDone() { d.done++ }

// messageNumbers returns the numbers in the payloads of the messages that a
// chunk holds.
func messageNumbers(ms *nlmsg.MessageSet) []int {
	var out []int
	for _, m := range ms.Messages {
		b := m.Buffer()[linux.NetlinkMessageHeaderSize+headerSize:]
		out = append(out, int(b[0])|int(b[1])<<8|int(b[2])<<16|int(b[3])<<24)
	}
	return out
}

// TestDumpOfAnySizeFitsOneChunkAtATime checks that a dump of 4 MiB, far above
// the 192 KiB that the old dump accepted, ends without an error. Each call of
// the adapter produces one chunk that stays within the limit of the reader.
func TestDumpOfAnySizeFitsOneChunkAtATime(t *testing.T) {
	f := &Family{Name: uniqueName("t-large"), id: 0x77}
	d := &countDump{total: 20000}
	a := &dumpAdapter{family: f, dumper: d}
	const limit = 3776
	next := 0
	for chunks := 0; ; chunks++ {
		ms := nlmsg.NewMessageSet(1, 2)
		ms.Multi = true
		more, err := a.DumpChunk(context.Background(), ms, limit)
		if err != nil {
			t.Fatalf("chunk %d failed with %v", chunks, err)
		}
		for _, n := range messageNumbers(ms) {
			if n != next {
				t.Fatalf("message %d has the number %d", next, n)
			}
			next++
		}
		if !more {
			break
		}
	}
	if next != d.total {
		t.Errorf("the dump sent %d messages, want %d", next, d.total)
	}
	for i, size := range d.sizes[:len(d.sizes)-1] {
		if size > limit {
			t.Errorf("chunk %d has %d bytes, want at most %d", i, size, limit)
		}
	}
	a.DumpDone()
	if d.done != 1 {
		t.Errorf("DumpDone ran %d times, want 1", d.done)
	}
}

// TestControllerDumpListsEveryFamilyAcrossChunks checks that the dump of
// nlctrl continues in later chunks when the chunk is small, and that it keeps
// the order of the family IDs.
func TestControllerDumpListsEveryFamilyAcrossChunks(t *testing.T) {
	for range 5 {
		registerTestFamily(t, &Family{Name: uniqueName("t-chunks"), Ops: []Op{{Cmd: 1, Do: noop}}})
	}
	dumper, err := ctrlDumpFamilies(context.Background(), nil)
	if err != nil {
		t.Fatalf("ctrlDumpFamilies failed with %v", err)
	}
	a := &dumpAdapter{family: lookupName("nlctrl"), dumper: dumper}
	var ids []uint16
	chunks := 0
	for {
		ms := nlmsg.NewMessageSet(1, 2)
		ms.Multi = true
		more, err := a.DumpChunk(context.Background(), ms, 300)
		if err != nil {
			t.Fatalf("chunk %d failed with %v", chunks, err)
		}
		chunks++
		for _, m := range ms.Messages {
			attrs, ok := ParseAttrs(nlmsg.AttrsView(m.Buffer()[linux.NetlinkMessageHeaderSize+headerSize:]))
			if !ok {
				t.Fatal("a family message does not parse")
			}
			v := attrs[ctrlAttrFamilyID]
			id, _ := v.Uint16()
			ids = append(ids, id)
		}
		if !more {
			break
		}
	}
	want := families()
	if len(ids) != len(want) {
		t.Fatalf("the dump lists %d families, want %d", len(ids), len(want))
	}
	for i, f := range want {
		if ids[i] != f.ID() {
			t.Errorf("family %d has the ID %#x, want %#x", i, ids[i], f.ID())
		}
	}
	if chunks < 2 {
		t.Errorf("the dump used %d chunks, want several for a 300-byte limit", chunks)
	}
	var _ netlink.Dumper = a
}
