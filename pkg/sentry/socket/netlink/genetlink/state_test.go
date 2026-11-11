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
	"bytes"
	stdcontext "context"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netlink/nlmsg"
	"z.gfire.dev/gvx/pkg/state"
)

func TestStateRoundTripProtocolAndControllerDump(t *testing.T) {
	f1 := &Family{Name: uniqueName("state-fam-a"), Version: 1, Ops: []Op{{Cmd: 1, Do: noop}}}
	f2 := &Family{Name: uniqueName("state-fam-b"), Version: 2, Ops: []Op{{Cmd: 2, Do: noop}}}
	registerTestFamily(t, f1)
	registerTestFamily(t, f2)

	protoIfc, err := NewProtocol(nil)
	if err != nil {
		t.Fatalf("NewProtocol: %v", err)
	}
	proto := protoIfc.(*Protocol)

	ctrl := lookupName("nlctrl")
	if ctrl == nil {
		t.Fatal("nlctrl family is not registered")
	}
	dumper, sysErr := ctrlDumpFamilies(context.Background(), &Request{})
	if sysErr != nil {
		t.Fatalf("ctrlDumpFamilies: %v", sysErr)
	}
	adapter := &dumpAdapter{family: ctrl, dumper: dumper}

	// Consume the first family entry before checkpoint so index > 0 is preserved.
	firstSet := nlmsg.NewMessageSet(0, 1)
	firstSet.Multi = true
	more, sysErr := adapter.DumpChunk(context.Background(), firstSet, linux.NetlinkMessageHeaderSize+128)
	if sysErr != nil || !more {
		t.Fatalf("initial DumpChunk: more=%v err=%v", more, sysErr)
	}

	var buf bytes.Buffer
	graph := []any{proto, adapter}
	if _, saveErr := state.Save(stdcontext.Background(), &buf, &graph); saveErr != nil {
		t.Fatalf("state.Save: %v", saveErr)
	}

	var loaded []any
	if _, loadErr := state.Load(stdcontext.Background(), &buf, &loaded); loadErr != nil {
		t.Fatalf("state.Load: %v", loadErr)
	}
	restoredProto := loaded[0].(*Protocol)
	restoredAdapter := loaded[1].(*dumpAdapter)

	if got := restoredProto.Protocol(); got != linux.NETLINK_GENERIC {
		t.Errorf("restored Protocol() = %d, want %d", got, linux.NETLINK_GENERIC)
	}
	if restoredAdapter.family != ctrl {
		t.Fatal("restored dumpAdapter did not rebind to nlctrl family")
	}

	var seenNames []string
	for {
		ms := nlmsg.NewMessageSet(0, 2)
		ms.Multi = true
		cont, dumpErr := restoredAdapter.DumpChunk(context.Background(), ms, 4096)
		if dumpErr != nil {
			t.Fatalf("restored DumpChunk: %v", dumpErr)
		}
		for _, m := range ms.Messages {
			raw := m.Buffer()
			attrs, ok := ParseAttrs(nlmsg.AttrsView(raw[linux.NetlinkMessageHeaderSize+headerSize:]))
			if !ok {
				t.Fatal("ParseAttrs failed on restored family dump message")
			}
			v := attrs[ctrlAttrFamilyName]
			seenNames = append(seenNames, v.String())
		}
		if !cont {
			break
		}
	}
	var sawF1, sawF2 bool
	for _, n := range seenNames {
		if n == f1.Name {
			sawF1 = true
		}
		if n == f2.Name {
			sawF2 = true
		}
	}
	if !sawF1 || !sawF2 {
		t.Errorf("remaining dump names %v missing %q or %q", seenNames, f1.Name, f2.Name)
	}
}
