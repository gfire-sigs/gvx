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

package netlink

import (
	"bytes"
	stdcontext "context"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/state"
)

// saveLoadDumpResume sends the dump record of s through pkg/state, as a
// checkpoint and a restore do, and returns the loaded record.
func saveLoadDumpResume(t *testing.T, s *Socket) dumpResume {
	t.Helper()
	s.beforeSave()
	var buf bytes.Buffer
	if _, err := state.Save(stdcontext.Background(), &buf, &s.dumpResume); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	var loaded dumpResume
	if _, err := state.Load(stdcontext.Background(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	return loaded
}

func TestRestoredSocketEndsInterruptedDumpWithDoneMessage(t *testing.T) {
	d := &testDumper{items: 300}
	saved, ctx := newDumpSocket(t, d)
	if err := saved.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	resume := saveLoadDumpResume(t, saved)

	// The restored socket has an empty receive queue and no Dumper.
	restored, _ := newDumpSocket(t, &testDumper{})
	restored.dumpResume = resume
	restored.afterLoad(ctx)

	items, _, others := readAll(t, ctx, restored, 4096)
	if len(items) != 0 {
		t.Errorf("restored socket produced %d dump items, want 0", len(items))
	}
	if len(others) != 1 {
		t.Fatalf("restored socket produced %d messages, want one NLMSG_DONE", len(others))
	}
	done := others[0]
	if got := doneErrno(t, done); got != 0 {
		t.Errorf("NLMSG_DONE errno = %d, want 0", got)
	}
	hdr := done.Header()
	if hdr.Flags&linux.NLM_F_DUMP_INTR == 0 {
		t.Errorf("NLMSG_DONE flags = %#x, want NLM_F_DUMP_INTR", hdr.Flags)
	}
	if hdr.Seq != testSeq || hdr.PortID != testPortID {
		t.Errorf("NLMSG_DONE seq = %d and port = %d, want %d and %d", hdr.Seq, hdr.PortID, testSeq, testPortID)
	}
}

func TestRestoredSocketWithoutDumpSendsNothing(t *testing.T) {
	idle, ctx := newDumpSocket(t, &testDumper{})
	resume := saveLoadDumpResume(t, idle)

	restored, _ := newDumpSocket(t, &testDumper{})
	restored.dumpResume = resume
	restored.afterLoad(ctx)
	if msgs := recvDatagram(t, ctx, restored, 4096); msgs != nil {
		t.Errorf("restored idle socket has %d queued messages, want none", len(msgs))
	}
}

func TestRestoredSocketAfterFinishedDumpSendsNothing(t *testing.T) {
	d := &testDumper{items: 3}
	finished, ctx := newDumpSocket(t, d)
	if err := finished.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	readAll(t, ctx, finished, 4096)
	resume := saveLoadDumpResume(t, finished)
	if resume.interrupted {
		t.Fatal("a dump that sent NLMSG_DONE is marked interrupted")
	}
}

func TestCheckpointWithoutStopDoesNotChangeRunningDump(t *testing.T) {
	d := &testDumper{items: 300}
	s, ctx := newDumpSocket(t, d)
	if err := s.ProcessMessages(ctx, dumpRequest(linux.NLM_F_REQUEST|linux.NLM_F_DUMP)); err != nil {
		t.Fatalf("ProcessMessages: %v", err)
	}
	if resume := saveLoadDumpResume(t, s); !resume.interrupted {
		t.Fatal("a running dump is not marked interrupted")
	}
	items, _, others := readAll(t, ctx, s, 4096)
	checkItems(t, items, 300)
	if len(others) != 1 {
		t.Fatalf("running dump produced %d other messages, want one NLMSG_DONE", len(others))
	}
	if hdr := others[0].Header(); hdr.Flags&linux.NLM_F_DUMP_INTR != 0 {
		t.Errorf("NLMSG_DONE of an uninterrupted dump has NLM_F_DUMP_INTR (flags %#x)", hdr.Flags)
	}
}
