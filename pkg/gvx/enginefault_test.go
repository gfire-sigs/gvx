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
)

func TestEngineFaultLogRecordsTheCauseAndForwardsEveryLine(t *testing.T) {
	_ = takeEngineFault()
	var sink bytes.Buffer
	w := engineFaultLog{next: &sink}
	lines := []string{
		"W1028 05:54:34.089849    5068 cpuid.go:253] cpuid HWCap not initialized\n",
		"W1028 05:54:35.000001    5068 task_run.go:364] [   1:   1] Unexpected SwitchToApp error: the stub died: exit code 0xc0000005\n",
		"I1028 05:54:35.100000    5068 loader.go:270] Error loading ELF: out of memory\n",
	}
	for _, l := range lines {
		if n, err := w.Write([]byte(l)); n != len(l) || err != nil {
			t.Fatalf("Write = (%d, %v), want (%d, nil)", n, err, len(l))
		}
	}
	if got := sink.String(); got != strings.Join(lines, "") {
		t.Errorf("the writer changed the log: %q", got)
	}
	if got, want := takeEngineFault(), "the stub died: exit code 0xc0000005"; got != want {
		t.Errorf("takeEngineFault = %q, want %q", got, want)
	}
	if got := takeEngineFault(); got != "" {
		t.Errorf("a second takeEngineFault = %q, want it empty", got)
	}
}

func TestEngineFaultErrorNamesTheCauseAndTheLogSwitch(t *testing.T) {
	err := engineFaultError("the stub died")
	if !errors.Is(err, ErrEngineFault) {
		t.Errorf("%v does not wrap ErrEngineFault", err)
	}
	for _, want := range []string{"the stub died", "GVX_DEBUG_LOG=1"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}
