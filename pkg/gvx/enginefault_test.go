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
	"strings"
	"testing"
)

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
