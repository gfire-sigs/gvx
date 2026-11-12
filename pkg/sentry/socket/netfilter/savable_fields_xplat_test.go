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

package netfilter

import (
	"reflect"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/state"
)

// TestSavableStateFieldsMatchStructs fails when a struct in savable_xplat.go
// gains, loses, or renames a field without an edit to its state methods.
func TestSavableStateFieldsMatchStructs(t *testing.T) {
	for _, v := range []state.StructType{
		(*TCPMatcher)(nil), (*UDPMatcher)(nil), (*conntrackMatcher)(nil), (*MarkMatcher)(nil),
		(*commentMatcher)(nil), (*OwnerMatcher)(nil), (*OwnerMatcherV1)(nil),
		(*multiportMatcher)(nil), (*multiportMatcherV1)(nil), (*dnatTarget)(nil), (*snatTarget)(nil),
	} {
		typ := reflect.TypeOf(v).Elem()
		var want []string
		for i := range typ.NumField() {
			want = append(want, typ.Field(i).Name)
		}
		if got := v.StateFields(); !slices.Equal(got, want) {
			t.Errorf("%s: StateFields() = %v, want %v", typ.Name(), got, want)
		}
	}
}
