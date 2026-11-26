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

package state

import (
	"io"
	"reflect"
	"testing"
)

func TestHashTypeSigDistinguishesInterfaces(t *testing.T) {
	ifaceA := reflect.TypeFor[interface{ Read([]byte) (int, error) }]()
	ifaceB := reflect.TypeFor[interface{ Write([]byte) (int, error) }]()
	ifaceC := reflect.TypeFor[interface {
		Read([]byte) (int, error)
		Close() error
	}]()
	namedReader := reflect.TypeFor[io.Reader]()
	namedReadCloser := reflect.TypeFor[io.ReadCloser]()
	empty := reflect.TypeFor[any]()

	hA1 := hashTypeSig(fnvOffset, ifaceA, 0, nil)
	hA2 := hashTypeSig(fnvOffset, ifaceA, 0, nil)
	if hA1 != hA2 {
		t.Fatalf("hashTypeSig not deterministic: %#x != %#x", hA1, hA2)
	}

	hashes := map[string]uint64{
		"ifaceA":          hA1,
		"ifaceB":          hashTypeSig(fnvOffset, ifaceB, 0, nil),
		"ifaceC":          hashTypeSig(fnvOffset, ifaceC, 0, nil),
		"namedReader":     hashTypeSig(fnvOffset, namedReader, 0, nil),
		"namedReadCloser": hashTypeSig(fnvOffset, namedReadCloser, 0, nil),
		"empty":           hashTypeSig(fnvOffset, empty, 0, nil),
	}
	seen := make(map[uint64]string, len(hashes))
	for label, h := range hashes {
		if prev, dup := seen[h]; dup {
			t.Errorf("interface hash collision between %s and %s: %#x", prev, label, h)
		}
		seen[h] = label
	}
}
