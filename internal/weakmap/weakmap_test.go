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

package weakmap

import (
	"runtime"
	"sync"
	"testing"
	"time"
	"weak"
)

type testOwner struct {
	id int
}

func TestStoreLoadDelete(t *testing.T) {
	var m Map[testOwner, int]

	if _, ok := m.Load(nil); ok {
		t.Fatal("Load(nil) reported present entry")
	}
	m.Store(nil, 42)
	if m.Len() != 0 {
		t.Fatalf("Len() after Store(nil) = %d, want 0", m.Len())
	}

	k1 := &testOwner{id: 1}
	k2 := &testOwner{id: 2}
	m.Store(k1, 10)
	m.Store(k1, 11)
	m.Store(k2, 20)

	if got := m.Len(); got != 2 {
		t.Fatalf("Len() = %d, want 2", got)
	}
	if v, ok := m.Load(k1); !ok || v != 11 {
		t.Fatalf("Load(k1) = (%d, %v), want (11, true)", v, ok)
	}
	if v, ok := m.Load(k2); !ok || v != 20 {
		t.Fatalf("Load(k2) = (%d, %v), want (20, true)", v, ok)
	}

	if v, ok := m.Delete(k1); !ok || v != 11 {
		t.Fatalf("Delete(k1) = (%d, %v), want (11, true)", v, ok)
	}
	if _, ok := m.Delete(k1); ok {
		t.Fatal("second Delete(k1) reported present entry")
	}
	if got := m.Len(); got != 1 {
		t.Fatalf("Len() after Delete(k1) = %d, want 1", got)
	}
	runtime.KeepAlive(k1)
	runtime.KeepAlive(k2)
}

func TestLoadOrStoreAndUpdate(t *testing.T) {
	var m Map[testOwner, string]
	k := &testOwner{id: 7}

	calls := 0
	got, loaded := m.LoadOrStore(k, func() string {
		calls++
		return "first"
	})
	if loaded || got != "first" || calls != 1 {
		t.Fatalf("first LoadOrStore = (%q, %v), calls=%d; want (\"first\", false, 1)", got, loaded, calls)
	}

	got, loaded = m.LoadOrStore(k, func() string {
		calls++
		return "second"
	})
	if !loaded || got != "first" || calls != 1 {
		t.Fatalf("second LoadOrStore = (%q, %v), calls=%d; want (\"first\", true, 1)", got, loaded, calls)
	}

	m.Update(k, func(old string, exists bool) (string, bool) {
		if !exists || old != "first" {
			t.Errorf("Update saw (%q, %v), want (\"first\", true)", old, exists)
		}
		return "updated", true
	})
	if v, ok := m.Load(k); !ok || v != "updated" {
		t.Fatalf("Load after Update = (%q, %v), want (\"updated\", true)", v, ok)
	}

	m.Update(k, func(_ string, _ bool) (string, bool) {
		return "", false
	})
	if m.Len() != 0 {
		t.Fatalf("Len() after Update drop = %d, want 0", m.Len())
	}
	runtime.KeepAlive(k)
}

func TestGarbageCollectionReclaimsUnreachableKeys(t *testing.T) {
	var m Map[testOwner, [256]byte]
	var wk weak.Pointer[testOwner]

	func() {
		k := &testOwner{id: 99}
		wk = weak.Make(k)
		m.Store(k, [256]byte{1, 2, 3})
		if m.Len() != 1 {
			t.Fatalf("Len() before drop = %d, want 1", m.Len())
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if wk.Value() == nil && m.Len() == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("entry survived GC: wk.Value()=%v, m.Len()=%d", wk.Value(), m.Len())
}

func TestConcurrentAccess(t *testing.T) {
	var m Map[testOwner, int]
	keys := make([]*testOwner, 16)
	for i := range keys {
		keys[i] = &testOwner{id: i}
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				k := keys[(worker+i)%len(keys)]
				switch i % 4 {
				case 0:
					m.Store(k, i)
				case 1:
					m.Load(k)
				case 2:
					m.LoadOrStore(k, func() int { return i })
				case 3:
					m.Delete(k)
				}
			}
		}(g)
	}
	wg.Wait()
	runtime.KeepAlive(keys)
}
