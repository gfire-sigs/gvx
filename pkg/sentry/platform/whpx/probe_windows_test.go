//go:build windows

package whpx

import (
	"testing"
	"unsafe"
)

func probePartition(t *testing.T) *winBackend {
	be, err := newBackend()
	if err != nil {
		t.Skip(err)
	}
	wb := be.(*winBackend)
	if _, err := wb.createPartition(partitionConfig{vpCount: 1}); err != nil {
		t.Fatalf("createPartition: %v", err)
	}
	return wb
}

func TestProbeTwoPartitions(t *testing.T) {
	for _, tc := range []struct {
		name       string
		gpa1, gpa2 uint64
		flags      uint32
	}{
		{"same gpa", 1 << 30, 1 << 30, mapFlagRead | mapFlagWrite},
		{"other gpa", 1 << 30, 2 << 30, mapFlagRead | mapFlagWrite},
		{"same gpa rx", 1 << 30, 1 << 30, mapFlagRead | mapFlagExecute},
		{"other gpa rx", 1 << 30, 2 << 30, mapFlagRead | mapFlagExecute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := probePartition(t), probePartition(t)
			defer a.closePartition()
			defer b.closePartition()
			for i, p := range []struct {
				be  *winBackend
				gpa uint64
			}{{a, tc.gpa1}, {b, tc.gpa2}} {
				mem, err := p.be.allocHost(ptSlabSize)
				if err != nil {
					t.Fatal(err)
				}
				err = p.be.mapGPA(unsafe.Pointer(&mem[0]), p.gpa, pageSize, tc.flags)
				t.Logf("partition %d: host %p gpa %#x: err=%v", i, &mem[0], p.gpa, err)
			}
		})
	}
	t.Run("sequential", func(t *testing.T) {
		a := probePartition(t)
		mem, _ := a.allocHost(ptSlabSize)
		t.Logf("first: %v", a.mapGPA(unsafe.Pointer(&mem[0]), 1<<30, pageSize, mapFlagRead|mapFlagWrite))
		a.closePartition()
		b := probePartition(t)
		defer b.closePartition()
		mem2, _ := b.allocHost(ptSlabSize)
		t.Logf("second after first closed: %v", b.mapGPA(unsafe.Pointer(&mem2[0]), 1<<30, pageSize, mapFlagRead|mapFlagWrite))
	})
}
