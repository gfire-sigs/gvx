//go:build (darwin || windows) && amd64

package systrap

import "testing"

func TestGSFaultAddr(t *testing.T) {
	for _, tc := range []struct {
		name            string
		hw, start, size uint64
		want            uint64
	}{
		{"inside one page", 0x7000_0030, 0x7000_0030, 8, 0x7000_0030},
		{"hardware address differs, no crossing", 0x1234_0030, 0x7000_0030, 8, 0x7000_0030},
		{"crossing, second page faults", 0x7000_1000, 0x7000_0ffc, 8, 0x7000_1000},
		{"crossing, first page faults", 0x7000_0ffc, 0x7000_0ffc, 8, 0x7000_0ffc},
		{"32-bit access that ends at the boundary", 0x7000_1000, 0x7000_0ffc, 4, 0x7000_0ffc},
		{"hardware at a boundary the access does not reach", 0x7000_2000, 0x7000_0ffc, 8, 0x7000_0ffc},
		{"hardware at a later boundary of another page", 0x1234_1000, 0x7000_0ffc, 8, 0x7000_0ffc},
		{"start on a boundary", 0x7000_1000, 0x7000_1000, 8, 0x7000_1000},
	} {
		if got := gsFaultAddr(tc.hw, tc.start, tc.size); got != tc.want {
			t.Errorf("%s: gsFaultAddr(%#x, %#x, %d) = %#x, want %#x", tc.name, tc.hw, tc.start, tc.size, got, tc.want)
		}
	}
	if (siteInfo{wide: true}).gsAccessSize() != 8 || (siteInfo{}).gsAccessSize() != 4 {
		t.Error("gsAccessSize does not follow the register width")
	}
}
