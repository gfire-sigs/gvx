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

//go:build linux

package systrap

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// These tests start real stub processes. The host kernel is the producer of
// the process tree, the descriptor table, and the mappings that they count.

// sharedPlatform is the one platform of the test binary. The source stub of
// globalPool keeps the memory file of the first platform, so all tests use it.
var sharedPlatform = sync.OnceValues(func() (*Systrap, error) {
	// New reads the CPU features of the host on amd64.
	cpuid.Initialize()
	return New(platform.Options{})
})

// mapAddr is the guest address where the tests map one page. It lies far
// below the stub region, which sits at the top of the address space.
const mapAddr = hostarch.Addr(1 << 28)

func requirePlatform(t *testing.T) *Systrap {
	t.Helper()
	if cgoBuild {
		t.Skip("the upstream systrap platform hangs while it starts in a cgo build (race builds use cgo)")
	}
	p, err := sharedPlatform()
	if err != nil {
		t.Skipf("systrap engine unavailable: %v", err)
	}
	if !procChildrenAvailable() {
		t.Skip("the host kernel has no /proc/<tid>/children (CONFIG_PROC_CHILDREN)")
	}
	drainIdleStubs()
	return p
}

// useIdleLimit replaces the bound of the idle pool for one test.
func useIdleLimit(t *testing.T, k int) {
	t.Helper()
	old := idleStubLimit
	idleStubLimit = func() int { return k }
	t.Cleanup(func() {
		drainIdleStubs()
		idleStubLimit = old
	})
}

// drainIdleStubs destroys every stub in the idle pool.
func drainIdleStubs() {
	for sp := globalPool.fetchAvailable(); sp != nil; sp = globalPool.fetchAvailable() {
		sp.destroyIdle()
	}
}

func procChildrenAvailable() bool {
	files, _ := filepath.Glob("/proc/self/task/*/children")
	return len(files) > 0
}

// childPIDs returns the child processes of the test process. A zombie that
// the test process did not reap counts as a child.
func childPIDs(t testing.TB) map[int]struct{} {
	t.Helper()
	files, err := filepath.Glob("/proc/self/task/*/children")
	if err != nil {
		t.Fatalf("glob /proc/self/task/*/children: %v", err)
	}
	pids := make(map[int]struct{})
	for _, f := range files {
		b, err := os.ReadFile(f)
		if os.IsNotExist(err) {
			continue // The Go runtime ended this thread.
		}
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for _, field := range strings.Fields(string(b)) {
			pid, err := strconv.Atoi(field)
			if err != nil {
				t.Fatalf("parse child pid %q in %s: %v", field, f, err)
			}
			pids[pid] = struct{}{}
		}
	}
	return pids
}

func countChildren(t testing.TB) int {
	t.Helper()
	return len(childPIDs(t))
}

func newTestAddressSpace(p *Systrap) (*subprocess, error) {
	as, err := p.NewAddressSpace(platform.AddressSpaceOptions{})
	if err != nil {
		return nil, err
	}
	return as.(*subprocess), nil
}

// mapAndUnmapPage maps one page of the platform memory file into the address
// space and unmaps it. The call goes through the syscall thread of the stub.
func mapAndUnmapPage(p *Systrap, as platform.AddressSpace) error {
	fr, err := p.memoryFile.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		return fmt.Errorf("allocate: %w", err)
	}
	defer p.memoryFile.DecRef(fr)
	if err := as.MapFile(mapAddr, p.memoryFile, fr, hostarch.ReadWrite, false); err != nil {
		return fmt.Errorf("MapFile: %w", err)
	}
	as.Unmap(mapAddr, hostarch.PageSize)
	return nil
}

// spaceSet holds the live address spaces of one test. The cleanup of the test
// releases the address spaces that the test did not release, so a failed test
// does not leave live stubs for the next test.
type spaceSet struct {
	spaces   []*subprocess
	released map[*subprocess]bool
}

// useAddressSpaces creates n address spaces and uses each one.
func useAddressSpaces(t *testing.T, p *Systrap, n int) *spaceSet {
	t.Helper()
	set := &spaceSet{released: make(map[*subprocess]bool)}
	t.Cleanup(func() { set.release(set.spaces...) })
	for i := range n {
		sp, err := newTestAddressSpace(p)
		if err != nil {
			t.Fatalf("NewAddressSpace %d of %d: %v", i, n, err)
		}
		set.spaces = append(set.spaces, sp)
		if err := mapAndUnmapPage(p, sp); err != nil {
			t.Fatalf("address space %d of %d: %v", i, n, err)
		}
	}
	return set
}

// release releases each address space that is still live.
func (g *spaceSet) release(spaces ...*subprocess) {
	for _, sp := range spaces {
		if !g.released[sp] {
			g.released[sp] = true
			sp.Release()
		}
	}
}

func TestReleasedStubsStayWithinTheIdleBound(t *testing.T) {
	p := requirePlatform(t)
	const k = 2
	useIdleLimit(t, k)

	for round := 1; round <= 2; round++ {
		set := useAddressSpaces(t, p, 8)
		if got, want := countChildren(t), 8+1; got != want {
			t.Fatalf("round %d: %d live address spaces: %d child processes, want %d (live stubs plus the source stub)", round, len(set.spaces), got, want)
		}
		set.release(set.spaces...)
		if got, want := countChildren(t), k+1; got != want {
			t.Fatalf("round %d: after releasing 8 address spaces with bound %d: %d child processes, want %d (pooled stubs plus the source stub)", round, k, got, want)
		}
	}
}

func TestStubOutlivesAddressSpaceUntilTheLastContextReleases(t *testing.T) {
	p := requirePlatform(t)
	useIdleLimit(t, 0)

	sp, err := newTestAddressSpace(p)
	if err != nil {
		t.Fatalf("NewAddressSpace: %v", err)
	}
	sc, err := sp.getSharedContext()
	if err != nil {
		t.Fatalf("getSharedContext: %v", err)
	}
	sp.Release()
	if got, want := countChildren(t), 2; got != want {
		t.Fatalf("a shared context still uses the stub: %d child processes, want %d", got, want)
	}
	sc.release()
	if got, want := countChildren(t), 1; got != want {
		t.Fatalf("the last shared context released the stub: %d child processes, want %d (the source stub)", got, want)
	}
}

// memfdMappings returns the number of lines of /proc/self/maps that map the
// file with inode ino, the sum of their lengths, and the number of all lines.
func memfdMappings(t testing.TB, ino uint64) (lines int, bytes uint64, all int) {
	t.Helper()
	b, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		t.Fatalf("read /proc/self/maps: %v", err)
	}
	for line := range strings.Lines(string(b)) {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		all++
		if fields[4] != strconv.FormatUint(ino, 10) || !strings.Contains(line, "memfd:") {
			continue
		}
		var start, end uint64
		if _, err := fmt.Sscanf(fields[0], "%x-%x", &start, &end); err != nil {
			t.Fatalf("parse maps line %q: %v", line, err)
		}
		lines++
		bytes += end - start
	}
	return lines, bytes, all
}

func openFDs(t testing.TB) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("read /proc/self/fd: %v", err)
	}
	return len(entries)
}

// settledUsage returns the allocated bytes of the memory file after the value
// stops changing and does not exceed atMost. The releaser goroutine of the
// file decommits waste pages in the background, so the value settles later
// than the last release. The call returns the last value when it does not
// settle in 20 seconds.
func settledUsage(t testing.TB, mf *pgalloc.MemoryFile, atMost uint64) uint64 {
	t.Helper()
	const stableReads = 5
	deadline := time.Now().Add(20 * time.Second)
	var prev uint64
	stable := 0
	for {
		got, err := mf.TotalUsage()
		if err != nil {
			t.Fatalf("TotalUsage: %v", err)
		}
		if got == prev {
			stable++
		} else {
			stable = 0
		}
		prev = got
		if (stable >= stableReads && got <= atMost) || time.Now().After(deadline) {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type hostCounts struct {
	fds, children, memfdLines, allLines int
	memfdBytes, usage                   uint64
}

func (c hostCounts) String() string {
	return fmt.Sprintf("fds=%d children=%d memfd mapping lines=%d memfd mapped bytes=%d all mapping lines=%d memory file usage=%d",
		c.fds, c.children, c.memfdLines, c.memfdBytes, c.allLines, c.usage)
}

func measureHost(t testing.TB, mf *pgalloc.MemoryFile, ino uint64, usageAtMost uint64) hostCounts {
	t.Helper()
	lines, bytes, all := memfdMappings(t, ino)
	return hostCounts{
		fds:        openFDs(t),
		children:   countChildren(t),
		memfdLines: lines,
		memfdBytes: bytes,
		allLines:   all,
		usage:      settledUsage(t, mf, usageAtMost),
	}
}

func TestDestroyingEveryReleasedStubLeaksNothing(t *testing.T) {
	p := requirePlatform(t)
	useIdleLimit(t, 0)

	st, err := p.memoryFile.File().Stat()
	if err != nil {
		t.Fatalf("stat memory file: %v", err)
	}
	ino := st.Sys().(*syscall.Stat_t).Ino

	oneRound := func() {
		sp, err := newTestAddressSpace(p)
		if err != nil {
			t.Fatalf("NewAddressSpace: %v", err)
		}
		if err := mapAndUnmapPage(p, sp); err != nil {
			t.Fatalf("use address space: %v", err)
		}
		sp.Release()
	}

	// The first round is a warm-up: it makes the Go runtime open its own
	// descriptors and mappings before the first measurement.
	oneRound()
	first := measureHost(t, p.memoryFile, ino, math.MaxUint64)
	t.Logf("after the warm-up round: %v", first)
	const rounds = 500
	for range rounds {
		oneRound()
	}
	last := measureHost(t, p.memoryFile, ino, first.usage)
	t.Logf("after %d rounds: %v", rounds, last)

	// The Go runtime maps and unmaps its own memory, so the total of mapping
	// lines may move a little. The lines of the memory file may not move.
	const runtimeSlack = 16
	if last.fds != first.fds || last.children != first.children ||
		last.memfdLines != first.memfdLines || last.memfdBytes != first.memfdBytes ||
		last.usage > first.usage || last.allLines > first.allLines+runtimeSlack {
		t.Fatalf("after %d create and release rounds with bound 0, the host counts differ from the first round\nfirst: %v\nlast:  %v",
			rounds, first, last)
	}
}

func TestIdleBoundHoldsUnderConcurrentReleaseAndMapFile(t *testing.T) {
	p := requirePlatform(t)
	const k = 2
	useIdleLimit(t, k)

	const (
		churners = 4
		rounds   = 15
		steady   = 3
	)
	steadySet := useAddressSpaces(t, p, steady)

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		failures []error
	)
	fail := func(err error) {
		mu.Lock()
		defer mu.Unlock()
		failures = append(failures, err)
	}
	stop := make(chan struct{})

	// Steady address spaces call MapFile while other stubs are destroyed.
	var steadyWG sync.WaitGroup
	for i, sp := range steadySet.spaces {
		steadyWG.Add(1)
		go func() {
			defer steadyWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if err := mapAndUnmapPage(p, sp); err != nil {
					fail(fmt.Errorf("steady address space %d: %w", i, err))
					return
				}
			}
		}()
	}

	for i := range churners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for r := range rounds {
				sp, err := newTestAddressSpace(p)
				if err != nil {
					fail(fmt.Errorf("churner %d round %d: NewAddressSpace: %w", i, r, err))
					return
				}
				if err := mapAndUnmapPage(p, sp); err != nil {
					fail(fmt.Errorf("churner %d round %d: %w", i, r, err))
				}
				sp.Release()
			}
		}()
	}
	wg.Wait()
	close(stop)
	steadyWG.Wait()
	steadySet.release(steadySet.spaces...)

	for _, err := range failures {
		t.Error(err)
	}
	if got, limit := countChildren(t), k+1; got > limit {
		t.Errorf("after the churn and releasing all address spaces: %d child processes, want at most %d", got, limit)
	}
}

func TestDefaultIdleBoundLimitsStubsToLivePlusBound(t *testing.T) {
	p := requirePlatform(t)
	k := idleStubLimit()

	atMost := func(stage string, live int) {
		t.Helper()
		if got, limit := countChildren(t), live+k+1; got > limit {
			t.Fatalf("%s: %d live address spaces and bound %d: %d child processes, want at most %d", stage, live, k, got, limit)
		}
	}

	set := useAddressSpaces(t, p, k+4)
	atMost("all live", len(set.spaces))
	half := len(set.spaces) / 2
	set.release(set.spaces[:half]...)
	atMost("half released", len(set.spaces)-half)
	set.release(set.spaces...)
	atMost("all released", 0)
	if got, want := countChildren(t), k+1; got != want {
		t.Fatalf("after releasing %d address spaces with bound %d: %d child processes, want %d (the bound plus the source stub)", len(set.spaces), k, got, want)
	}

	// A new round reuses the pooled stubs and stays within the bound.
	set = useAddressSpaces(t, p, k+4)
	atMost("second round, all live", len(set.spaces))
	set.release(set.spaces...)
	atMost("second round, all released", 0)
}
