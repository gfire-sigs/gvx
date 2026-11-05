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
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// MinMemoryLimit is the smallest memory limit that ParseMemory accepts. Docker
// uses the same minimum.
const MinMemoryLimit = 6 << 20

// ErrMemoryLimit reports that the guest passed its memory limit and that the
// sandbox killed it.
var ErrMemoryLimit = errors.New("gvx: the guest passed its memory limit")

// memoryUnits maps a unit suffix to its binary multiple, as Docker does.
var memoryUnits = map[string]float64{
	"": 1, "b": 1,
	"k": 1 << 10, "kb": 1 << 10,
	"m": 1 << 20, "mb": 1 << 20,
	"g": 1 << 30, "gb": 1 << 30,
	"t": 1 << 40, "tb": 1 << 40,
}

// ParseMemory parses a memory size such as "512m", "1.5g", or "4194304". The
// units are binary and case-insensitive. A "0" means no limit and returns 0.
// Any other size below MinMemoryLimit is an error.
func ParseMemory(s string) (int64, error) {
	raw := strings.ToLower(strings.TrimSpace(s))
	if raw == "" {
		return 0, fmt.Errorf("%w: empty memory size", ErrInvalidConfig)
	}
	split := strings.IndexFunc(raw, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	num, unit := raw, ""
	if split >= 0 {
		num, unit = raw[:split], raw[split:]
	}
	mult, ok := memoryUnits[unit]
	if !ok {
		return 0, fmt.Errorf("%w: unknown unit %q in memory size %q (want b, k, m, g, or t)", ErrInvalidConfig, unit, s)
	}
	n, err := strconv.ParseFloat(num, 64)
	if err != nil || n < 0 || math.IsNaN(n) || math.IsInf(n, 0) {
		return 0, fmt.Errorf("%w: invalid memory size %q", ErrInvalidConfig, s)
	}
	bytes := n * mult
	if bytes >= math.MaxInt64 {
		return 0, fmt.Errorf("%w: memory size %q is too large", ErrInvalidConfig, s)
	}
	limit := int64(bytes)
	if limit == 0 {
		return 0, nil
	}
	if limit < MinMemoryLimit {
		return 0, fmt.Errorf("%w: memory size %q is below the minimum of 6m", ErrInvalidConfig, s)
	}
	return limit, nil
}

// ParseCPUs parses a CPU quota such as "1.5" and returns it in thousandths of a
// CPU. A "0" means no limit and returns 0. Any other value must be at least
// 0.001 and at most hostCPUs.
func ParseCPUs(s string, hostCPUs int) (int64, error) {
	raw := strings.TrimSpace(s)
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil || f < 0 || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("%w: invalid CPU quota %q", ErrInvalidConfig, s)
	}
	millis := int64(math.Round(f * 1000))
	if millis == 0 {
		if f > 0 {
			return 0, fmt.Errorf("%w: CPU quota %q is below 0.001", ErrInvalidConfig, s)
		}
		return 0, nil
	}
	if millis > int64(hostCPUs)*1000 {
		return 0, fmt.Errorf("%w: CPU quota %q exceeds the %d CPUs of the host", ErrInvalidConfig, s, hostCPUs)
	}
	return millis, nil
}

// guestCPUs returns the number of CPUs that the guest sees for a CPU quota in
// thousandths. A zero quota means every host CPU. The guest sees whole CPUs,
// rounded up, and at least one.
func guestCPUs(quotaMillis int64, hostCPUs int) int {
	hostCPUs = max(1, hostCPUs)
	if quotaMillis <= 0 {
		return hostCPUs
	}
	return min(hostCPUs, max(1, int((quotaMillis+999)/1000)))
}

// memoryGuard stops the guest when its memory use passes a limit. The Sentry
// keeps guest memory in a memory file, and no host mechanism counts that memory
// on every host OS, so the guard compares the Sentry accounting with the limit.
type memoryGuard struct {
	// limit is the largest allowed use in bytes. It must be above zero.
	limit uint64
	// used returns the current use in bytes.
	used func() uint64
	// interval is the time between two readings.
	interval time.Duration
	// kill stops the guest. The guard calls it once.
	kill func()
}

// run reads the use every interval until ctx ends or the use passes the limit.
// It calls kill and returns true in the second case.
func (g memoryGuard) run(ctx context.Context) bool {
	tick := time.NewTicker(g.interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-tick.C:
			if g.used() > g.limit {
				g.kill()
				return true
			}
		}
	}
}
