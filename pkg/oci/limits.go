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

package oci

import (
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"
)

// ErrLimitExceeded marks every error that reports an exceeded size budget.
var ErrLimitExceeded = errors.New("oci: size limit exceeded")

// LimitError reports which budget an input exceeded.
type LimitError struct {
	// What names the budgeted quantity.
	What string
	// Limit is the budget in bytes, or in entries for entry counts.
	Limit int64
}

// Error implements error.
func (e *LimitError) Error() string {
	return fmt.Sprintf("oci: %s exceeds the limit of %d", e.What, e.Limit)
}

// Is reports whether target is ErrLimitExceeded.
func (e *LimitError) Is(target error) bool {
	return target == ErrLimitExceeded
}

// Limits bounds the memory, disk, and network volume that untrusted image
// content can consume. Every field must be positive.
type Limits struct {
	// MaxJSONBytes bounds each index, manifest, and config body.
	MaxJSONBytes int64
	// MaxBlobBytes bounds one compressed layer blob.
	MaxBlobBytes int64
	// MaxLayerBytes bounds the decompressed tar stream of one layer.
	MaxLayerBytes int64
	// MaxImageBytes bounds the decompressed tar streams of all layers of one image.
	MaxImageBytes int64
	// MaxEntryBytes bounds the content of one regular file.
	MaxEntryBytes int64
	// MaxEntries bounds the number of tar entries of one layer.
	MaxEntries int64
	// MaxArchiveEntries bounds the number of members of an image archive.
	MaxArchiveEntries int64
	// MaxZstdWindowBytes bounds the zstd window, and so the decoder memory.
	MaxZstdWindowBytes uint64
	// RegistryIdleTimeout is how long a registry request may go without data
	// before it fails. Zero selects the default of the registry of tunables.
	RegistryIdleTimeout time.Duration
}

// DefaultLimits returns the limits that production pulls use.
func DefaultLimits() Limits {
	const (
		mib = int64(1) << 20
		gib = int64(1) << 30
	)
	return Limits{
		MaxJSONBytes:        8 * mib,
		MaxBlobBytes:        32 * gib,
		MaxLayerBytes:       64 * gib,
		MaxImageBytes:       128 * gib,
		MaxEntryBytes:       32 * gib,
		MaxEntries:          2_000_000,
		MaxArchiveEntries:   1_000_000,
		MaxZstdWindowBytes:  128 * uint64(mib),
		RegistryIdleTimeout: defaultIdleTimeout,
	}
}

func (l Limits) validate() error {
	for name, v := range map[string]int64{
		"MaxJSONBytes":      l.MaxJSONBytes,
		"MaxBlobBytes":      l.MaxBlobBytes,
		"MaxLayerBytes":     l.MaxLayerBytes,
		"MaxImageBytes":     l.MaxImageBytes,
		"MaxEntryBytes":     l.MaxEntryBytes,
		"MaxEntries":        l.MaxEntries,
		"MaxArchiveEntries": l.MaxArchiveEntries,
	} {
		if v <= 0 {
			return fmt.Errorf("oci: limit %s must be positive, got %d", name, v)
		}
	}
	if l.MaxZstdWindowBytes == 0 {
		return errors.New("oci: limit MaxZstdWindowBytes must be positive")
	}
	if l.RegistryIdleTimeout < 0 {
		return fmt.Errorf("oci: limit RegistryIdleTimeout must not be negative, got %s", l.RegistryIdleTimeout)
	}
	return nil
}

// byteBudget is a shared byte counter that several readers draw from.
type byteBudget struct {
	what      string
	limit     int64
	remaining atomic.Int64
}

func newByteBudget(what string, limit int64) *byteBudget {
	b := &byteBudget{what: what, limit: limit}
	b.remaining.Store(limit)
	return b
}

// take draws n bytes and reports a LimitError when the budget runs out.
func (b *byteBudget) take(n int64) error {
	if b.remaining.Add(-n) < 0 {
		return &LimitError{What: b.what, Limit: b.limit}
	}
	return nil
}

// boundedReader reads at most limit bytes from r. Unlike io.LimitedReader, it
// returns a LimitError instead of a silent EOF when r holds more data. It also
// draws every byte from an optional shared budget.
type boundedReader struct {
	r      io.Reader
	what   string
	limit  int64
	n      int64
	shared *byteBudget
}

func newBoundedReader(r io.Reader, what string, limit int64, shared *byteBudget) *boundedReader {
	return &boundedReader{r: r, what: what, limit: limit, shared: shared}
}

// Read implements io.Reader.
func (b *boundedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.n > b.limit {
		return 0, &LimitError{What: b.what, Limit: b.limit}
	}
	// Request one byte beyond the limit so that an overrun is observable.
	if allowed := b.limit - b.n + 1; int64(len(p)) > allowed {
		p = p[:allowed]
	}
	n, err := b.r.Read(p)
	b.n += int64(n)
	if over := b.n - b.limit; over > 0 {
		return n - int(over), &LimitError{What: b.what, Limit: b.limit}
	}
	if n > 0 && b.shared != nil {
		if takeErr := b.shared.take(int64(n)); takeErr != nil {
			return 0, takeErr
		}
	}
	return n, err
}

// readAllBounded reads r to EOF and fails if it holds more than limit bytes.
func readAllBounded(r io.Reader, what string, limit int64) ([]byte, error) {
	return io.ReadAll(newBoundedReader(r, what, limit, nil))
}
