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

package pgalloc

import (
	"bytes"
	"context"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"
)

// saveMultiChunkStream returns the stream that SaveTo writes for the real
// two-chunk fixture.
func saveMultiChunkStream(t *testing.T) []byte {
	t.Helper()
	fx := buildMultiChunkFixture(t)
	var buf bytes.Buffer
	if err := fx.mf.SaveTo(context.Background(), &buf, &SaveOpts{ExitAfterSaving: true}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	fx.releaseAndDestroy(t, fx.mf)
	return buf.Bytes()
}

func loadStream(t *testing.T, stream []byte, opts MemoryFileOpts) error {
	t.Helper()
	mf := newTestMemoryFile(t, opts)
	err := mf.LoadFrom(context.Background(), bytes.NewReader(stream), &LoadOpts{})
	if err == nil {
		awaitDestroy(t, mf)
	}
	return err
}

func TestLoadFromRejectsOversizedMetadataLength(t *testing.T) {
	stream := saveMultiChunkStream(t)
	for _, length := range []uint64{maxLoadMetadataBytes + 1, 1 << 62, ^uint64(0)} {
		bad := bytes.Clone(stream)
		binary.LittleEndian.PutUint64(bad, length)
		err := loadStream(t, bad, MemoryFileOpts{ExpectHugepages: true})
		if err == nil || !strings.Contains(err.Error(), "exceeds the limit") {
			t.Fatalf("LoadFrom with metadata length %d = %v, want a limit error", length, err)
		}
	}
}

func TestLoadFromBoundsAllocationByStreamSize(t *testing.T) {
	stream := saveMultiChunkStream(t)
	const claimed = maxLoadMetadataBytes - 1
	bad := bytes.Clone(stream[:64])
	binary.LittleEndian.PutUint64(bad, claimed)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	err := loadStream(t, bad, MemoryFileOpts{ExpectHugepages: true})
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("LoadFrom with a truncated metadata stream succeeded, want an error")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > claimed/4 {
		t.Fatalf("LoadFrom allocated %d bytes for a 56 byte stream that claims %d bytes", grew, uint64(claimed))
	}
}

func TestLoadFromEnforcesMaxLoadBytes(t *testing.T) {
	stream := saveMultiChunkStream(t)
	err := loadStream(t, stream, MemoryFileOpts{ExpectHugepages: true, MaxLoadBytes: chunkSize})
	if err == nil || !strings.Contains(err.Error(), "above the limit") {
		t.Fatalf("LoadFrom with MaxLoadBytes = one chunk = %v, want a limit error", err)
	}
	if err := loadStream(t, stream, MemoryFileOpts{ExpectHugepages: true, MaxLoadBytes: 2 * chunkSize}); err != nil {
		t.Fatalf("LoadFrom with MaxLoadBytes = two chunks: %v", err)
	}
}

// metadataStream hand-encodes a MemoryFileMetadataProto with nChunks empty
// chunks and the given accounting ranges, behind the 8-byte length header.
// Field numbers come from pgalloc.proto: version 1, chunks 2, mem_acct 3, and
// start 1 and end 2 inside a range.
func metadataStream(nChunks int, memAcct [][2]uint64) []byte {
	field := func(dst []byte, num uint64, msg []byte) []byte {
		dst = binary.AppendUvarint(dst, num<<3|2)
		dst = binary.AppendUvarint(dst, uint64(len(msg)))
		return append(dst, msg...)
	}
	meta := []byte{1<<3 | 0, 1} // version = 1
	for range nChunks {
		meta = field(meta, 2, nil)
	}
	for _, r := range memAcct {
		var rng []byte
		rng = binary.AppendUvarint(rng, 1<<3|0)
		rng = binary.AppendUvarint(rng, r[0])
		rng = binary.AppendUvarint(rng, 2<<3|0)
		rng = binary.AppendUvarint(rng, r[1])
		meta = field(meta, 3, rng)
	}
	return append(binary.LittleEndian.AppendUint64(nil, uint64(len(meta))), meta...)
}

func TestLoadFromRejectsMalformedRanges(t *testing.T) {
	cases := []struct {
		name   string
		stream []byte
		want   string
	}{
		{"range beyond file", metadataStream(1, [][2]uint64{{0, 2 * chunkSize}}), "exceeds the backing file size"},
		{"inverted range", metadataStream(1, [][2]uint64{{8192, 4096}}), "empty or inverted"},
		{"overlapping ranges", metadataStream(1, [][2]uint64{{0, 8192}, {4096, 12288}}), "overlaps or precedes"},
		{"too many chunks", metadataStream(maxLoadChunks+1, nil), "chunks exceed the limit"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := loadStream(t, tc.stream, MemoryFileOpts{ExpectHugepages: true})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadFrom = %v, want an error containing %q", err, tc.want)
			}
		})
	}
}

func TestLoadFromAcceptsWellFormedHandEncodedMetadata(t *testing.T) {
	// The encoder must produce what the real decoder accepts, or the cases
	// above prove nothing.
	if err := loadStream(t, metadataStream(1, [][2]uint64{{0, 8192}, {8192, 12288}}), MemoryFileOpts{ExpectHugepages: true}); err != nil {
		t.Fatalf("LoadFrom of valid hand-encoded metadata: %v", err)
	}
}
