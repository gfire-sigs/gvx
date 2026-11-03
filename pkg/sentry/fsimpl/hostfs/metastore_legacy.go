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

package hostfs

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/crc32"
)

// This file reads the two path-keyed forms that earlier releases wrote:
// the JSON document of schema versions 1 and 2, and the journal of version 3,
// whose records are JSON bodies under a guest path. hostfs never writes them
// any more. The loader converts them to the current form at the first flush
// of a session that changes a record.

// journalVersionV3 is the version byte of the path-keyed journal.
const journalVersionV3 = 3

// metaStoreFile is the JSON document of the oldest form.
type metaStoreFile struct {
	Version int                  `json:"version"`
	Entries map[string]POSIXAttr `json:"entries"`
}

const (
	// metaVersion is the schema version of the JSON document. metaVersionV1
	// is the schema before the xattr field. The reader accepts both.
	metaVersion   = 2
	metaVersionV1 = 1

	opSetV3    = 1
	opDeleteV3 = 2
)

// parseLegacyJSON decodes the JSON document of the oldest form.
func parseLegacyJSON(raw []byte) (metaImage, error) {
	var parsed metaStoreFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return metaImage{}, fmt.Errorf("hostfs: parse %s: %w", MetaFileName, err)
	}
	if parsed.Version != metaVersion && parsed.Version != metaVersionV1 {
		return metaImage{}, fmt.Errorf("hostfs: %s has unsupported version %d", MetaFileName, parsed.Version)
	}
	img := metaImage{paths: make(map[string]POSIXAttr, len(parsed.Entries)), legacy: true}
	for k, v := range parsed.Entries {
		if key, ok := legacyPathKey(k); ok {
			img.paths[key] = v
		}
	}
	return img, nil
}

// legacyPathKey returns the normalized guest path for the key k of an older
// release. It reports false for a key that hostfs does not honor: one that
// escapes the workspace, names the root, or names a hidden metadata file.
func legacyPathKey(k string) (string, bool) {
	clean, err := CleanRelativePath(k)
	if err != nil || clean == "." || isReservedPath(clean) {
		return "", false
	}
	return clean, true
}

// parseJournalV3 replays the frames of a version 3 journal. The header is
// valid already.
func parseJournalV3(raw []byte) (metaImage, error) {
	img := metaImage{paths: make(map[string]POSIXAttr), legacy: true, size: int64(journalHeader)}
	off := journalHeader
	for off < len(raw) {
		payload, ok := nextFrame(raw[off:])
		if !ok {
			img.torn = true
			break
		}
		n, err := applyFrameV3(payload, img.paths)
		if err != nil {
			return metaImage{}, err
		}
		img.ops += n
		off += frameHeader + len(payload)
		img.size = int64(off)
	}
	return img, nil
}

// applyFrameV3 applies the operations of one version 3 frame to entries. It
// returns the number of operations.
func applyFrameV3(payload []byte, entries map[string]POSIXAttr) (int, error) {
	ops := 0
	for len(payload) > 0 {
		op := payload[0]
		payload = payload[1:]
		key, rest, ok := cutBytes(payload)
		if !ok || (op != opSetV3 && op != opDeleteV3) {
			return ops, errMetaCorrupt
		}
		payload = rest
		k := string(key)
		switch op {
		case opSetV3:
			body, rest, ok := cutBytes(payload)
			if !ok {
				return ops, errMetaCorrupt
			}
			payload = rest
			var attr POSIXAttr
			if err := json.Unmarshal(body, &attr); err != nil {
				return ops, fmt.Errorf("%w: %w", errMetaCorrupt, err)
			}
			if key, ok := legacyPathKey(k); ok {
				entries[key] = attr
			}
		case opDeleteV3:
			if key, ok := legacyPathKey(k); ok {
				delete(entries, key)
			}
		}
		ops++
	}
	return ops, nil
}

// cutBytes splits a length-prefixed byte string off the front of b.
func cutBytes(b []byte) (field, rest []byte, ok bool) {
	n, w := binary.Uvarint(b)
	if w <= 0 || n > uint64(len(b)-w) {
		return nil, nil, false
	}
	return b[w : w+int(n)], b[w+int(n):], true
}

// nextFrame returns the payload of the frame at the start of b. It reports
// false when the frame is incomplete or its checksum fails.
func nextFrame(b []byte) ([]byte, bool) {
	if len(b) < frameHeader {
		return nil, false
	}
	n := binary.LittleEndian.Uint32(b)
	sum := binary.LittleEndian.Uint32(b[4:])
	if n > maxFrameBytes || int(n) > len(b)-frameHeader {
		return nil, false
	}
	payload := b[frameHeader : frameHeader+int(n)]
	if crc32.Checksum(payload, castagnoli) != sum {
		return nil, false
	}
	return payload, true
}
