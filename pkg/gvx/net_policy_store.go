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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"z.gfire.dev/gvx/pkg/netbackend"
)

const (
	policyStoreVersion  = 1
	policyStoreIDBytes  = 16
	policyStorePageSize = 16 << 10
	policyStoreSlotSize = 1 << 20
	policyStoreSlotBase = 3 * policyStorePageSize
	policyStoreFileSize = policyStoreSlotBase + 2*policyStoreSlotSize

	policyStoreMagic       = "GVXNPS01"
	policyStoreMarkerSize  = len(policyStoreMagic) + 8 + 4 + sha256.Size
	policyStoreGeneration  = len(policyStoreMagic)
	policyStoreLength      = policyStoreGeneration + 8
	policyStoreDigest      = policyStoreLength + 4
	policyStoreMarkerFirst = policyStorePageSize
	policyStoreMarkerLast  = 2 * policyStorePageSize
)

var (
	errPolicyStoreUncertain = errors.New("net policy commit outcome is uncertain")
	errPolicyStoreCorrupt   = errors.New("net policy store is corrupt")
	errPolicyStoreUnsafe    = errors.New("net policy store path is not private")
)

// The SDK serializes access to the store, including Close. Only markers
// determine authority. Stage never changes either marker. Commit replaces both
// copies on separate pages; recovery refuses disagreement rather than rolling
// back to one readable copy.
type netPolicyStore struct {
	file       *os.File
	id         string
	generation uint64
	config     netbackend.PolicyConfig
	staged     stagedPolicyRecord
	uncertain  bool
}

type policyStoreRecord struct {
	Version    int                     `json:"version"`
	ID         string                  `json:"id"`
	Generation uint64                  `json:"generation"`
	Policy     netbackend.PolicyConfig `json:"policy"`
}

type stagedPolicyRecord struct {
	config netbackend.PolicyConfig
	marker [policyStoreMarkerSize]byte
	ready  bool
}

func openNetPolicyStore(path string, seed *netbackend.PolicyConfig) (*netPolicyStore, error) {
	path, err := absolutePolicyStorePath(path)
	if err != nil {
		return nil, err
	}
	s := &netPolicyStore{}
	var initialize func(*os.File) error
	if seed != nil {
		var id [policyStoreIDBytes]byte
		rand.Read(id[:])
		s.id = hex.EncodeToString(id[:])
		config := *seed
		data, err := encodePolicyStoreRecord(s.id, 1, config)
		if err != nil {
			return nil, err
		}
		initialize = func(f *os.File) error {
			s.file = f
			if err := f.Truncate(policyStoreFileSize); err != nil {
				return fmt.Errorf("size policy store: %w", err)
			}
			if err := s.stageRecord(1, config, data); err != nil {
				return err
			}
			return s.Commit()
		}
	}
	f, err := openPolicyStoreFile(path, initialize)
	if err != nil {
		return nil, fmt.Errorf("open policy store %q: %w", path, err)
	}
	s.file = f
	if seed == nil {
		if err := s.recover(); err != nil {
			return nil, errors.Join(err, s.Close())
		}
	}
	return s, nil
}

func absolutePolicyStorePath(path string) (string, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 || os.IsPathSeparator(path[len(path)-1]) {
		return "", fmt.Errorf("%w: expected a file path", errPolicyStoreUnsafe)
	}
	// Do not clean away a path component that could have been a link.
	relative := path
	if volume := filepath.VolumeName(path); volume != "" {
		if !filepath.IsAbs(path) {
			return "", fmt.Errorf("%w: drive-relative path", errPolicyStoreUnsafe)
		}
		relative = path[len(volume):]
	}
	for name := range strings.FieldsFuncSeq(relative, func(r rune) bool {
		return r < 128 && os.IsPathSeparator(byte(r))
	}) {
		if name == ".." {
			return "", fmt.Errorf("%w: parent traversal", errPolicyStoreUnsafe)
		}
		if filepath.Separator == '\\' && name != "." && strings.TrimRight(name, " .") != name {
			return "", fmt.Errorf("%w: ambiguous Windows path component", errPolicyStoreUnsafe)
		}
	}
	if filepath.Base(path) == "." {
		return "", fmt.Errorf("%w: expected a file name", errPolicyStoreUnsafe)
	}
	return filepath.Abs(path)
}

func policyStoreSlot(generation uint64) int64 {
	return policyStoreSlotBase + int64((generation-1)%2)*policyStoreSlotSize
}

// Stage writes only the inactive slot. Its caller must compile the policy
// before staging it. A failed stage cannot authorize a new generation.
func (s *netPolicyStore) Stage(config netbackend.PolicyConfig) error {
	if s.uncertain {
		return errPolicyStoreUncertain
	}
	if s.file == nil {
		return os.ErrClosed
	}
	s.staged = stagedPolicyRecord{}
	if s.generation == math.MaxUint64 {
		return fmt.Errorf("net policy store generation exhausted")
	}
	generation := s.generation + 1
	data, err := encodePolicyStoreRecord(s.id, generation, config)
	if err != nil {
		return err
	}
	return s.stageRecord(generation, config, data)
}

func (s *netPolicyStore) stageRecord(generation uint64, config netbackend.PolicyConfig, data []byte) error {
	if _, err := s.file.WriteAt(data, policyStoreSlot(generation)); err != nil {
		return fmt.Errorf("write staged policy: %w", err)
	}
	if err := syncPolicyStoreFile(s.file); err != nil {
		return fmt.Errorf("sync staged policy: %w", err)
	}
	pending := &s.staged
	pending.config = config
	copy(pending.marker[:], policyStoreMagic)
	binary.BigEndian.PutUint64(pending.marker[policyStoreGeneration:], generation)
	binary.BigEndian.PutUint32(pending.marker[policyStoreLength:], uint32(len(data)))
	digest := sha256.Sum256(data)
	copy(pending.marker[policyStoreDigest:], digest[:])
	pending.ready = true
	return nil
}

// Commit does not advance the in-memory generation until the markers sync.
// A write or sync error cannot prove what reached disk, so only reopening
// the store can establish authority again.
func (s *netPolicyStore) Commit() error {
	if s.uncertain {
		return errPolicyStoreUncertain
	}
	if s.file == nil {
		return os.ErrClosed
	}
	if !s.staged.ready {
		return fmt.Errorf("no staged net policy")
	}
	pending := &s.staged
	defer func() { s.staged = stagedPolicyRecord{} }()
	for _, offset := range [...]int64{policyStoreMarkerFirst, policyStoreMarkerLast} {
		if _, err := s.file.WriteAt(pending.marker[:], offset); err != nil {
			s.uncertain = true
			return fmt.Errorf("%w: write marker: %w", errPolicyStoreUncertain, err)
		}
	}
	if err := syncPolicyStoreFile(s.file); err != nil {
		s.uncertain = true
		return fmt.Errorf("%w: sync markers: %w", errPolicyStoreUncertain, err)
	}
	s.generation = binary.BigEndian.Uint64(pending.marker[policyStoreGeneration:])
	s.config = pending.config
	return nil
}

func (s *netPolicyStore) recover() error {
	info, err := s.file.Stat()
	if err != nil {
		return fmt.Errorf("stat policy store: %w", err)
	}
	if info.Size() != policyStoreFileSize {
		return fmt.Errorf("%w: invalid file size", errPolicyStoreCorrupt)
	}
	var first, last [policyStoreMarkerSize]byte
	if _, err := s.file.ReadAt(first[:], policyStoreMarkerFirst); err != nil {
		return fmt.Errorf("read first policy marker: %w", err)
	}
	if _, err := s.file.ReadAt(last[:], policyStoreMarkerLast); err != nil {
		return fmt.Errorf("read second policy marker: %w", err)
	}
	if first != last || string(first[:policyStoreGeneration]) != policyStoreMagic {
		return fmt.Errorf("%w: invalid or conflicting commit markers", errPolicyStoreCorrupt)
	}
	generation := binary.BigEndian.Uint64(first[policyStoreGeneration:])
	length := binary.BigEndian.Uint32(first[policyStoreLength:])
	if generation == 0 || length == 0 || length > policyStoreSlotSize {
		return fmt.Errorf("%w: invalid commit marker bounds", errPolicyStoreCorrupt)
	}
	data := make([]byte, length)
	if _, err := s.file.ReadAt(data, policyStoreSlot(generation)); err != nil {
		return fmt.Errorf("read committed policy: %w", err)
	}
	if digest := sha256.Sum256(data); !bytes.Equal(digest[:], first[policyStoreDigest:]) {
		return fmt.Errorf("%w: committed policy digest mismatch", errPolicyStoreCorrupt)
	}
	var record policyStoreRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return fmt.Errorf("%w: invalid policy record JSON", errPolicyStoreCorrupt)
	}
	var id [policyStoreIDBytes]byte
	if record.Version != policyStoreVersion || record.Generation != generation || len(record.ID) != hex.EncodedLen(len(id)) {
		return fmt.Errorf("%w: invalid policy identity", errPolicyStoreCorrupt)
	}
	if _, err := hex.Decode(id[:], []byte(record.ID)); err != nil || strings.ToLower(record.ID) != record.ID {
		return fmt.Errorf("%w: invalid policy store ID", errPolicyStoreCorrupt)
	}
	// A canonical round trip rejects missing, duplicate and unknown fields,
	// including fields that a permissive JSON decoder would ignore.
	canonical, err := encodePolicyStoreRecord(record.ID, generation, record.Policy)
	if err != nil || !bytes.Equal(data, canonical) {
		return fmt.Errorf("%w: invalid policy record encoding", errPolicyStoreCorrupt)
	}
	s.id, s.generation, s.config = record.ID, generation, record.Policy
	return nil
}

func encodePolicyStoreRecord(id string, generation uint64, config netbackend.PolicyConfig) ([]byte, error) {
	if len(config.RulesV4) > netbackend.MaxPolicyRules || len(config.RulesV6) > netbackend.MaxPolicyRules {
		return nil, fmt.Errorf("net policy rules exceed the store size limit")
	}
	if !utf8.ValidString(config.RulesV4) || !utf8.ValidString(config.RulesV6) {
		return nil, fmt.Errorf("net policy rules must use UTF-8")
	}
	data, err := json.Marshal(policyStoreRecord{Version: policyStoreVersion, ID: id, Generation: generation, Policy: config})
	if err != nil {
		return nil, fmt.Errorf("encode policy record: %w", err)
	}
	if len(data) > policyStoreSlotSize {
		return nil, fmt.Errorf("net policy record exceeds slot size")
	}
	return data, nil
}

func (s *netPolicyStore) Close() error {
	if s.file == nil {
		return nil
	}
	f := s.file
	s.file, s.staged = nil, stagedPolicyRecord{}
	// Closing the unshared descriptor also releases the exclusive lock.
	return f.Close()
}
