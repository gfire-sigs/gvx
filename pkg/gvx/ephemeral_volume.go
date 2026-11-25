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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/oci"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
)

const (
	ephemeralVolumesDirName = "ephemeral-volumes"
	ephemeralStagingPrefix  = "ephemeral-"
	ephemeralStagingSuffix  = ".ext4.staging"
	ephemeralLockFileName   = ".lock"
)

// forceEphemeralStagingFallback forces Linux to exercise the POSIX
// create-and-unlink staging path in tests.
var forceEphemeralStagingFallback atomic.Bool

// ephemeralVolumeRoot returns the directory holding private ephemeral ext4lite
// scratch images under the configured cache base.
func (c Config) ephemeralVolumeRoot() (string, error) {
	if c.OCICacheDir != "" {
		return filepath.Join(c.OCICacheDir, ephemeralVolumesDirName), nil
	}
	layers, err := oci.DefaultCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(layers), ephemeralVolumesDirName), nil
}

func randomEphemeralToken() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("gvx: generate ephemeral volume name: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

func isEphemeralStagingName(name string) bool {
	return len(name) > len(ephemeralStagingPrefix)+len(ephemeralStagingSuffix) &&
		name[:len(ephemeralStagingPrefix)] == ephemeralStagingPrefix &&
		name[len(name)-len(ephemeralStagingSuffix):] == ephemeralStagingSuffix
}

func (s *Sandbox) openEphemeralVolume(m Mount) (*ext4lite.Volume, error) {
	dir, err := s.cfg.ephemeralVolumeRoot()
	if err != nil {
		return nil, fmt.Errorf("gvx: locate ephemeral volume directory: %w", err)
	}
	f, err := openEphemeralVolumeFile(dir)
	if err != nil {
		return nil, fmt.Errorf("gvx: create ephemeral volume for %s: %w", m.GuestPath, err)
	}
	vol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{
		MaxBytes: m.SizeBytes,
	})
	if errors.Is(err, ext4lite.ErrInvalidVolumeSize) || errors.Is(err, ext4lite.ErrVolumeExceedsMaxBytes) {
		return nil, fmt.Errorf("gvx: format ephemeral volume for %s: %w: %w", m.GuestPath, ErrInvalidConfig, err)
	}
	if err != nil {
		return nil, fmt.Errorf("gvx: format ephemeral volume for %s: %w", m.GuestPath, err)
	}
	return vol, nil
}
