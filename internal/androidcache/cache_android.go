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

// Package androidcache binds the installed app's cache directory for rungv.
package androidcache

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// LaunchFlag prefixes the descriptor and path supplied by the app launcher.
const LaunchFlag = "--android-cache-fd"

const (
	userOffset     = 100000
	firstAppID     = 10000
	lastAppID      = 19999
	cacheGIDOffset = 10000
)

// AppUID reports whether the effective UID is in an Android application range.
func AppUID() bool {
	appID := os.Geteuid() % userOffset
	return appID >= firstAppID && appID <= lastAppID
}

var errCacheIdentity = errors.New("cache directory does not match the current Android app")

// Verify binds fd to the cache path from Context.getCacheDir and the working
// directory from Context.getFilesDir. It does not enumerate system ancestors.
func Verify(fd int, path string) error {
	if !AppUID() || fd < 3 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "cache" {
		return errCacheIdentity
	}
	uid := uint32(os.Geteuid())
	var cache unix.Stat_t
	if err := unix.Fstat(fd, &cache); err != nil {
		return fmt.Errorf("stat inherited cache directory: %w", err)
	}
	// Android installd sets the cache directory's group to the app cache GID.
	cacheGroup := cache.Gid == uid || cache.Gid == uid+cacheGIDOffset
	if cache.Mode&unix.S_IFMT != unix.S_IFDIR || cache.Uid != uid || cache.Mode&0o002 != 0 ||
		(cache.Mode&0o020 != 0 && !cacheGroup) {
		return errCacheIdentity
	}
	var app unix.Stat_t
	if err := unix.Fstatat(unix.AT_FDCWD, "..", &app, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return fmt.Errorf("stat app directory: %w", err)
	}
	if app.Uid != uid || app.Mode&0o022 != 0 {
		return errCacheIdentity
	}
	for _, name := range [...]string{path, "../cache"} {
		var actual unix.Stat_t
		if err := unix.Fstatat(unix.AT_FDCWD, name, &actual, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return fmt.Errorf("verify cache directory %q: %w", name, err)
		}
		if actual.Dev != cache.Dev || actual.Ino != cache.Ino || actual.Uid != uid {
			return errCacheIdentity
		}
	}
	return nil
}
