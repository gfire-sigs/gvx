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

package gpurender

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Locate returns the absolute path of the renderer executable. explicit
// (Config.GPU.RendererPath) wins; then the EnvRenderer variable; then
// <dir of os.Executable>/gvx-gpu-renderer/bin/gvx-gpu-renderer; then
// <dir>/../libexec/gvx-gpu-renderer/bin/gvx-gpu-renderer. When explicit or
// the variable is set, Locate searches only that path. The error wraps
// ErrNotFound and names every searched path.
func Locate(explicit string) (string, error) {
	exe, err := os.Executable()
	if err == nil {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
	}
	found, _, err := locate(explicit, os.Getenv(EnvRenderer), exe, isRegularExecutable)
	return found, err
}

// locate is Locate with its inputs. isRenderer reports whether a path is a
// regular file with an execute bit.
func locate(explicit, envValue, exePath string, isRenderer func(string) bool) (string, []string, error) {
	if explicit != "" {
		return locateSingle(explicit, isRenderer)
	}
	if envValue != "" {
		return locateSingle(envValue, isRenderer)
	}
	if exePath == "" {
		return "", nil, fmt.Errorf("%w: could not resolve executable directory", ErrNotFound)
	}
	dir := filepath.Dir(exePath)
	candidates := []string{
		filepath.Join(dir, "gvx-gpu-renderer", "bin", "gvx-gpu-renderer"),
		filepath.Join(dir, "..", "libexec", "gvx-gpu-renderer", "bin", "gvx-gpu-renderer"),
	}
	searched := make([]string, 0, len(candidates))
	for _, cand := range candidates {
		searched = append(searched, cand)
		if isRenderer(cand) {
			return cand, searched, nil
		}
	}
	return "", searched, fmt.Errorf("%w: searched %s", ErrNotFound, strings.Join(searched, ", "))
}

func locateSingle(raw string, isRenderer func(string) bool) (string, []string, error) {
	target := raw
	if !filepath.IsAbs(target) {
		abs, err := filepath.Abs(target)
		if err != nil {
			searched := []string{target}
			return "", searched, fmt.Errorf("%w: resolve %s: %v", ErrNotFound, target, err)
		}
		target = abs
	}
	searched := []string{target}
	if isRenderer(target) {
		return target, searched, nil
	}
	return "", searched, fmt.Errorf("%w: searched %s", ErrNotFound, target)
}

func isRegularExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	// Windows file modes do not carry POSIX execute bits.
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode().Perm()&0o111 != 0
}
