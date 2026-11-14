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
	"os"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/oci"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvf"
	"z.gfire.dev/gvx/pkg/sentry/platform/whpx"
)

// SystemInfo summarizes the host environment, execution backends, and local
// gvx storage directories.
type SystemInfo struct {
	OS                string            `json:"OS"`
	Architecture      string            `json:"Architecture"`
	GoVersion         string            `json:"GoVersion"`
	NumCPU            int               `json:"NumCPU"`
	PageSize          int               `json:"PageSize"`
	DefaultBackend    string            `json:"DefaultBackend"`
	AvailableBackends []string          `json:"AvailableBackends"`
	BackendWarnings   []string          `json:"BackendWarnings,omitempty"`
	HostLockdown      string            `json:"HostLockdown"`
	LayerCacheDir     string            `json:"LayerCacheDir"`
	VolumeDir         string            `json:"VolumeDir"`
	Images            int               `json:"Images"`
	Volumes           int               `json:"Volumes"`
	BackendDetails    map[string]string `json:"BackendDetails,omitempty"`
}

// ProbeSystemInfo inspects available execution backends, lockdown profile, and
// local image and volume store statistics without applying host lockdown.
func ProbeSystemInfo(cacheDir string, tuned tuning.Values) (SystemInfo, error) {
	cacheDir = strings.TrimSpace(cacheDir)
	resolvedCacheDir := cacheDir
	if resolvedCacheDir == "" {
		var err error
		resolvedCacheDir, err = oci.DefaultCacheDir()
		if err != nil {
			return SystemInfo{}, err
		}
	}
	volDir, err := VolumeDir(cacheDir)
	if err != nil {
		return SystemInfo{}, err
	}

	info := SystemInfo{
		OS:                runtime.GOOS,
		Architecture:      runtime.GOARCH,
		GoVersion:         runtime.Version(),
		NumCPU:            runtime.NumCPU(),
		PageSize:          os.Getpagesize(),
		HostLockdown:      hostLockdownProfileName(runtime.GOOS),
		LayerCacheDir:     resolvedCacheDir,
		VolumeDir:         volDir,
		AvailableBackends: []string{},
	}

	probeExecutionBackends(&info)

	if st, statErr := os.Stat(resolvedCacheDir); statErr == nil && st.IsDir() {
		if cache, openErr := NewLayerCacheWithTuning(resolvedCacheDir, tuned); openErr == nil {
			if du, duErr := cache.DiskUsage(); duErr == nil {
				info.Images = du.TotalImages
			}
		}
	}
	if vdu, vErr := ComputeVolumeDiskUsage(cacheDir); vErr == nil {
		info.Volumes = vdu.Total
	}
	return info, nil
}

func hostLockdownProfileName(goos string) string {
	switch goos {
	case "windows":
		return "restricted-token+job-object+file-broker"
	case "darwin":
		return "seatbelt"
	case "linux", "android":
		return "landlock+seccomp"
	default:
		return "none"
	}
}

func probeExecutionBackends(info *SystemInfo) {
	info.BackendDetails = make(map[string]string)
	switch runtime.GOOS {
	case "windows":
		if p, err := whpx.NewWithOptions(whpx.Options{}); err == nil {
			_ = p.Close()
			info.AvailableBackends = append(info.AvailableBackends, whpx.PlatformName)
			info.DefaultBackend = whpx.PlatformName
			info.BackendDetails[whpx.PlatformName] = "available"
		} else {
			info.BackendDetails[whpx.PlatformName] = err.Error()
			if hint := platformFailureHint("windows", err); hint != "" {
				info.BackendWarnings = append(info.BackendWarnings, hint)
			}
		}
		if _, err := probeStub(); err == nil {
			info.AvailableBackends = append(info.AvailableBackends, string(PlatformSystrap))
			info.BackendDetails[string(PlatformSystrap)] = "available (usermode-patch)"
		} else {
			info.BackendDetails[string(PlatformSystrap)] = err.Error()
		}

	case "darwin":
		if p, err := hvf.New(); err == nil {
			_ = p.Close()
			info.AvailableBackends = append(info.AvailableBackends, hvf.PlatformName)
			info.DefaultBackend = hvf.PlatformName
			info.BackendDetails[hvf.PlatformName] = "available"
		} else {
			info.BackendDetails[hvf.PlatformName] = err.Error()
			if hint := platformFailureHint("darwin", err); hint != "" {
				info.BackendWarnings = append(info.BackendWarnings, hint)
			}
		}

	default:
		if _, err := probeStub(); err == nil {
			info.AvailableBackends = append(info.AvailableBackends, string(PlatformSystrap))
			info.DefaultBackend = string(PlatformSystrap)
			info.BackendDetails[string(PlatformSystrap)] = "available"
		} else {
			info.BackendDetails[string(PlatformSystrap)] = err.Error()
		}
	}
	if info.DefaultBackend == "" {
		info.DefaultBackend = "unavailable"
	}
	if len(info.BackendDetails) == 0 {
		info.BackendDetails = nil
	}
}
