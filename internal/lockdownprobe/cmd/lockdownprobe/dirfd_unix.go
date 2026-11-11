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

//go:build !windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"z.gfire.dev/gvx/internal/lockdownprobe"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

type dirfdProbe struct {
	rootFD  int
	wsFD    int
	relRoot string
	relWS   string
}

func openDirfdProbe(workspace, outsideFile string) *dirfdProbe {
	p := &dirfdProbe{rootFD: -1, wsFD: -1}
	var realOut string
	if outsideFile != "" {
		if resolved, err := filepath.EvalSymlinks(outsideFile); err == nil {
			realOut = resolved
		} else if abs, absErr := filepath.Abs(outsideFile); absErr == nil {
			realOut = abs
		}
	}
	if realOut != "" {
		if fd, err := unix.Open("/", rootDirOpenFlags, 0); err == nil {
			p.rootFD = fd
			p.relRoot = strings.TrimPrefix(realOut, "/")
		}
	}
	if workspace != "" {
		if realWS, err := filepath.EvalSymlinks(workspace); err == nil {
			if fd, openErr := unix.Open(realWS, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); openErr == nil {
				p.wsFD = fd
				if realOut != "" {
					if rel, relErr := filepath.Rel(realWS, realOut); relErr == nil {
						p.relWS = rel
					}
				}
			}
		}
	}
	return p
}

func (p *dirfdProbe) close() {
	if p.rootFD >= 0 {
		_ = unix.Close(p.rootFD)
		p.rootFD = -1
	}
	if p.wsFD >= 0 {
		_ = unix.Close(p.wsFD)
		p.wsFD = -1
	}
}

func (p *dirfdProbe) run(rep *lockdownprobe.Report) {
	if p.rootFD < 0 && p.wsFD < 0 {
		return
	}
	rep.DirfdProbed = true
	if p.rootFD >= 0 && p.relRoot != "" {
		fd, err := unix.Openat(p.rootFD, p.relRoot, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			rep.RootDirfdReadErr = err.Error()
		} else {
			_ = unix.Close(fd)
		}
	}
	if p.wsFD >= 0 {
		if p.relWS != "" {
			fd, err := unix.Openat(p.wsFD, p.relWS, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				rep.WorkspaceEscapeErr = err.Error()
			} else {
				_ = unix.Close(fd)
			}
		}
		if err := probeWorkspaceReadWrite(p.wsFD); err != nil {
			rep.WorkspaceRWProbeErr = err.Error()
		}
	}
}

func probeWorkspaceReadWrite(wsFD int) error {
	const name = ".gvx_lockdown_rw_probe"
	const payload = "ws-rw-ok"
	fd, err := unix.Openat(wsFD, name, unix.O_CREAT|unix.O_EXCL|unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return fmt.Errorf("create inside workspace: %w", err)
	}
	_, writeErr := unix.Write(fd, []byte(payload))
	buf := make([]byte, len(payload))
	n, readErr := unix.Pread(fd, buf, 0)
	closeErr := unix.Close(fd)
	unlinkErr := unix.Unlinkat(wsFD, name, 0)
	if writeErr != nil {
		return fmt.Errorf("write inside workspace: %w", writeErr)
	}
	if readErr != nil || string(buf[:n]) != payload {
		return fmt.Errorf("read inside workspace = (%q, %v)", string(buf[:n]), readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close workspace probe file: %w", closeErr)
	}
	if unlinkErr != nil {
		return fmt.Errorf("unlink workspace probe file: %w", unlinkErr)
	}
	return nil
}
