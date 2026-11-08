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

//go:build linux

// Command androidprobe reports the host facilities that the Linux systrap
// engine needs, as the process that runs it sees them. On Android, the probe
// app of scripts/android starts it as untrusted_app, so it sees the SELinux
// domain and the seccomp filter of an app (docs/gvxip/gvxip-006).
//
// Usage:
//
//	androidprobe report
//	androidprobe guests DIR
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"z.gfire.dev/gvx/internal/testelf"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: androidprobe report | guests DIR")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "report":
		os.Exit(report(os.Stdout))
	case "guests":
		if len(os.Args) != 3 {
			fmt.Fprintln(os.Stderr, "usage: androidprobe guests DIR")
			os.Exit(2)
		}
		if err := writeGuests(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case childPtrace, childSeccompTrap, childSeccompListener:
		os.Exit(runChild(os.Args[1]))
	default:
		fmt.Fprintf(os.Stderr, "androidprobe: unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

// writeGuests writes the guest programs that the smoke runs of the probe app
// start with rungv -bin. Each program prints its name and exits with 0.
func writeGuests(dir string) error {
	guests := map[string]func() ([]byte, error){
		// A position-independent executable.
		"guest-pie": func() ([]byte, error) {
			return testelf.BuildDynamicGuestELF64(runtime.GOARCH, 0, "guest-pie ok\n")
		},
		// Fixed-address executables at the base addresses of Go and GNU ld.
		"guest-fixed-0x10000": func() ([]byte, error) {
			return testelf.BuildGuestELF64At(runtime.GOARCH, 0x10000, 0, "guest-fixed-0x10000 ok\n")
		},
		"guest-fixed-0x400000": func() ([]byte, error) {
			return testelf.BuildGuestELF64At(runtime.GOARCH, 0x400000, 0, "guest-fixed-0x400000 ok\n")
		},
	}
	if runtime.GOARCH == "arm64" {
		// Code and data share one 16 KB host page at a 4 KB boundary.
		guests["guest-shared-page"] = func() ([]byte, error) {
			return testelf.BuildSharedPageGuestELF64(0x400000)
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, build := range guests {
		data, err := build()
		if err != nil {
			return fmt.Errorf("build %s: %w", name, err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o755); err != nil {
			return err
		}
	}
	return nil
}
