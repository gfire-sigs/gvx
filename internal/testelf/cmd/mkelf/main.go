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

// Command mkelf writes a tiny position-independent Linux ELF64 guest. The CI
// smoke steps run it with rungvx, so they need no registry access.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"z.gfire.dev/gvx/internal/testelf"
)

func main() {
	arch := flag.String("arch", runtime.GOARCH, "guest architecture: amd64 or arm64")
	text := flag.String("text", "gvx-smoke-ok\n", "text that the guest writes to standard output")
	exit := flag.Int("exit", 0, "exit code of the guest")
	out := flag.String("o", "", "output path of the ELF file")
	flag.Parse()
	if *out == "" {
		fmt.Fprintln(os.Stderr, "mkelf: -o is required")
		os.Exit(2)
	}
	image, err := testelf.BuildDynamicGuestELF64(*arch, *exit, *text)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkelf: build the guest: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, image, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkelf: write %s: %v\n", *out, err)
		os.Exit(1)
	}
}
