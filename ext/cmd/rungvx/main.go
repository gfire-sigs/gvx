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

// Binary rungvx in z.gfire.dev/gvx/ext compiles optional hardware extensions
// into rungvx via Go build tags (for example -tags ext_gpu or -tags ext_all).
package main

import (
	"os"

	"z.gfire.dev/gvx/pkg/rungvx"
)

func main() {
	os.Exit(rungvx.MainWithPlugins(os.Args[1:], registeredPlugins...))
}
