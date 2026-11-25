// Copyright 2023 The gVisor Authors.
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

//go:build !false && network_plugins
// +build !false,network_plugins

// Binary runsc-plugin-stack implements the OCI runtime interface
// which supports using third-party network stack as plugin netstack.
package main

import (
	"z.gfire.dev/gvx/pkg/sentry/socket/plugin/cgo"
	"z.gfire.dev/gvx/runsc/cli/maincli"
	"z.gfire.dev/gvx/runsc/sandbox"
	"z.gfire.dev/gvx/runsc/version"
)

// version.Version is set dynamically, but needs to be
// linked in the binary, so reference it here.
var _ = version.Version()

func main() {
	sandbox.PluginStackPreInit = cgo.PreInitStack
	maincli.Main()
}
