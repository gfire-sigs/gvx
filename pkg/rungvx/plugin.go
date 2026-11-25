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

package rungvx

import (
	"context"
	"flag"
	"io"

	"z.gfire.dev/gvx/pkg/gvx"
)

// CLIPlugin integrates an optional compile-time extension into rungvx flag
// parsing, sandbox configuration, and nginx-style version output.
type CLIPlugin interface {
	// Name returns the stable lowercase identifier of the extension (for example "gpu").
	Name() string
	// BuildSummary returns a concise deterministic capability summary printed by
	// `rungvx version -V` (for example "modes=venus,virgl").
	BuildSummary() string
	// RegisterFlags adds extension-specific flags to the run/restore FlagSet.
	RegisterFlags(fs *flag.FlagSet)
	// ApplyConfig validates parsed flags and appends any enabled gvx.Extension
	// to cfg.Extensions.
	ApplyConfig(cfg *gvx.Config) error
}

// PluginCommand defines an optional top-level subcommand contributed by a
// CLIPlugin that implements CommandPlugin.
type PluginCommand struct {
	Name    string
	Aliases []string
	Summary string
	Usage   []string
	Run     func(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int
}

// CommandPlugin is optionally implemented by a CLIPlugin that contributes
// additional top-level subcommands to rungvx.
type CommandPlugin interface {
	Commands() []PluginCommand
}
