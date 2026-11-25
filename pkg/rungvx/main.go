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

// Package rungvx implements the standalone CLI runner for gvx.
package rungvx

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
)

// cliIO carries the standard streams and compile-time CLI plugins of one
// command invocation.
type cliIO struct {
	stdin   io.Reader
	stdout  io.Writer
	stderr  io.Writer
	plugins []CLIPlugin
}

// command is one subcommand of rungvx. Each command file registers itself in an
// init function, so that adding a command changes no shared line.
type command struct {
	name    string
	aliases []string
	summary string
	// usage lists the synopsis lines that the help text prints.
	usage []string
	run   func(ctx context.Context, args []string, streams cliIO) int
}

var commands = map[string]command{}

func register(c command) {
	if _, dup := commands[c.name]; dup {
		panic("rungvx: duplicate command " + c.name)
	}
	commands[c.name] = c
	for _, alias := range c.aliases {
		if _, dup := commands[alias]; dup {
			panic("rungvx: duplicate command " + alias)
		}
		commands[alias] = c
	}
}

// Main runs the pure-Go rungvx CLI with no compile-time extension plugins.
func Main(args []string) int {
	return MainWithPlugins(args)
}

// MainWithPlugins runs the rungvx CLI with the supplied compile-time extension
// plugins attached to flag parsing, sandbox configuration, and version output.
func MainWithPlugins(args []string, plugins ...CLIPlugin) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return executeCLIWithPlugins(ctx, args, os.Stdin, os.Stdout, os.Stderr, plugins)
}

func executeCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return executeCLIWithPlugins(ctx, args, stdin, stdout, stderr, nil)
}

func executeCLIWithPlugins(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, plugins []CLIPlugin) int {
	filtered := make([]CLIPlugin, 0, len(plugins))
	for _, p := range plugins {
		if p != nil {
			filtered = append(filtered, p)
		}
	}
	if len(args) == 0 {
		printUsageWithPlugins(stderr, filtered)
		return 2
	}

	streams := cliIO{stdin: stdin, stdout: stdout, stderr: stderr, plugins: filtered}
	subcmd := args[0]
	if subcmd == unixForwardHelperSubcmd {
		return runUnixForwardHelper(ctx, args[1:], stdin, stdout)
	}
	switch subcmd {
	case "-h", "--help", "help":
		printUsageWithPlugins(stdout, filtered)
		return 0
	case "-version", "--version":
		return commands["version"].run(ctx, args[1:], streams)
	case "-V":
		return commands["version"].run(ctx, append([]string{"-V"}, args[1:]...), streams)
	}
	if c, ok := commands[subcmd]; ok {
		return c.run(ctx, args[1:], streams)
	}
	if pc, ok := findPluginCommand(filtered, subcmd); ok {
		return pc.Run(ctx, args[1:], stdin, stdout, stderr)
	}
	// Allow invoking rungvx directly with flags if "run" was omitted.
	if strings.HasPrefix(subcmd, "-") {
		return commands["run"].run(ctx, args, streams)
	}
	_, _ = fmt.Fprintf(stderr, "rungvx: unknown subcommand %q\n", subcmd)
	printUsageWithPlugins(stderr, filtered)
	return 2
}

func findPluginCommand(plugins []CLIPlugin, name string) (PluginCommand, bool) {
	for _, p := range plugins {
		cp, ok := p.(CommandPlugin)
		if !ok {
			continue
		}
		for _, pc := range cp.Commands() {
			if pc.Name == name {
				return pc, true
			}
			for _, alias := range pc.Aliases {
				if alias == name {
					return pc, true
				}
			}
		}
	}
	return PluginCommand{}, false
}

func printUsage(w io.Writer) {
	printUsageWithPlugins(w, nil)
}

func printUsageWithPlugins(w io.Writer, plugins []CLIPlugin) {
	_, _ = fmt.Fprintln(w, "Usage:")
	merged := make(map[string]command, len(commands))
	names := make([]string, 0, len(commands))
	for name, c := range commands {
		if name == c.name {
			merged[name] = c
			names = append(names, name)
		}
	}
	for _, p := range plugins {
		cp, ok := p.(CommandPlugin)
		if !ok {
			continue
		}
		for _, pc := range cp.Commands() {
			if pc.Name == "" {
				continue
			}
			if _, exists := merged[pc.Name]; exists {
				continue
			}
			merged[pc.Name] = command{
				name:    pc.Name,
				summary: pc.Summary,
				usage:   pc.Usage,
			}
			names = append(names, pc.Name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		c := merged[name]
		for _, line := range c.usage {
			_, _ = fmt.Fprintln(w, "  "+line)
		}
		for _, line := range strings.Split(c.summary, "\n") {
			if line != "" {
				_, _ = fmt.Fprintln(w, "      "+line)
			}
		}
	}
}
