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

// Binary rungv is the standalone CLI runner for gvx on Windows and macOS.
package main

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

// cliIO carries the standard streams of one command invocation.
type cliIO struct {
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

// command is one subcommand of rungv. Each command file registers itself in an
// init function, so that adding a command changes no shared line.
type command struct {
	name    string
	summary string
	// usage lists the synopsis lines that the help text prints.
	usage []string
	run   func(ctx context.Context, args []string, streams cliIO) int
}

var commands = map[string]command{}

func register(c command) {
	if _, dup := commands[c.name]; dup {
		panic("rungv: duplicate command " + c.name)
	}
	commands[c.name] = c
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code := executeCLI(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	os.Exit(code)
}

func executeCLI(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	streams := cliIO{stdin: stdin, stdout: stdout, stderr: stderr}
	subcmd := args[0]
	switch subcmd {
	case "worker":
		return workerSubcommand(ctx, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	}
	if c, ok := commands[subcmd]; ok {
		return c.run(ctx, args[1:], streams)
	}
	// Allow invoking rungv directly with flags if "run" was omitted.
	if strings.HasPrefix(subcmd, "-") {
		return commands["run"].run(ctx, args, streams)
	}
	_, _ = fmt.Fprintf(stderr, "rungv: unknown subcommand %q\n", subcmd)
	printUsage(stderr)
	return 2
}

func printUsage(w io.Writer) {
	_, _ = fmt.Fprintln(w, "Usage:")
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		c := commands[name]
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
