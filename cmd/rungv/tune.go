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

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

func init() {
	register(command{
		name:    "tune",
		summary: "List the host-side tunables that --tune and --tune-file accept.",
		usage:   []string{"rungv tune list"},
		run: func(_ context.Context, args []string, streams cliIO) int {
			return tuneSubcommand(args, streams.stdout, streams.stderr)
		},
	})
}

// tuneFlags holds the --tune and --tune-file flags of one command.
type tuneFlags struct {
	pairs listFlag
	file  *string
}

// addTuneFlags defines --tune and --tune-file on fs.
func addTuneFlags(fs *flag.FlagSet) *tuneFlags {
	t := &tuneFlags{}
	fs.Var(&t.pairs, "tune", "Set a host-side tunable: KEY=VALUE, repeatable; run `rungv tune list` for the keys")
	t.file = fs.String("tune-file", "", "Read host-side tunables from a JSON object of key and value pairs; --tune wins over the file")
	return t
}

// values builds the tunables. The file comes first, and each --tune flag
// follows in order, so a flag wins over the file.
func (t *tuneFlags) values() (tuning.Values, error) {
	var v tuning.Values
	if path := strings.TrimSpace(*t.file); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return tuning.Values{}, fmt.Errorf("--tune-file: %w", err)
		}
		if v, err = tuning.ParseJSON(data); err != nil {
			return tuning.Values{}, fmt.Errorf("--tune-file %s: %w", path, err)
		}
	}
	for _, pair := range t.pairs {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			return tuning.Values{}, fmt.Errorf("--tune %q: want KEY=VALUE", pair)
		}
		var err error
		if v, err = v.Set(strings.TrimSpace(key), value); err != nil {
			return tuning.Values{}, fmt.Errorf("--tune: %w", err)
		}
	}
	return v, nil
}

// tuneSubcommand runs `rungv tune`.
func tuneSubcommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "list" {
		_, _ = fmt.Fprintln(stderr, "usage: rungv tune list")
		return 2
	}
	writeTunables(stdout)
	return 0
}

// writeTunables prints one line for each tunable: the key, the type, the
// default, the range, the unit, and the description.
func writeTunables(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "KEY\tTYPE\tDEFAULT\tRANGE\tUNIT\tDESCRIPTION")
	for _, e := range tuning.Entries() {
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", e.Name, e.Kind, e.DefaultText(), e.RangeText(), e.Unit, e.Doc)
	}
	_ = tw.Flush()
}
