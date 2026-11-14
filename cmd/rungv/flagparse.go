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
	"flag"
	"strings"
)

type boolFlagValue interface {
	flag.Value
	IsBoolFlag() bool
}

func isBoolFlag(f *flag.Flag) bool {
	if f == nil {
		return false
	}
	bf, ok := f.Value.(boolFlagValue)
	return ok && bf.IsBoolFlag()
}

func flagVisited(fs *flag.FlagSet, name string) bool {
	visited := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			visited = true
		}
	})
	return visited
}

// normalizeRunArgs expands short flag clusters and attached short-flag values
// before "--" or the first positional target. Arguments from the guest target
// onward remain untouched.
func normalizeRunArgs(fs *flag.FlagSet, args []string) []string {
	return normalizeArgs(fs, args, true)
}

// normalizeCommandArgs expands short flag clusters and lifts interspersed flags
// ahead of positional arguments for management commands that take no arbitrary
// guest argv.
func normalizeCommandArgs(fs *flag.FlagSet, args []string) []string {
	return normalizeArgs(fs, args, false)
}

func normalizeArgs(fs *flag.FlagSet, args []string, stopAtPositional bool) []string {
	flagArgs := make([]string, 0, len(args))
	var posArgs []string
	missingValue := false

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			if missingValue {
				return flagArgs
			}
			if stopAtPositional {
				return append(flagArgs, args[i:]...)
			}
			posArgs = append(posArgs, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			if stopAtPositional {
				return append(flagArgs, args[i:]...)
			}
			posArgs = append(posArgs, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, _, hasEq := strings.Cut(arg[2:], "=")
			flagArgs = append(flagArgs, arg)
			if !hasEq {
				if f := fs.Lookup(name); f != nil && !isBoolFlag(f) {
					if i+1 < len(args) && args[i+1] != "--" {
						i++
						flagArgs = append(flagArgs, args[i])
					} else {
						missingValue = true
					}
				}
			}
			continue
		}

		body := arg[1:]
		name, _, hasEq := strings.Cut(body, "=")
		if f := fs.Lookup(name); f != nil {
			flagArgs = append(flagArgs, arg)
			if !hasEq && !isBoolFlag(f) {
				if i+1 < len(args) && args[i+1] != "--" {
					i++
					flagArgs = append(flagArgs, args[i])
				} else {
					missingValue = true
				}
			}
			continue
		}
		if (name == "h" || name == "help") && !hasEq {
			flagArgs = append(flagArgs, arg)
			continue
		}
		if len(body) > 1 {
			if expanded, needNext, ok := expandShortToken(fs, body); ok {
				flagArgs = append(flagArgs, expanded...)
				if needNext {
					if i+1 < len(args) && args[i+1] != "--" {
						i++
						flagArgs = append(flagArgs, args[i])
					} else {
						missingValue = true
					}
				}
				continue
			}
		}
		flagArgs = append(flagArgs, arg)
	}

	if stopAtPositional || len(posArgs) == 0 || missingValue {
		return flagArgs
	}
	out := make([]string, 0, len(flagArgs)+1+len(posArgs))
	out = append(out, flagArgs...)
	out = append(out, "--")
	out = append(out, posArgs...)
	return out
}

func expandShortToken(fs *flag.FlagSet, body string) (expanded []string, needNext bool, ok bool) {
	for j := 0; j < len(body); j++ {
		ch := body[j : j+1]
		f := fs.Lookup(ch)
		if f == nil {
			return nil, false, false
		}
		if isBoolFlag(f) {
			if j+1 < len(body) && body[j+1] == '=' {
				expanded = append(expanded, "-"+ch+body[j+1:])
				return expanded, false, true
			}
			expanded = append(expanded, "-"+ch)
			continue
		}
		if j+1 < len(body) {
			if body[j+1] == '=' {
				expanded = append(expanded, "-"+ch+body[j+1:])
			} else {
				expanded = append(expanded, "-"+ch, body[j+1:])
			}
			return expanded, false, true
		}
		expanded = append(expanded, "-"+ch)
		return expanded, true, true
	}
	return expanded, false, len(expanded) > 0
}
