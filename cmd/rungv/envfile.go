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
	"bufio"
	"fmt"
	"io"
	"strings"
)

// lookupEnv reads one variable of the host environment.
type lookupEnv func(key string) (string, bool)

// resolveEnvEntry turns one "-e" argument or one line of an env file into a
// KEY=VALUE entry. An entry "KEY=VALUE" stays as it is. An entry "KEY" takes
// the value from the host, and it yields no entry when the host has no such
// variable, as Docker does. The value is literal: the function removes no quote.
func resolveEnvEntry(entry string, lookup lookupEnv) (kv string, ok bool, err error) {
	key, _, hasValue := strings.Cut(entry, "=")
	if key == "" {
		return "", false, fmt.Errorf("invalid environment variable %q: the name is empty", entry)
	}
	if strings.ContainsAny(key, " \t") {
		return "", false, fmt.Errorf("invalid environment variable %q: the name contains white space", entry)
	}
	if hasValue {
		return entry, true, nil
	}
	if value, found := lookup(key); found {
		return key + "=" + value, true, nil
	}
	return "", false, nil
}

// parseEnvFile reads a Docker env file. A line is "KEY=VALUE" or "KEY". The
// parser skips blank lines and lines that start with "#", trims white space at
// the start of a line, and removes a carriage return at the end of a line.
func parseEnvFile(r io.Reader, lookup lookupEnv) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimLeft(strings.TrimSuffix(sc.Text(), "\r"), " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		kv, ok, err := resolveEnvEntry(line, lookup)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		if ok {
			out = append(out, kv)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read the env file: %w", err)
	}
	return out, nil
}
