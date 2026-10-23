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

package oci

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// IsTerminal reports whether v is an open *os.File that is a terminal.
func IsTerminal(v any) bool {
	f, ok := v.(*os.File)
	return ok && isTerminalFile(f)
}

// ReadLine reads one line from r and removes the line ending. It reads one
// byte at a time, so it never takes input that belongs to a later read. It
// returns an empty string at the end of the input.
func ReadLine(r io.Reader) (string, error) {
	var line []byte
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return strings.TrimRight(string(line), "\r"), nil
}

// ReadPassword reads a password. When in is a terminal *os.File, it writes
// "Password: " to prompt, reads without echo, and ends the prompt line.
// Otherwise it reads one line from in.
func ReadPassword(in io.Reader, prompt io.Writer) (string, error) {
	if !IsTerminal(in) {
		return ReadLine(in)
	}
	if _, err := io.WriteString(prompt, "Password: "); err != nil {
		return "", fmt.Errorf("oci: write the password prompt: %w", err)
	}
	password, err := readPasswordFile(in.(*os.File))
	_, _ = io.WriteString(prompt, "\n")
	if err != nil {
		return "", fmt.Errorf("oci: read the password: %w", err)
	}
	return password, nil
}
