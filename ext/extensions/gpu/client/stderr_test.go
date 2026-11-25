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

package gpurender

import (
	"bytes"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestSanitizeLine(t *testing.T) {
	if got, want := sanitizeLine([]byte("\x1b[31mred\x07")), "?[31mred?"; got != want {
		t.Fatalf("sanitizeLine(ANSI) = %q, want %q", got, want)
	}

	long := bytes.Repeat([]byte("a"), 600)
	gotLong := sanitizeLine(long)
	if len(gotLong) != maxLogLineBytes {
		t.Fatalf("len(sanitizeLine(600)) = %d, want %d", len(gotLong), maxLogLineBytes)
	}

	// UTF-8 multi-byte code point U+00E9 encodes as 0xC3 0xA9 (two bytes outside ASCII).
	if got, want := sanitizeLine([]byte("a\u00e9b")), "a??b"; got != want {
		t.Fatalf("sanitizeLine(UTF-8) = %q, want %q", got, want)
	}
}

func TestLineLimiterWindow(t *testing.T) {
	var lim lineLimiter
	t0 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)

	for i := range maxLogLinesPerSecond {
		ok, summary := lim.allow(t0.Add(time.Duration(i) * time.Millisecond))
		if !ok || summary != "" {
			t.Fatalf("line %d: allow = (%v, %q), want (true, \"\")", i+1, ok, summary)
		}
	}

	ok, summary := lim.allow(t0.Add(500 * time.Millisecond))
	if ok || summary != "" {
		t.Fatalf("line 51: allow = (%v, %q), want (false, \"\")", ok, summary)
	}

	ok, summary = lim.allow(t0.Add(time.Second))
	wantSummary := "gpurender: dropped 1 renderer stderr lines"
	if !ok || summary != wantSummary {
		t.Fatalf("next window line 1: allow = (%v, %q), want (true, %q)", ok, summary, wantSummary)
	}
}

func TestPumpStderrKeepsTail(t *testing.T) {
	var in strings.Builder
	var wantAll []string
	for i := 1; i <= 10; i++ {
		line := fmt.Sprintf("line %d", i)
		wantAll = append(wantAll, line)
		in.WriteString(line)
		in.WriteByte('\n')
	}

	var logged []string
	var tail stderrTail
	pumpStderr(io.NopCloser(strings.NewReader(in.String())), func(line string) {
		logged = append(logged, line)
	}, &tail)

	if !slices.Equal(logged, wantAll) {
		t.Fatalf("logged = %v, want %v", logged, wantAll)
	}
	wantTail := wantAll[2:]
	if gotTail := tail.lines(); !slices.Equal(gotTail, wantTail) {
		t.Fatalf("tail = %v, want %v", gotTail, wantTail)
	}
}

func TestPumpStderrTruncatesOversizedLine(t *testing.T) {
	huge := strings.Repeat("x", 8192) + "\nafter\n"
	var logged []string
	var tail stderrTail
	pumpStderr(io.NopCloser(strings.NewReader(huge)), func(line string) {
		logged = append(logged, line)
	}, &tail)

	if len(logged) != 2 {
		t.Fatalf("len(logged) = %d, want 2", len(logged))
	}
	if len(logged[0]) != maxLogLineBytes {
		t.Fatalf("len(logged[0]) = %d, want %d", len(logged[0]), maxLogLineBytes)
	}
	if logged[1] != "after" {
		t.Fatalf("logged[1] = %q, want %q", logged[1], "after")
	}
	wantTail := []string{strings.Repeat("x", maxLogLineBytes), "after"}
	if gotTail := tail.lines(); !slices.Equal(gotTail, wantTail) {
		t.Fatalf("tail = %v, want %v", gotTail, wantTail)
	}
}
