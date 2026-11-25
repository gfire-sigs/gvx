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
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

const (
	maxLogLineBytes      = 512
	maxLogLinesPerSecond = 50
	tailLines            = 8
)

// sanitizeLine returns line truncated to maxLogLineBytes, with every byte
// outside 0x20 to 0x7e replaced by '?'.
func sanitizeLine(line []byte) string {
	if len(line) > maxLogLineBytes {
		line = line[:maxLogLineBytes]
	}
	var b strings.Builder
	b.Grow(len(line))
	for _, c := range line {
		if c < 0x20 || c > 0x7e {
			b.WriteByte('?')
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// lineLimiter allows at most maxLogLinesPerSecond lines in each one-second
// window and counts the lines that it drops.
type lineLimiter struct {
	windowStart time.Time
	count       int
	dropped     int
}

// allow reports whether a line at now may pass. When a new window starts
// after drops, it returns a summary line "gpurender: dropped N renderer
// stderr lines" to emit first.
func (l *lineLimiter) allow(now time.Time) (ok bool, summary string) {
	if l.windowStart.IsZero() || now.Sub(l.windowStart) >= time.Second {
		if l.dropped > 0 {
			summary = fmt.Sprintf("gpurender: dropped %d renderer stderr lines", l.dropped)
			l.dropped = 0
		}
		l.windowStart = now
		l.count = 1
		return true, summary
	}
	if l.count >= maxLogLinesPerSecond {
		l.dropped++
		return false, ""
	}
	l.count++
	return true, ""
}

// stderrTail keeps the last tailLines sanitized lines for StartError.
type stderrTail struct {
	mu    sync.Mutex
	ring  [tailLines]string
	next  int
	count int
}

func (t *stderrTail) add(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.ring[t.next] = line
	t.next = (t.next + 1) % tailLines
	if t.count < tailLines {
		t.count++
	}
}

func (t *stderrTail) lines() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.count == 0 {
		return nil
	}
	out := make([]string, t.count)
	start := 0
	if t.count == tailLines {
		start = t.next
	}
	for i := range t.count {
		out[i] = t.ring[(start+i)%tailLines]
	}
	return out
}

// pumpStderr reads r line by line until end of file, sanitizes each line,
// adds it to tail, and passes it to log through the limiter.
func pumpStderr(r io.ReadCloser, log func(string), tail *stderrTail) {
	defer r.Close()
	br := bufio.NewReaderSize(r, 4096)
	var lim lineLimiter
	for {
		frag, err := br.ReadSlice('\n')
		if len(frag) == 0 && err != nil {
			return
		}
		var raw []byte
		if err == bufio.ErrBufferFull {
			// Copy the bounded prefix before draining the rest of the line,
			// because the next ReadSlice reuses the reader buffer.
			raw = append([]byte(nil), frag[:min(len(frag), maxLogLineBytes)]...)
			for err == bufio.ErrBufferFull {
				_, err = br.ReadSlice('\n')
			}
		} else {
			raw = bytes.TrimSuffix(frag, []byte{'\n'})
			raw = bytes.TrimSuffix(raw, []byte{'\r'})
		}
		line := sanitizeLine(raw)
		if tail != nil {
			tail.add(line)
		}
		if log != nil {
			ok, summary := lim.allow(time.Now())
			if summary != "" {
				log(summary)
			}
			if ok {
				log(line)
			}
		}
		if err != nil {
			return
		}
	}
}
