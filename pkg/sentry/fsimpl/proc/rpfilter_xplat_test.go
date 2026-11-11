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

package proc

import (
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/usermem"
)

// rpFilterFile is a file under test: the part of the files that the guest
// reads and writes.
type rpFilterFile interface {
	vfs.WritableDynamicBytesSource
}

func newRPFilterStack(t *testing.T) *netstack.Stack {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	t.Cleanup(func() { s.Close() })
	if err := s.CreateNIC(tcpip.NICID(1), loopback.New()); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	return netstack.NewStack(s, 1)
}

func readRPFilter(t *testing.T, f rpFilterFile) string {
	t.Helper()
	var buf bytes.Buffer
	if err := f.Generate(context.Background(), &buf); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return buf.String()
}

func writeRPFilter(f rpFilterFile, text string, offset int64) (int64, error) {
	return f.Write(context.Background(), nil, usermem.BytesIOSequence([]byte(text)), offset)
}

func TestRPFilterFilesReadAndWriteIntegers(t *testing.T) {
	files := map[string]func(*netstack.Stack) rpFilterFile{
		"all":     func(s *netstack.Stack) rpFilterFile { return &nsRPFilter{stack: s} },
		"default": func(s *netstack.Stack) rpFilterFile { return &nsRPFilter{stack: s, isDefault: true} },
		"link":    func(s *netstack.Stack) rpFilterFile { return &linkRPFilter{stack: s, id: 1} },
	}
	for name, newFile := range files {
		f := newFile(newRPFilterStack(t))
		if got := readRPFilter(t, f); got != "0\n" {
			t.Errorf("%s starts with %q, want \"0\\n\"", name, got)
		}
		for _, tc := range []struct{ write, want string }{
			{"1\n", "1\n"}, {"2", "2\n"}, {"  1  \n", "1\n"}, {"0\n", "0\n"},
			{"5\n", "5\n"}, {"-1\n", "-1\n"}, {"2147483647\n", "2147483647\n"},
		} {
			n, err := writeRPFilter(f, tc.write, 0)
			if err != nil || n != int64(len(tc.write)) {
				t.Errorf("%s write %q = (%d, %v), want (%d, nil)", name, tc.write, n, err, len(tc.write))
			}
			if got := readRPFilter(t, f); got != tc.want {
				t.Errorf("%s after write %q reads %q, want %q", name, tc.write, got, tc.want)
			}
		}
		before := readRPFilter(t, f)
		for _, bad := range []string{"abc\n", "1.5\n", "99999999999\n"} {
			if _, err := writeRPFilter(f, bad, 0); !linuxerr.Equals(linuxerr.EINVAL, err) {
				t.Errorf("%s write %q = %v, want EINVAL", name, bad, err)
			}
		}
		if _, err := writeRPFilter(f, "1\n", 3); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Errorf("%s write at offset 3 = %v, want EINVAL", name, err)
		}
		if got := readRPFilter(t, f); got != before {
			t.Errorf("%s changed from %q to %q after refused writes", name, before, got)
		}
	}
}

func TestRPFilterFilesFollowTheRulesOfLinux(t *testing.T) {
	s := newRPFilterStack(t)
	all := &nsRPFilter{stack: s}
	def := &nsRPFilter{stack: s, isDefault: true}
	link := &linkRPFilter{stack: s, id: 1}

	if _, err := writeRPFilter(def, "2\n", 0); err != nil {
		t.Fatal(err)
	}
	// The link has no value of its own, so it follows the default.
	if got := readRPFilter(t, link); got != "2\n" {
		t.Errorf("link after a write to default = %q, want \"2\\n\"", got)
	}
	if got := readRPFilter(t, all); got != "0\n" {
		t.Errorf("all after a write to default = %q, want \"0\\n\"", got)
	}
	if _, err := writeRPFilter(all, "1\n", 0); err != nil {
		t.Fatal(err)
	}
	if got := readRPFilter(t, link); got != "2\n" {
		t.Errorf("link after a write to all = %q, want \"2\\n\"", got)
	}
	if _, err := writeRPFilter(link, "0\n", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := writeRPFilter(def, "1\n", 0); err != nil {
		t.Fatal(err)
	}
	if got := readRPFilter(t, link); got != "0\n" {
		t.Errorf("link with a value of its own after a write to default = %q, want \"0\\n\"", got)
	}
	if got := s.EffectiveRPFilter(1); got != 1 {
		t.Errorf("EffectiveRPFilter = %d, want max(all=1, link=0) = 1", got)
	}
}

func TestRPFilterLinkFileOfAMissingLink(t *testing.T) {
	s := newRPFilterStack(t)
	f := &linkRPFilter{stack: s, id: 42}
	var buf bytes.Buffer
	if err := f.Generate(context.Background(), &buf); !linuxerr.Equals(linuxerr.ENODEV, err) {
		t.Errorf("Generate of a missing link = %v, want ENODEV", err)
	}
	if _, err := writeRPFilter(f, "1\n", 0); !linuxerr.Equals(linuxerr.ENODEV, err) {
		t.Errorf("Write of a missing link = %v, want ENODEV", err)
	}
}
