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
	"bytes"
	"context"
	"strings"
	"testing"
)

func runStub(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code = executeCLI(context.Background(), append([]string{"stub"}, args...), nil, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

func TestStubRejectsArguments(t *testing.T) {
	code, stdout, stderr := runStub(t, "extra")
	if code != 2 || stdout != "" || !strings.Contains(stderr, `unexpected argument "extra"`) {
		t.Fatalf("rungvx stub extra = (code %d, stdout %q, stderr %q), want usage error", code, stdout, stderr)
	}
}

func TestStubHelpListsSubcommand(t *testing.T) {
	var stdout bytes.Buffer
	if code := executeCLI(context.Background(), []string{"help"}, nil, &stdout, &bytes.Buffer{}); code != 0 {
		t.Fatalf("rungvx help exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "rungvx stub") {
		t.Fatalf("usage = %q, want the stub subcommand", stdout.String())
	}
}
