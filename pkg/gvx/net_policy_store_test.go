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

//go:build (linux && !android) || (darwin && !ios) || windows

package gvx

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/netbackend"
)

const (
	policyStoreChildOp   = "GVX_POLICY_STORE_TEST_OP"
	policyStoreChildPath = "GVX_POLICY_STORE_TEST_PATH"
	policyStoreChildExit = 17
)

func policyStoreTestConfig(verdict string) netbackend.PolicyConfig {
	rules := "*filter\n:INPUT " + verdict + " [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"
	return netbackend.PolicyConfig{RulesV4: rules, RulesV6: rules}
}

func mustOpenPolicyStore(t *testing.T, path string, seed *netbackend.PolicyConfig) *netPolicyStore {
	t.Helper()
	s, err := openNetPolicyStore(path, seed)
	if err != nil {
		t.Fatalf("open policy store: %v", err)
	}
	t.Cleanup(func() { mustClosePolicyStore(t, s) })
	return s
}

func mustClosePolicyStore(t *testing.T, s *netPolicyStore) {
	t.Helper()
	if err := s.Close(); err != nil {
		t.Errorf("close policy store: %v", err)
	}
}

func requirePolicyStoreRejection(t *testing.T, path string, seed *netbackend.PolicyConfig, cause error) {
	t.Helper()
	s, err := openNetPolicyStore(path, seed)
	if err == nil {
		mustClosePolicyStore(t, s)
		t.Fatal("open policy store succeeded, want rejection")
	}
	if cause != nil && !errors.Is(err, cause) {
		t.Fatalf("open policy store error = %v, want %v", err, cause)
	}
}

func runPolicyStoreChild(t *testing.T, path, op string) {
	t.Helper()
	program, err := os.Executable()
	if err != nil {
		t.Fatalf("find test executable: %v", err)
	}
	cmd := exec.CommandContext(t.Context(), program, "-test.run=^TestNetPolicyStoreChild$")
	cmd.Env = append(cmd.Environ(), policyStoreChildOp+"="+op, policyStoreChildPath+"="+path)
	out, err := cmd.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != policyStoreChildExit {
		t.Fatalf("child %s did not reach interruption point: %v\n%s", op, err, out)
	}
}

func TestNetPolicyStoreChild(t *testing.T) {
	op := os.Getenv(policyStoreChildOp)
	if op == "" {
		return
	}
	path := os.Getenv(policyStoreChildPath)
	if op == "exclusive" {
		requirePolicyStoreRejection(t, path, nil, nil)
		os.Exit(policyStoreChildExit)
	}
	s := mustOpenPolicyStore(t, path, nil)
	if op == "partial-stage" {
		if _, err := s.file.WriteAt([]byte(`{"version":1,`), policyStoreSlot(s.generation+1)); err != nil {
			t.Fatalf("write partial slot: %v", err)
		}
		if err := syncPolicyStoreFile(s.file); err != nil {
			t.Fatalf("sync partial slot: %v", err)
		}
		os.Exit(policyStoreChildExit)
	}
	if err := s.Stage(policyStoreTestConfig("DROP")); err != nil {
		t.Fatalf("stage replacement: %v", err)
	}
	switch op {
	case "staged":
	case "committed":
		if err := s.Commit(); err != nil {
			t.Fatalf("commit replacement: %v", err)
		}
	case "torn-marker":
		if _, err := s.file.WriteAt(s.staged.marker[:policyStoreLength], policyStoreMarkerFirst); err != nil {
			t.Fatalf("write partial commit marker: %v", err)
		}
		if err := syncPolicyStoreFile(s.file); err != nil {
			t.Fatalf("sync partial marker: %v", err)
		}
	default:
		t.Fatalf("unknown store interruption: %q", op)
	}
	os.Exit(policyStoreChildExit)
}

func TestNetPolicyStoreCrashRecovery(t *testing.T) {
	seed := policyStoreTestConfig("ACCEPT")
	replacement := policyStoreTestConfig("DROP")
	for _, tc := range []struct {
		op         string
		generation uint64
		rules      string
	}{
		{op: "partial-stage", generation: 1, rules: seed.RulesV4},
		{op: "staged", generation: 1, rules: seed.RulesV4},
		{op: "committed", generation: 2, rules: replacement.RulesV4},
		{op: "torn-marker"},
	} {
		t.Run(tc.op, func(t *testing.T) {
			path := filepath.Join(privatePolicyStoreDir(t), "policy")
			s := mustOpenPolicyStore(t, path, &seed)
			id := s.id
			mustClosePolicyStore(t, s)

			runPolicyStoreChild(t, path, tc.op)
			if tc.generation == 0 {
				requirePolicyStoreRejection(t, path, nil, errPolicyStoreCorrupt)
				return
			}
			reopened := mustOpenPolicyStore(t, path, nil)
			if reopened.id != id || reopened.generation != tc.generation || reopened.config.RulesV4 != tc.rules {
				t.Errorf("recovered ID=%s generation=%d rules=%q, want ID=%s generation=%d rules=%q", reopened.id, reopened.generation, reopened.config.RulesV4, id, tc.generation, tc.rules)
			}
		})
	}
}

func TestNetPolicyStoreRejectsCorruptCommittedState(t *testing.T) {
	for _, tc := range []struct {
		name   string
		offset int64
		size   int
	}{
		{name: "erased marker", offset: policyStoreMarkerFirst, size: policyStoreMarkerSize},
		{name: "damaged payload", offset: policyStoreSlot(2), size: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(privatePolicyStoreDir(t), "policy")
			seed := policyStoreTestConfig("ACCEPT")
			mustClosePolicyStore(t, mustOpenPolicyStore(t, path, &seed))
			runPolicyStoreChild(t, path, "committed")

			f, err := os.OpenFile(path, os.O_WRONLY, 0)
			if err != nil {
				t.Fatalf("open file for corruption fixture: %v", err)
			}
			_, err = f.WriteAt(make([]byte, tc.size), tc.offset)
			if err := errors.Join(err, f.Close()); err != nil {
				t.Fatalf("corrupt committed state: %v", err)
			}
			requirePolicyStoreRejection(t, path, nil, errPolicyStoreCorrupt)
		})
	}
}

func TestNetPolicyStoreOwnsOneWriter(t *testing.T) {
	path := filepath.Join(privatePolicyStoreDir(t), "policy")
	seed := policyStoreTestConfig("ACCEPT")
	requirePolicyStoreRejection(t, path, nil, os.ErrNotExist)
	s := mustOpenPolicyStore(t, path, &seed)
	requirePolicyStoreRejection(t, path, &seed, nil)
	requirePolicyStoreRejection(t, path, nil, nil)
	runPolicyStoreChild(t, path, "exclusive")
	mustClosePolicyStore(t, s)

	reopened := mustOpenPolicyStore(t, path, nil)
	if reopened.id != s.id || reopened.generation != 1 {
		t.Errorf("reopened store = %s generation %d, want %s generation 1", reopened.id, reopened.generation, s.id)
	}
}

func TestNetPolicyStoreOverwritesOnlyInactiveSlot(t *testing.T) {
	path := filepath.Join(privatePolicyStoreDir(t), "policy")
	seed := policyStoreTestConfig("ACCEPT")
	s := mustOpenPolicyStore(t, path, &seed)
	for i, v := range []string{"DROP", "ACCEPT", "DROP"} {
		next := policyStoreTestConfig(v)
		next.RulesV6 += "# replacement rule text\n"
		if err := s.Stage(next); err != nil {
			t.Fatalf("stage generation %d: %v", i+2, err)
		}
		if err := s.Commit(); err != nil {
			t.Fatalf("commit generation %d: %v", i+2, err)
		}
		mustClosePolicyStore(t, s)
		s = mustOpenPolicyStore(t, path, nil)
		if s.generation != uint64(i+2) || s.config != next {
			t.Fatalf("recovered generation=%d policy=%+v, want generation=%d policy=%+v", s.generation, s.config, i+2, next)
		}
	}
}

func TestNetPolicyStoreStageFailureKeepsAuthority(t *testing.T) {
	path := filepath.Join(privatePolicyStoreDir(t), "policy")
	seed := policyStoreTestConfig("ACCEPT")
	s := mustOpenPolicyStore(t, path, &seed)
	replacement := policyStoreTestConfig("DROP")
	if err := s.Stage(replacement); err != nil {
		t.Fatalf("stage valid replacement: %v", err)
	}
	replacement.RulesV4 = strings.Repeat("x", netbackend.MaxPolicyRules+1)
	if err := s.Stage(replacement); err == nil || errors.Is(err, errPolicyStoreUncertain) {
		t.Fatalf("oversized Stage error = %v, want a definite failure", err)
	}
	if err := s.Commit(); err == nil {
		t.Fatal("Commit after failed restage succeeded")
	}
	mustClosePolicyStore(t, s)
	s = mustOpenPolicyStore(t, path, nil)
	if s.generation != 1 || s.config != seed {
		t.Errorf("reopened after failed stage: generation=%d config=%+v, want generation=1 seed configuration", s.generation, s.config)
	}
}

func TestNetPolicyStoreCommitIOFailureIsUncertain(t *testing.T) {
	path := filepath.Join(privatePolicyStoreDir(t), "policy")
	seed := policyStoreTestConfig("ACCEPT")
	s := mustOpenPolicyStore(t, path, &seed)
	replacement := policyStoreTestConfig("DROP")
	if err := s.Stage(replacement); err != nil {
		t.Fatalf("stage replacement: %v", err)
	}
	if err := s.file.Close(); err != nil {
		t.Fatalf("close underlying descriptor: %v", err)
	}
	if err := s.Commit(); !errors.Is(err, errPolicyStoreUncertain) {
		t.Errorf("Commit while I/O unavailable = %v, want uncertain outcome", err)
	}
	if err := s.Stage(replacement); !errors.Is(err, errPolicyStoreUncertain) {
		t.Errorf("Stage after commit failure = %v, want uncertain outcome", err)
	}
	if s.generation != 1 {
		t.Errorf("generation after uncertain Commit = %d, want 1", s.generation)
	}
	if err := s.Close(); !errors.Is(err, os.ErrClosed) {
		t.Errorf("Close after descriptor failure = %v, want closed file error", err)
	}
}

func TestNetPolicyStoreRejectsHardLinks(t *testing.T) {
	dir := privatePolicyStoreDir(t)
	path := filepath.Join(dir, "policy")
	seed := policyStoreTestConfig("ACCEPT")
	mustClosePolicyStore(t, mustOpenPolicyStore(t, path, &seed))
	if err := os.Link(path, filepath.Join(dir, "alias")); err != nil {
		t.Fatalf("create hard link: %v", err)
	}
	requirePolicyStoreRejection(t, path, nil, errPolicyStoreUnsafe)
}
