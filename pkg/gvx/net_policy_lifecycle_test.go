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
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/netbackend"
)

const (
	policyAllowAll = "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
	policyDropAll  = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"
)

func newNetPolicyTestConfig(t *testing.T) Config {
	t.Helper()
	cfg := newCheckpointTestConfig(t, t.TempDir())
	cfg.NetworkMode = NetModeNAT
	cfg.HostDNSServers = []string{"127.0.0.1:1"}
	return cfg
}

func closeNetPolicyTestSandbox(t *testing.T, sb *Sandbox) {
	t.Helper()
	if err := sb.Close(); err != nil {
		t.Errorf("close sandbox: %v", err)
	}
}

func TestNetPolicyConcurrentReplacePersistsOnlyTheCASWinner(t *testing.T) {
	cfg := newNetPolicyTestConfig(t)
	seed := netbackend.PolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}
	path := filepath.Join(privatePolicyStoreDir(t), "policy")
	cfg.NetPolicy = &NetPolicyOptions{Path: path, Seed: &seed}
	sb, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("create protected sandbox: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, sb)
	initial, err := sb.NetPolicy()
	if err != nil || initial.Revision == "" || initial.PolicyConfig != seed {
		t.Fatalf("read seed policy: (%+v, %v), want nonempty revision and %+v", initial, err, seed)
	}

	limit := netbackend.PolicyLimit{RateBPS: 10_000_000, BurstBytes: 131_072, QueueBytes: 524_288}
	candidates := []netbackend.PolicyConfig{
		{RulesV4: policyDropAll, RulesV6: policyAllowAll, TX: limit},
		{RulesV4: policyAllowAll, RulesV6: policyDropAll, RX: limit},
	}
	type result struct {
		candidate netbackend.PolicyConfig
		snapshot  NetPolicySnapshot
		err       error
	}
	start := make(chan struct{})
	results := make(chan result, len(candidates))
	for _, candidate := range candidates {
		go func() {
			<-start
			snapshot, err := sb.ReplaceNetPolicy(initial.Revision, candidate)
			results <- result{candidate, snapshot, err}
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first.err != nil {
		first, second = second, first
	}
	if first.err != nil || first.snapshot.Revision == initial.Revision || first.snapshot.PolicyConfig != first.candidate {
		t.Fatalf("winning replacement: (%+v, %v), want new revision and %+v", first.snapshot, first.err, first.candidate)
	}
	if got := NetPolicyErrorCode(second.err); got != "revision_conflict" {
		t.Fatalf("second replacement: code %s (%v), want revision_conflict", got, second.err)
	}
	cfg.NetPolicy = &NetPolicyOptions{Path: path}
	busy, err := New(t.Context(), cfg)
	if busy != nil {
		closeNetPolicyTestSandbox(t, busy)
	}
	if NetPolicyErrorCode(err) != "state_unavailable" {
		t.Fatalf("reopen a busy store: %v, want state_unavailable", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("close before restart: %v", err)
	}

	reopened, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("reopen committed policy: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, reopened)
	current, err := reopened.NetPolicy()
	if err != nil || current.Revision == first.snapshot.Revision || current.PolicyConfig != first.candidate {
		t.Fatalf("policy after restart: (%+v, %v), want a new revision and the CAS winner", current, err)
	}
	if _, err := reopened.ReplaceNetPolicy(first.snapshot.Revision, second.candidate); NetPolicyErrorCode(err) != "revision_conflict" {
		t.Fatalf("replace with previous instance revision: %v, want revision_conflict", err)
	}
}

func TestProtectedCheckpointUsesLatestMatchingStoreGeneration(t *testing.T) {
	cfg := netPolicyCheckpointConfig(t)
	seed := netbackend.PolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}
	second := netbackend.PolicyConfig{RulesV4: policyDropAll, RulesV6: policyAllowAll}
	latest := netbackend.PolicyConfig{RulesV4: policyDropAll, RulesV6: policyDropAll}
	storePath := filepath.Join(privatePolicyStoreDir(t), "policy")
	store, err := openNetPolicyStore(storePath, &seed)
	if err != nil {
		t.Fatalf("create initial policy store: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close initial policy store: %v", err)
	}
	firstGeneration := readNetPolicyStoreTestBytes(t, storePath)
	cfg.NetPolicy = &NetPolicyOptions{Path: storePath}
	bundle := filepath.Join(t.TempDir(), "checkpoint")
	manifest := captureNetPolicyCheckpoint(t, cfg, bundle, &second)
	if manifest.Version != protectedCheckpointManifestVersion {
		t.Fatalf("protected manifest version = %d, want %d", manifest.Version, protectedCheckpointManifestVersion)
	}
	if manifest.NetPolicy == nil {
		t.Fatal("protected manifest has no policy binding")
	}
	if got := manifest.NetPolicy.MinGeneration; got != 2 {
		t.Fatalf("protected manifest minimum policy generation = %d, want 2", got)
	}
	cfg.NetPolicy = nil

	t.Run("store is mandatory", func(t *testing.T) {
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle}, "state_unavailable")
	})
	t.Run("missing store cannot be recreated", func(t *testing.T) {
		missingPath := filepath.Join(privatePolicyStoreDir(t), "missing")
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle, NetPolicy: &NetPolicyOptions{Path: missingPath}}, "state_unavailable")
		if _, err := os.Stat(missingPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("protected restore recreated the missing store: stat error %v", err)
		}
	})
	t.Run("protected store cannot be seeded", func(t *testing.T) {
		newPath := filepath.Join(privatePolicyStoreDir(t), "replacement")
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle, NetPolicy: &NetPolicyOptions{Path: newPath, Seed: &seed}}, "state_mismatch")
		if _, err := os.Stat(newPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("protected restore created a replacement store: stat error %v", err)
		}
	})
	t.Run("store identity must match", func(t *testing.T) {
		otherPath := filepath.Join(privatePolicyStoreDir(t), "policy")
		other, err := openNetPolicyStore(otherPath, &seed)
		if err != nil {
			t.Fatalf("create unrelated store: %v", err)
		}
		if err := other.Close(); err != nil {
			t.Fatalf("close unrelated store: %v", err)
		}
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle, NetPolicy: &NetPolicyOptions{Path: otherPath}}, "state_mismatch")
	})
	t.Run("store must meet the recorded minimum", func(t *testing.T) {
		currentGeneration := readNetPolicyStoreTestBytes(t, storePath)
		writeNetPolicyStoreTestBytes(t, storePath, firstGeneration)
		defer writeNetPolicyStoreTestBytes(t, storePath, currentGeneration)
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle, NetPolicy: &NetPolicyOptions{Path: storePath}}, "state_mismatch")
	})
	t.Run("protected manifest requires a binding", func(t *testing.T) {
		incomplete := manifest
		incomplete.NetPolicy = nil
		writeNetPolicyTestManifest(t, bundle, incomplete)
		defer writeNetPolicyTestManifest(t, bundle, manifest)
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle}, "state_mismatch")
	})
	t.Run("legacy manifest cannot name protected state", func(t *testing.T) {
		stale := manifest
		stale.Version, stale.NetPolicy = legacyCheckpointManifestVersion, nil
		writeNetPolicyTestManifest(t, bundle, stale)
		defer writeNetPolicyTestManifest(t, bundle, manifest)
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle}, "state_mismatch")
	})
	t.Run("state header must agree with the protected manifest", func(t *testing.T) {
		stale := manifest
		stale.NetPolicy = &CheckpointNetPolicy{StoreID: manifest.NetPolicy.StoreID, MinGeneration: 3}
		writeNetPolicyTestManifest(t, bundle, stale)
		defer writeNetPolicyTestManifest(t, bundle, manifest)
		requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle}, "state_mismatch")
	})

	selected := &NetPolicyOptions{Path: storePath}
	restored, err := Restore(t.Context(), cfg, RestoreOptions{Dir: bundle, NetPolicy: selected})
	if err != nil {
		t.Fatalf("restore exact generation: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, restored)
	atMinimum, err := restored.NetPolicy()
	if err != nil || atMinimum.PolicyConfig != second {
		t.Fatalf("policy at checkpoint generation: (%+v, %v), want %+v", atMinimum, err, second)
	}
	third, err := restored.ReplaceNetPolicy(atMinimum.Revision, latest)
	if err != nil {
		t.Fatalf("commit a policy newer than the checkpoint: %v", err)
	}
	if err := restored.Close(); err != nil {
		t.Fatalf("close sandbox after replacing restored policy: %v", err)
	}
	newer, err := Restore(t.Context(), cfg, RestoreOptions{Dir: bundle, NetPolicy: selected})
	if err != nil {
		t.Fatalf("restore with store newer than the checkpoint: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, newer)
	got, err := newer.NetPolicy()
	if err != nil || got.PolicyConfig != latest || got.Revision == third.Revision {
		t.Fatalf("policy after restoring older checkpoint: (%+v, %v), want %+v and a new instance revision", got, err, latest)
	}
}

func TestUnprotectedNATCheckpointAcceptsExplicitPolicySeed(t *testing.T) {
	cfg := netPolicyCheckpointConfig(t)
	bundle := filepath.Join(t.TempDir(), "checkpoint")
	manifest := captureNetPolicyCheckpoint(t, cfg, bundle, nil)
	if manifest.Version != CheckpointManifestVersion {
		t.Fatalf("unprotected manifest version = %d, want %d", manifest.Version, CheckpointManifestVersion)
	}
	if manifest.NetPolicy != nil {
		t.Fatalf("unprotected manifest policy binding = %+v, want nil", manifest.NetPolicy)
	}
	seed := netbackend.PolicyConfig{RulesV4: policyDropAll, RulesV6: policyDropAll}
	path := filepath.Join(privatePolicyStoreDir(t), "policy")
	opts := RestoreOptions{Dir: bundle, NetPolicy: &NetPolicyOptions{Path: path, Seed: &seed}}
	restored, err := Restore(t.Context(), cfg, opts)
	if err != nil {
		t.Fatalf("restore unprotected bundle with new policy: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, restored)
	current, err := restored.NetPolicy()
	if err != nil || current.Revision == "" || current.PolicyConfig != seed {
		t.Fatalf("policy after restore with seed: (%+v, %v), want a nonempty revision and %+v", current, err, seed)
	}
}

func TestNetPolicyRejectsPrivateFilesInGuestMountsAndCaches(t *testing.T) {
	private := privatePolicyStoreDir(t)
	store := filepath.Join(private, "policy")
	seed := netbackend.PolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}
	for _, tc := range []struct {
		name      string
		configure func(*testing.T, *Config)
	}{
		{"read-only workspace", func(_ *testing.T, c *Config) { c.WorkspacePath, c.WorkspaceReadOnly = private, true }},
		{"layer cache", func(_ *testing.T, c *Config) { c.OCICacheDir = private }},
		{"checkpoint directory", func(_ *testing.T, c *Config) { c.CheckpointDir = private }},
		{"checkpoint output mounted separately", func(t *testing.T, c *Config) {
			c.CheckpointDir = filepath.Join(t.TempDir(), "checkpoints")
			c.WorkspacePath = filepath.Dir(c.CheckpointDir)
		}},
		{"ext4 image", func(_ *testing.T, c *Config) {
			c.Mounts = []Mount{{Kind: MountVolume, ImagePath: store, GuestPath: "/data"}}
		}},
		{"overlay upper", func(_ *testing.T, c *Config) {
			c.Mounts = []Mount{{Kind: MountOverlay, ImagePath: filepath.Join(private, "base.ext4"), UpperImagePath: store, GuestPath: "/data"}}
		}},
		{"root image", func(_ *testing.T, c *Config) {
			c.OCIImage, c.RootVolume = "example.invalid/gvx", store
		}},
		{"control token mounted separately", func(t *testing.T, c *Config) {
			workspace := t.TempDir()
			c.WorkspacePath = workspace
			c.NetPolicy.ControlPaths = []string{filepath.Join(workspace, "control.token")}
		}},
		{"symlinked workspace", func(t *testing.T, c *Config) {
			alias := filepath.Join(t.TempDir(), "alias")
			symlinkOrSkip(t, private, alias)
			c.WorkspacePath = alias
		}},
		{"legacy hostfs volume alias", func(t *testing.T, c *Config) {
			c.OCICacheDir = t.TempDir()
			root := filepath.Join(c.OCICacheDir, "volumes")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}
			symlinkOrSkip(t, private, filepath.Join(root, "data"))
			c.Mounts = []Mount{{Kind: MountVolume, VolumeName: "data", GuestPath: "/data"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{NetPolicy: &NetPolicyOptions{Path: store, Seed: &seed}, DisableHostLockdown: true}
			tc.configure(t, &cfg)
			sb, err := New(t.Context(), cfg)
			if sb != nil {
				closeNetPolicyTestSandbox(t, sb)
			}
			if !errors.Is(err, ErrInvalidConfig) || NetPolicyErrorCode(err) != "state_unavailable" {
				t.Fatalf("start with overlapping private path: %v, want invalid configuration with state_unavailable", err)
			}
			if _, err := os.Stat(store); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("overlapping path created a store: stat error %v", err)
			}
		})
	}
}

func TestNetPolicyRejectsControlAddressDifferentFromBoundListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	bound := ln.Addr().(*net.TCPAddr).AddrPort()
	other := netip.AddrPortFrom(bound.Addr(), bound.Port()^1)
	cfg := Config{
		NetPolicy:           &NetPolicyOptions{Path: filepath.Join(privatePolicyStoreDir(t), "policy"), ControlAddress: other},
		CheckpointListener:  ln,
		DisableHostLockdown: true,
	}
	sb, err := New(t.Context(), cfg)
	if sb != nil {
		closeNetPolicyTestSandbox(t, sb)
	}
	if NetPolicyErrorCode(err) != "invalid_policy" {
		t.Fatalf("start with configured control address %s and bound address %s: %v, want invalid_policy", other, bound, err)
	}
}

func netPolicyCheckpointConfig(t *testing.T) Config {
	t.Helper()
	cfg := newNetPolicyTestConfig(t)
	cat, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: cat, Mode: 0o755},
		testimage.File{Name: "ready", Data: []byte("ready\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatal(err)
	}
	cfg.OCILayerTars = [][]byte{layer}
	cfg.Argv = []string{"/bin/cat", "/ready", "/proc/self/fd/0"}
	return cfg
}

func captureNetPolicyCheckpoint(t *testing.T, cfg Config, bundle string, replacement *netbackend.PolicyConfig) CheckpointManifest {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	input, writer := net.Pipe()
	defer input.Close()
	defer writer.Close()
	output := newNotifyBuffer()
	cfg.CheckpointDir, cfg.Stdin, cfg.Stdout = bundle, input, output
	sb, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("start checkpoint source: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, sb)
	if replacement != nil {
		current, err := sb.NetPolicy()
		if err != nil {
			t.Fatalf("read policy before checkpoint: %v", err)
		}
		if _, err := sb.ReplaceNetPolicy(current.Revision, *replacement); err != nil {
			t.Fatalf("replace policy before checkpoint: %v", err)
		}
	}
	var runCode int
	var runErr error
	done := make(chan struct{})
	go func() {
		runCode, runErr = sb.Run(ctx)
		close(done)
	}()
	defer func() {
		cancel()
		_ = writer.Close()
		<-done
	}()
	output.waitForSubstring(t, "ready\n", 15*time.Second)
	if err := sb.Checkpoint(ctx, CheckpointOptions{}); err != nil {
		t.Fatalf("checkpoint NAT sandbox: %v", err)
	}
	<-done
	if runCode != 0 || runErr != nil {
		t.Fatalf("checkpoint source Run: (%d, %v), want (0, nil)", runCode, runErr)
	}
	manifest, err := readAndParseManifest(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func readNetPolicyStoreTestBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("save policy fixture: %v", err)
	}
	return data
}

func writeNetPolicyStoreTestBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("restore policy fixture: %v", err)
	}
}

func writeNetPolicyTestManifest(t *testing.T, bundle string, manifest CheckpointManifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, checkpointManifestFileName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireNetPolicyRestoreError(t *testing.T, cfg Config, opts RestoreOptions, wantCode string) {
	t.Helper()
	sb, err := Restore(t.Context(), cfg, opts)
	if sb != nil {
		closeNetPolicyTestSandbox(t, sb)
	}
	if got := NetPolicyErrorCode(err); got != wantCode {
		t.Fatalf("restore: code %s (%v), want %s", got, err, wantCode)
	}
}
