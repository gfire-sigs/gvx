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

func TestNetPolicyConcurrentReplacementsBothSucceed(t *testing.T) {
	cfg := newNetPolicyTestConfig(t)
	cfg.NetPolicy = &NetPolicyOptions{Policy: NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}}
	sb, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("create protected sandbox: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, sb)

	limit := NetPolicyLimit{RateBPS: 10_000_000, BurstBytes: 131_072, QueueBytes: 524_288}
	candidates := []NetPolicyConfig{
		{RulesV4: policyDropAll, RulesV6: policyAllowAll, TX: limit},
		{RulesV4: policyAllowAll, RulesV6: policyDropAll, RX: limit},
	}
	start := make(chan struct{})
	results := make(chan error, len(candidates))
	for _, candidate := range candidates {
		go func() {
			<-start
			results <- sb.ReplaceNetPolicy(candidate)
		}()
	}
	close(start)
	for range candidates {
		if err := <-results; err != nil {
			t.Errorf("concurrent replacement: %v", err)
		}
	}
	got, err := sb.NetPolicy()
	if err != nil || (got != candidates[0] && got != candidates[1]) {
		t.Fatalf("active policy after concurrent replacements: (%+v, %v), want one complete replacement", got, err)
	}
}

func TestNetPolicyRestartReadsSuppliedConfig(t *testing.T) {
	cfg := newNetPolicyTestConfig(t)
	initial := NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}
	restart := NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyDropAll}
	live := NetPolicyConfig{RulesV4: policyDropAll, RulesV6: policyDropAll}
	cfg.NetPolicy = &NetPolicyOptions{Policy: initial}
	sb, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("create protected sandbox: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, sb)

	cfg.NetPolicy.Policy = restart
	if got, err := sb.NetPolicy(); err != nil || got != initial {
		t.Fatalf("active policy after editing options: (%+v, %v), want %+v", got, err, initial)
	}
	if err := sb.ReplaceNetPolicy(restart); err != nil {
		t.Fatalf("first live replacement: %v", err)
	}
	if err := sb.ReplaceNetPolicy(live); err != nil {
		t.Fatalf("replace live policy: %v", err)
	}
	if got, err := sb.NetPolicy(); err != nil || got != live {
		t.Fatalf("active policy after replacement: (%+v, %v), want %+v", got, err, live)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("close before restart: %v", err)
	}

	reopened, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatalf("restart protected sandbox: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, reopened)
	if got, err := reopened.NetPolicy(); err != nil || got != restart {
		t.Fatalf("policy after restart: (%+v, %v), want %+v", got, err, restart)
	}
}

func TestProtectedCheckpointRestoreUsesExplicitPolicy(t *testing.T) {
	cfg := netPolicyCheckpointConfig(t)
	initial := NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}
	live := NetPolicyConfig{RulesV4: policyDropAll, RulesV6: policyAllowAll}
	cfg.NetPolicy = &NetPolicyOptions{Policy: initial}
	bundle := filepath.Join(t.TempDir(), "checkpoint")
	manifest := captureNetPolicyCheckpoint(t, cfg, bundle, &live)
	if manifest.Version != 5 {
		t.Fatalf("protected manifest version = %d, want 5", manifest.Version)
	}

	withoutPolicy := cfg
	withoutPolicy.NetPolicy = nil
	withoutPolicy.Platform = PlatformType("invalid")
	requireNetPolicyRestoreError(t, withoutPolicy, RestoreOptions{Dir: bundle}, "policy_required")

	selected := NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyDropAll}
	cfg.NetPolicy = &NetPolicyOptions{Policy: selected}
	mountedBundle := cfg
	mountedBundle.WorkspacePath = filepath.Dir(bundle)
	requireNetPolicyRestoreError(t, mountedBundle, RestoreOptions{Dir: bundle}, "invalid_policy")

	restored, err := Restore(t.Context(), cfg, RestoreOptions{Dir: bundle})
	if err != nil {
		t.Fatalf("restore with a different explicit policy: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, restored)
	if got, err := restored.NetPolicy(); err != nil || got != selected {
		t.Fatalf("policy after restore: (%+v, %v), want %+v", got, err, selected)
	}
}

func TestProtectedCheckpointRejectsManifestStateMismatch(t *testing.T) {
	cfg := netPolicyCheckpointConfig(t)
	cfg.NetPolicy = &NetPolicyOptions{Policy: NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}}
	bundle := filepath.Join(t.TempDir(), "checkpoint")
	manifest := captureNetPolicyCheckpoint(t, cfg, bundle, nil)
	cfg.NetPolicy = nil
	statePath := filepath.Join(bundle, checkpointStateFileName)
	state, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(state) <= checkpointPolicyStateHeaderSize {
		t.Fatalf("saved state has no payload after the protected prefix: %d bytes", len(state))
	}
	for _, tc := range []struct {
		name    string
		version int
		state   []byte
	}{
		{"downgrade to legacy unprotected manifest", legacyCheckpointManifestVersion, state},
		{"downgrade to unprotected manifest", CheckpointManifestVersion, state},
		{"partial magic under unprotected manifest", CheckpointManifestVersion, state[:len(checkpointPolicyStateMagic)-1]},
		{"unprotected state under protected manifest", protectedCheckpointManifestVersion, state[checkpointPolicyStateHeaderSize:]},
		{"truncated protected header", protectedCheckpointManifestVersion, state[:len(checkpointPolicyStateMagic)]},
		{"obsolete protected header", protectedCheckpointManifestVersion, []byte(checkpointPolicyStateMagic + "\x01")},
		{"unreleased protected manifest version 2", 2, state},
		{"unreleased protected manifest version 4", 4, state},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := manifest
			m.Version = tc.version
			writeNetPolicyTestManifest(t, bundle, m)
			if err := os.WriteFile(statePath, tc.state, 0o600); err != nil {
				t.Fatal(err)
			}
			requireNetPolicyRestoreError(t, cfg, RestoreOptions{Dir: bundle}, "state_mismatch")
		})
	}
}

func TestUnprotectedNATCheckpointAcceptsExplicitPolicy(t *testing.T) {
	cfg := netPolicyCheckpointConfig(t)
	bundle := filepath.Join(t.TempDir(), "checkpoint")
	manifest := captureNetPolicyCheckpoint(t, cfg, bundle, nil)
	if manifest.Version != CheckpointManifestVersion {
		t.Fatalf("unprotected manifest version = %d, want %d", manifest.Version, CheckpointManifestVersion)
	}
	policy := NetPolicyConfig{RulesV4: policyDropAll, RulesV6: policyDropAll}
	cfg.NetPolicy = &NetPolicyOptions{Policy: policy}
	restored, err := Restore(t.Context(), cfg, RestoreOptions{Dir: bundle})
	if err != nil {
		t.Fatalf("restore unprotected bundle with new policy: %v", err)
	}
	defer closeNetPolicyTestSandbox(t, restored)
	if got, err := restored.NetPolicy(); err != nil || got != policy {
		t.Fatalf("policy after explicit restore: (%+v, %v), want %+v", got, err, policy)
	}
}

func TestNetPolicyRejectsPrivateFilesInGuestMounts(t *testing.T) {
	private := t.TempDir()
	token := filepath.Join(private, "control.token")
	policy := NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}
	for _, tc := range []struct {
		name      string
		configure func(*testing.T, *Config)
	}{
		{"read-only workspace", func(_ *testing.T, c *Config) { c.WorkspacePath, c.WorkspaceReadOnly = private, true }},
		{"checkpoint output mounted separately", func(t *testing.T, c *Config) {
			c.CheckpointDir = filepath.Join(t.TempDir(), "checkpoints")
			c.WorkspacePath = filepath.Dir(c.CheckpointDir)
		}},
		{"ext4 image", func(_ *testing.T, c *Config) {
			c.Mounts = []Mount{{Kind: MountVolume, ImagePath: token, GuestPath: "/data"}}
		}},
		{"overlay upper", func(_ *testing.T, c *Config) {
			c.Mounts = []Mount{{Kind: MountOverlay, ImagePath: filepath.Join(private, "base.ext4"), UpperImagePath: token, GuestPath: "/data"}}
		}},
		{"root image", func(_ *testing.T, c *Config) {
			c.OCIImage, c.RootVolume = "example.invalid/gvx", token
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
			cfg := Config{
				NetPolicy:           &NetPolicyOptions{Policy: policy, ControlPaths: []string{token}},
				DisableHostLockdown: true,
			}
			tc.configure(t, &cfg)
			sb, err := New(t.Context(), cfg)
			if sb != nil {
				closeNetPolicyTestSandbox(t, sb)
			}
			if !errors.Is(err, ErrInvalidConfig) || NetPolicyErrorCode(err) != "invalid_policy" {
				t.Fatalf("start with overlapping private path: %v, want invalid configuration with invalid_policy", err)
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
		NetPolicy:           &NetPolicyOptions{Policy: NetPolicyConfig{RulesV4: policyAllowAll, RulesV6: policyAllowAll}, ControlAddress: other},
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

func captureNetPolicyCheckpoint(t *testing.T, cfg Config, bundle string, replacement *NetPolicyConfig) CheckpointManifest {
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
		if err := sb.ReplaceNetPolicy(*replacement); err != nil {
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
	if wantCode == "state_mismatch" && !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("restore: %v, want ErrCheckpointManifest", err)
	}
}
