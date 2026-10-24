package gvxshim

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func platformFixture(t *testing.T) *instancePaths {
	t.Helper()
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := instanceIdentity{Owner: owner, Namespace: "platform-tests", ID: "instance", Bundle: bundle}
	id.ContainerdAddress, _, err = platformAddresses(id, "test-containerd")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := openPaths(t.Context(), id, createPaths)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := paths.Close(); err != nil {
			t.Error(err)
		}
	})
	return paths
}

func TestInspectPathsDoesNotCreateState(t *testing.T) {
	owner, err := currentOwner()
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := canonicalBundle(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := instanceIdentity{Owner: owner, Namespace: "inspect-tests", ID: "absent", Bundle: bundle}
	id.ContainerdAddress, _, err = platformAddresses(id, "inspect-containerd")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := openPaths(t.Context(), id, inspectPaths)
	if err != nil {
		t.Fatal(err)
	}
	defer paths.Close()
	if paths.State != nil {
		t.Fatal("inspection created or adopted absent state")
	}
	if _, err := os.Lstat(filepath.Join(bundle, ".gvx-shim")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("state after inspection: %v", err)
	}
}

func TestStableLockReportsContentionAndCancellation(t *testing.T) {
	paths := platformFixture(t)
	first, err := openLock(paths, commandLock)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := openLock(paths, commandLock)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := tryLock(first); err != nil {
		t.Fatal(err)
	}
	defer unlock(first)
	if err := tryLock(second); !errors.Is(err, errLockBusy) {
		t.Fatalf("second lock: got %v, want contention", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := lock(ctx, second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled lock: %v", err)
	}
}

func TestOwnedRemovalPreservesReplacement(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := paths.State.Root.Rename(ref.Name, "original.log"); err != nil {
		t.Fatal(err)
	}
	replacement, err := openPrivateFile(paths.State, ref.Name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.WriteString("replacement"); err != nil {
		t.Fatal(err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	if err := removeOwned(paths.State, ref); !errors.Is(err, errPathChanged) {
		t.Fatalf("replacement removal: %v", err)
	}
	data, err := paths.State.Root.ReadFile(ref.Name)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement changed: %q, %v", data, err)
	}
}

func TestMutableHardlinkIsRejected(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(paths.Identity.Bundle, ".gvx-shim", ref.Name), filepath.Join(paths.Identity.Bundle, ".gvx-shim", "alias")); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectEntry(paths.State, ref.Name, regularEntry); !errors.Is(err, errUnsafeEntry) {
		t.Fatalf("hardlinked entry accepted: %v", err)
	}
	if err := removeOwned(paths.State, ref); !errors.Is(err, errUnsafeEntry) {
		t.Fatalf("hardlinked entry removal: %v", err)
	}
}

func TestDiagnosticsCannotReplaceExistingEntry(t *testing.T) {
	paths := platformFixture(t)
	file, _, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("preserve"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if other, _, err := createDiagnostics(paths); err == nil {
		other.Close()
		t.Fatal("existing diagnostics accepted")
	}
	data, err := paths.State.Root.ReadFile("diagnostics.log")
	if err != nil || string(data) != "preserve" {
		t.Fatalf("diagnostics changed: %q, %v", data, err)
	}
}

func TestAbsentEndpointsRejectsUnrecordedListener(t *testing.T) {
	paths := platformFixture(t)
	if err := absentEndpoints(paths); err != nil {
		t.Fatalf("absent endpoints: %v", err)
	}
	if err := prepareEndpointDir(t.Context(), paths); err != nil {
		t.Fatal(err)
	}
	endpoint, err := listenLocal(t.Context(), paths, taskEndpoint)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		endpoint.Listener.Close()
		if endpoint.Ref.Socket != nil {
			if err := removeOwned(paths.UnixEndpointDir, *endpoint.Ref.Socket); err != nil {
				t.Error(err)
			}
		}
		if paths.Snapshot.UnixEndpointDir != nil {
			if err := removeEndpointDir(paths, *paths.Snapshot.UnixEndpointDir); err != nil {
				t.Error(err)
			}
		}
	})
	if err := absentEndpoints(paths); err == nil {
		t.Fatal("unrecorded listener reported absent")
	}
}

func TestPrivateTruncateRemovesPreviousEOF(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("previous longer record"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = openPrivateFile(paths.State, ref.Name, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("short"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := paths.State.Root.ReadFile(ref.Name)
	if err != nil || string(data) != "short" {
		t.Fatalf("truncated record: %q, %v", data, err)
	}
}

func TestPrivateTruncatePreservesUnsafeHardlink(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	const original = "preserve unsafe file"
	if _, err := file.WriteString(original); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(paths.Identity.Bundle, ".gvx-shim", "diagnostics-alias")
	if err := os.Link(filepath.Join(paths.Identity.Bundle, ".gvx-shim", ref.Name), alias); err != nil {
		t.Fatal(err)
	}
	if file, err := openPrivateFile(paths.State, ref.Name, os.O_WRONLY|os.O_TRUNC, 0); err == nil {
		file.Close()
		t.Fatal("hardlinked file accepted for truncation")
	} else if !errors.Is(err, errUnsafeEntry) {
		t.Fatalf("unsafe truncation error: %v", err)
	}
	data, err := os.ReadFile(alias)
	if err != nil || string(data) != original {
		t.Fatalf("unsafe file changed before rejection: %q, %v", data, err)
	}
}

func TestPrivateAppendPreservesExistingBytes(t *testing.T) {
	paths := platformFixture(t)
	file, ref, err := createDiagnostics(paths)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("first"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, err = openPrivateFile(paths.State, ref.Name, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("second"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := paths.State.Root.ReadFile(ref.Name)
	if err != nil || string(data) != "firstsecond" {
		t.Fatalf("appended diagnostics: %q, %v", data, err)
	}
}
