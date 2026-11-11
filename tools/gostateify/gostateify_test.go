package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/tools/gostateify/internal/testfixture"
	"z.gfire.dev/gvx/tools/gostateify/stateify"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return filepath.Clean(filepath.Join(wd, "..", ".."))
}

func TestGoldenUpstreamPackages(t *testing.T) {
	root := repoRoot(t)
	goldenPackages := []string{
		"pkg/bitmap",
		"pkg/bpf",
		"pkg/ilist",
		"pkg/refs",
		"pkg/sentry/checkpoint",
		"pkg/sentry/fsimpl/kernfs",
		"pkg/sentry/fsimpl/tmpfs",
		"pkg/sentry/inet",
		"pkg/sentry/kernel/auth",
		"pkg/sentry/kernel/futex",
		"pkg/sentry/kernel/pipe",
		"pkg/sentry/limits",
		"pkg/sentry/pgalloc",
		"pkg/sentry/socket/control",
		"pkg/sentry/uniqueid",
		"pkg/sentry/vfs",
		"pkg/tcpip/stack",
		"pkg/tcpip/transport/udp",
		"pkg/waiter",
	}

	for _, pkg := range goldenPackages {
		t.Run(pkg, func(t *testing.T) {
			report, err := stateify.Run(stateify.Options{
				RootDir:         root,
				Packages:        []string{pkg},
				PartitionByTier: true,
				Check:           true,
			})
			if err != nil {
				t.Fatalf("verify %s failed:\n%v", pkg, err)
			}
			if report.PackagesInspected != 1 || report.FilesVerified == 0 {
				t.Fatalf("unexpected report for %s: %+v", pkg, report)
			}
		})
	}

	for _, pkg := range []string{"pkg/sentry/kernel", "pkg/sentry/mm"} {
		t.Run(pkg+"_tier2", func(t *testing.T) {
			report, err := stateify.Run(stateify.Options{
				RootDir:         root,
				Packages:        []string{pkg},
				PartitionByTier: true,
				Tier2Only:       true,
				Check:           true,
			})
			if err != nil {
				t.Fatalf("verify Tier 2 siblings for %s failed:\n%v", pkg, err)
			}
			if report.PackagesInspected != 1 {
				t.Fatalf("unexpected report for %s: %+v", pkg, report)
			}
		})
	}
}

func TestIdempotentRegenerationWithoutExistingAutogen(t *testing.T) {
	root := repoRoot(t)
	tmpRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpRoot, "go.mod"), []byte("module z.gfire.dev/gvx\n\ngo 1.27\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	samplePackages := []string{
		"pkg/sentry/fsimpl/tmpfs",
		"pkg/sentry/kernel/auth",
		"pkg/bpf",
	}

	for _, relPkg := range samplePackages {
		srcDir := filepath.Join(root, filepath.FromSlash(relPkg))
		dstDir := filepath.Join(tmpRoot, filepath.FromSlash(relPkg))
		if err := os.MkdirAll(dstDir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dstDir, err)
		}

		entries, err := os.ReadDir(srcDir)
		if err != nil {
			t.Fatalf("readdir %s: %v", srcDir, err)
		}
		wantAutogens := make(map[string][]byte)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			data, readErr := os.ReadFile(filepath.Join(srcDir, name))
			if readErr != nil {
				t.Fatalf("read %s: %v", name, readErr)
			}
			if strings.HasSuffix(name, "_state_autogen.go") {
				wantAutogens[name] = bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
				continue
			}
			if writeErr := os.WriteFile(filepath.Join(dstDir, name), data, 0o644); writeErr != nil {
				t.Fatalf("write %s: %v", name, writeErr)
			}
		}

		// Seed stale garbage into one autogen file to verify gostateify ignores *_state_autogen.go inputs.
		pkgBase := filepath.Base(dstDir)
		if err := os.WriteFile(filepath.Join(dstDir, pkgBase+"_state_autogen.go"), []byte("package broken // stale"), 0o644); err != nil {
			t.Fatalf("seed stale autogen: %v", err)
		}

		if _, err := stateify.Run(stateify.Options{
			RootDir:         tmpRoot,
			Packages:        []string{relPkg},
			PartitionByTier: true,
		}); err != nil {
			t.Fatalf("regenerate %s: %v", relPkg, err)
		}

		for name, want := range wantAutogens {
			got, readErr := os.ReadFile(filepath.Join(dstDir, name))
			if readErr != nil {
				t.Fatalf("missing regenerated %s/%s: %v", relPkg, name, readErr)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("regenerated %s/%s differs from golden upstream autogen", relPkg, name)
			}
		}
	}
}

func TestGeneratedStateSaveLoadRoundTrip(t *testing.T) {
	prevGraph := state.GraphEngineEnabled()
	t.Cleanup(func() {
		state.EnableGraphEngine(prevGraph)
	})

	for _, enableGraph := range []bool{true, false} {
		modeName := "legacy_engine"
		if enableGraph {
			modeName = "graph_engine"
		}
		t.Run(modeName, func(t *testing.T) {
			state.EnableGraphEngine(enableGraph)
			ctx := context.Background()

			orig := &testfixture.RootContainer{
				EmbeddedMeta:   testfixture.EmbeddedMeta{Version: 7},
				Count:          42,
				Title:          "checkpoint-alpha",
				Leaf:           &testfixture.LeafNode{Value: 9001},
				TransientCache: "ephemeral-do-not-save",
				MustBeZero:     0,
				AnyPayload:     testfixture.Payload{0xde, 0xad, 0xbe, 0xef},
			}
			orig.SetItems([]string{"one", "two", "three"})

			origIdent := &testfixture.IdentBox{Code: 11, Name: "ident-ok"}
			origXplat := &testfixture.XplatState{Seq: 99, Tag: "xplat-ok"}

			var buf bytes.Buffer
			if _, err := state.Save(ctx, &buf, orig); err != nil {
				t.Fatalf("state.Save RootContainer: %v", err)
			}
			if !slices.Equal(orig.SavedHookOrder, []string{"beforeSave"}) {
				t.Fatalf("beforeSave hook order = %v, want [beforeSave]", orig.SavedHookOrder)
			}

			var restored testfixture.RootContainer
			if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
				t.Fatalf("state.Load RootContainer: %v", err)
			}

			if restored.Version != 7 || restored.Count != 42 || restored.Title != "checkpoint-alpha" {
				t.Fatalf("unexpected scalar fields after load: %+v", restored)
			}
			if restored.TransientCache != "" {
				t.Fatalf("nosave field persisted: got %q, want empty", restored.TransientCache)
			}
			if !slices.Equal(restored.Items(), []string{"one", "two", "three"}) {
				t.Fatalf("custom value saver/loader items = %v, want [one two three]", restored.Items())
			}
			if restored.Leaf == nil || restored.Leaf.Value != 9001 || !restored.Leaf.LoadedReady {
				t.Fatalf("leaf node not restored properly: %+v", restored.Leaf)
			}
			if !restored.LeafWasReady {
				t.Fatal("state:\"wait\" violated: Leaf.afterLoad did not run before RootContainer.afterLoad")
			}
			gotPayload, ok := restored.AnyPayload.(testfixture.Payload)
			if !ok || !bytes.Equal(gotPayload, testfixture.Payload{0xde, 0xad, 0xbe, 0xef}) {
				t.Fatalf("registered non-struct interface payload = %#v, want deadbeef", restored.AnyPayload)
			}

			var identBuf bytes.Buffer
			if _, err := state.Save(ctx, &identBuf, origIdent); err != nil {
				t.Fatalf("state.Save IdentBox: %v", err)
			}
			var restoredIdent testfixture.IdentBox
			if _, err := state.Load(ctx, bytes.NewReader(identBuf.Bytes()), &restoredIdent); err != nil {
				t.Fatalf("state.Load IdentBox: %v", err)
			}
			if restoredIdent != *origIdent {
				t.Fatalf("IdentBox = %+v, want %+v", restoredIdent, *origIdent)
			}

			var xplatBuf bytes.Buffer
			if _, err := state.Save(ctx, &xplatBuf, origXplat); err != nil {
				t.Fatalf("state.Save XplatState: %v", err)
			}
			var restoredXplat testfixture.XplatState
			if _, err := state.Load(ctx, bytes.NewReader(xplatBuf.Bytes()), &restoredXplat); err != nil {
				t.Fatalf("state.Load XplatState: %v", err)
			}
			if restoredXplat.Seq != 99 || restoredXplat.Tag != "xplat-ok" || !restoredXplat.Restored {
				t.Fatalf("XplatState = %+v, want Seq=99 Tag=xplat-ok Restored=true", restoredXplat)
			}

			// Verify state:"zerovalue" rejects non-zero MustBeZero during state.Save.
			bad := &testfixture.RootContainer{MustBeZero: 5}
			var badBuf bytes.Buffer
			if _, err := state.Save(ctx, &badBuf, bad); err == nil {
				t.Fatal("expected state.Save to fail on non-zero state:\"zerovalue\" field, got nil")
			} else if !strings.Contains(err.Error(), "MustBeZero") {
				t.Fatalf("expected zerovalue error mentioning MustBeZero, got: %v", err)
			}
		})
	}
}

func TestPartitionByTierSharedAndTier1(t *testing.T) {
	root := repoRoot(t)
	tmpRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	writeTestFile(t, filepath.Join(tmpRoot, "go.mod"), "module example.com/testgvx\n\ngo 1.27.4\n")
	writeTestFile(t, filepath.Join(tmpRoot, "go.work"), fmt.Sprintf("go 1.27.4\n\nuse (\n\t%q\n\t%q\n)\n", tmpRoot, root))

	sharedDir := filepath.Join(tmpRoot, "pkg", "sharedsample")
	if err := os.MkdirAll(sharedDir, 0o755); err != nil {
		t.Fatalf("mkdir sharedDir: %v", err)
	}

	writeTestFile(t, filepath.Join(sharedDir, "core.go"), `package sharedsample

import "context"

type SharedID uint64

// +stateify savable
type CoreRecord struct {
	ID SharedID
}

func (c *CoreRecord) afterLoad(context.Context) {}
`)

	// 1. Verify cross-tier beforeSave on Tier 3 CoreRecord inside _xplat.go fails fast.
	writeTestFile(t, filepath.Join(sharedDir, "bad_hook_xplat.go"), `package sharedsample

func (c *CoreRecord) beforeSave() {}
`)
	if _, err := stateify.Run(stateify.Options{
		RootDir:         tmpRoot,
		Packages:        []string{"pkg/sharedsample"},
		PartitionByTier: true,
	}); err == nil || !strings.Contains(err.Error(), "cross-tier beforeSave hook on Tier 3 struct CoreRecord") {
		t.Fatalf("expected cross-tier hook rejection, got: %v", err)
	}
	if err := os.Remove(filepath.Join(sharedDir, "bad_hook_xplat.go")); err != nil {
		t.Fatal(err)
	}

	// 2. Verify narrower-constraint hook inside the same tier fails fast.
	writeTestFile(t, filepath.Join(sharedDir, "common_xplat.go"), `package sharedsample

// +stateify savable
type CommonXplat struct {
	Owner SharedID
}
`)
	writeTestFile(t, filepath.Join(sharedDir, "narrow_hook_xplat.go"), `//go:build windows

package sharedsample

import "context"

func (cx *CommonXplat) afterLoad(context.Context) {}
`)
	if _, err := stateify.Run(stateify.Options{
		RootDir:         tmpRoot,
		Packages:        []string{"pkg/sharedsample"},
		PartitionByTier: true,
	}); err == nil || !strings.Contains(err.Error(), "does not cover struct CommonXplat") {
		t.Fatalf("expected narrower-constraint hook rejection, got: %v", err)
	}
	if err := os.Remove(filepath.Join(sharedDir, "narrow_hook_xplat.go")); err != nil {
		t.Fatal(err)
	}

	// 3. Populate valid unconstrained + constrained _xplat.go, arch-split windows files, and darwin_arm64.
	writeTestFile(t, filepath.Join(sharedDir, "host_xplat.go"), `//go:build windows || darwin

package sharedsample

type HostCookie uint32

// +stateify savable
type HostXplat struct {
	Cookie HostCookie
	Owner  SharedID
}
`)
	writeTestFile(t, filepath.Join(sharedDir, "handle_windows.go"), `package sharedsample

// +stateify savable
type WinState struct {
	Handle uintptr
}
`)
	writeTestFile(t, filepath.Join(sharedDir, "regs_windows_amd64.go"), `package sharedsample

import "context"

type RegWord uint64

// +stateify savable
type ArchRegs struct {
	RAX RegWord
}

func (r *ArchRegs) afterLoad(context.Context) {}
`)
	writeTestFile(t, filepath.Join(sharedDir, "regs_windows_arm64.go"), `package sharedsample

type RegWord uint32

// +stateify savable
type ArchRegs struct {
	X0 RegWord
}
`)
	writeTestFile(t, filepath.Join(sharedDir, "port_darwin_arm64.go"), `package sharedsample

// +stateify savable
type MacState struct {
	Port uint32
}
`)

	if _, err := stateify.Run(stateify.Options{
		RootDir:         tmpRoot,
		Packages:        []string{"pkg/sharedsample"},
		PartitionByTier: true,
	}); err != nil {
		t.Fatalf("Run sharedsample: %v", err)
	}

	coreGen := readTestFile(t, filepath.Join(sharedDir, "sharedsample_state_autogen.go"))
	if strings.Contains(coreGen, "//go:build") || strings.Contains(coreGen, "// +build") {
		t.Fatalf("unexpected build tag in Tier 3 autogen:\n%s", coreGen)
	}
	if !strings.Contains(coreGen, "state.RegisterStruct((*CoreRecord)(nil))") {
		t.Fatalf("expected Tier 3 afterLoad hook to trigger RegisterStruct:\n%s", coreGen)
	}
	if strings.Contains(coreGen, "CommonXplat") || strings.Contains(coreGen, "HostXplat") || strings.Contains(coreGen, "WinState") {
		t.Fatalf("Tier 2 types leaked into Tier 3 autogen:\n%s", coreGen)
	}

	xplatUnconstrained := readTestFile(t, filepath.Join(sharedDir, "sharedsample_xplat_state_autogen.go"))
	if strings.Contains(xplatUnconstrained, "//go:build") {
		t.Fatalf("expected unconstrained sharedsample_xplat_state_autogen.go without build tag:\n%s", xplatUnconstrained)
	}
	if !strings.Contains(xplatUnconstrained, `"pkg/sharedsample.CommonXplat"`) || strings.Contains(xplatUnconstrained, "HostCookie") {
		t.Fatalf("unexpected unconstrained xplat autogen:\n%s", xplatUnconstrained)
	}

	xplatConstrained := readTestFile(t, filepath.Join(sharedDir, "sharedsample_xplat_darwin_windows_state_autogen.go"))
	if !strings.Contains(xplatConstrained, "//go:build windows || darwin\n") {
		t.Fatalf("expected //go:build windows || darwin in suffixed xplat autogen:\n%s", xplatConstrained)
	}
	if !strings.Contains(xplatConstrained, "SaveUint32(0, (*uint32)(&h.Cookie))") {
		t.Fatalf("expected scoped HostCookie uint32 cast in constrained xplat autogen:\n%s", xplatConstrained)
	}

	winGen := readTestFile(t, filepath.Join(sharedDir, "sharedsample_windows_state_autogen.go"))
	if !strings.Contains(winGen, "//go:build windows\n") {
		t.Fatalf("expected //go:build windows header:\n%s", winGen)
	}

	winAmd64Gen := readTestFile(t, filepath.Join(sharedDir, "sharedsample_windows_amd64_state_autogen.go"))
	if !strings.Contains(winAmd64Gen, "//go:build windows && amd64\n") || !strings.Contains(winAmd64Gen, "SaveUint64(0, (*uint64)(&r.RAX))") || !strings.Contains(winAmd64Gen, "state.RegisterStruct((*ArchRegs)(nil))") {
		t.Fatalf("unexpected windows_amd64 autogen:\n%s", winAmd64Gen)
	}

	winArm64Gen := readTestFile(t, filepath.Join(sharedDir, "sharedsample_windows_arm64_state_autogen.go"))
	if !strings.Contains(winArm64Gen, "//go:build windows && arm64\n") || !strings.Contains(winArm64Gen, "SaveUint32(0, (*uint32)(&a.X0))") || !strings.Contains(winArm64Gen, "state.RegisterNoHooks((*ArchRegs)(nil))") {
		t.Fatalf("unexpected windows_arm64 autogen (expected isolated RegWord=uint32 and no amd64 afterLoad leak):\n%s", winArm64Gen)
	}

	macArm64Gen := readTestFile(t, filepath.Join(sharedDir, "sharedsample_darwin_arm64_state_autogen.go"))
	if !strings.Contains(macArm64Gen, "//go:build darwin && arm64\n") {
		t.Fatalf("expected //go:build darwin && arm64 header:\n%s", macArm64Gen)
	}

	// 4. Verify Tier 1 package partitioning (pkg/ipset).
	tier1Dir := filepath.Join(tmpRoot, "pkg", "ipset")
	if err := os.MkdirAll(tier1Dir, 0o755); err != nil {
		t.Fatalf("mkdir tier1Dir: %v", err)
	}
	writeTestFile(t, filepath.Join(tier1Dir, "set.go"), `package ipset

// +stateify savable
type Set struct {
	Name string
}
`)
	writeTestFile(t, filepath.Join(tier1Dir, "set_darwin.go"), `package ipset

// +stateify savable
type darwinTable struct {
	Count int
}
`)
	if _, err := stateify.Run(stateify.Options{
		RootDir:         tmpRoot,
		Packages:        []string{"pkg/ipset"},
		PartitionByTier: true,
	}); err != nil {
		t.Fatalf("Run Tier 1 pkg/ipset: %v", err)
	}
	if !strings.Contains(readTestFile(t, filepath.Join(tier1Dir, "ipset_state_autogen.go")), `"pkg/ipset.Set"`) {
		t.Fatal("missing Set in ipset_state_autogen.go")
	}
	tier1Darwin := readTestFile(t, filepath.Join(tier1Dir, "ipset_darwin_state_autogen.go"))
	if !strings.Contains(tier1Darwin, "//go:build darwin\n") || !strings.Contains(tier1Darwin, `"pkg/ipset.darwinTable"`) {
		t.Fatalf("unexpected ipset_darwin_state_autogen.go:\n%s", tier1Darwin)
	}

	// 5. Compile both generated packages across linux/amd64, darwin/arm64, windows/amd64, and windows/arm64.
	targets := [][2]string{
		{"linux", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
		{"windows", "arm64"},
	}
	for _, tgt := range targets {
		cmd := exec.Command("go", "build", "./pkg/sharedsample", "./pkg/ipset")
		cmd.Dir = tmpRoot
		cmd.Env = append(os.Environ(),
			"GOOS="+tgt[0],
			"GOARCH="+tgt[1],
			"CGO_ENABLED=0",
			"GOWORK="+filepath.Join(tmpRoot, "go.work"),
		)
		if out, buildErr := cmd.CombinedOutput(); buildErr != nil {
			t.Fatalf("go build for %s/%s failed: %v\n%s", tgt[0], tgt[1], buildErr, out)
		}
	}

	// 6. Verify Tier2Only preserves Tier 3 autogen untouched while removing emptied Tier 2 files.
	customMarker := coreGen + "// untouched-tier3-marker\n"
	writeTestFile(t, filepath.Join(sharedDir, "sharedsample_state_autogen.go"), customMarker)
	if err := os.Remove(filepath.Join(sharedDir, "common_xplat.go")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(sharedDir, "host_xplat.go")); err != nil {
		t.Fatal(err)
	}
	rep, err := stateify.Run(stateify.Options{
		RootDir:         tmpRoot,
		Packages:        []string{"pkg/sharedsample"},
		PartitionByTier: true,
		Tier2Only:       true,
	})
	if err != nil {
		t.Fatalf("Run Tier2Only: %v", err)
	}
	if gotCore := readTestFile(t, filepath.Join(sharedDir, "sharedsample_state_autogen.go")); gotCore != customMarker {
		t.Fatal("Tier2Only modified Tier 3 sharedsample_state_autogen.go")
	}
	for _, removedName := range []string{"sharedsample_xplat_state_autogen.go", "sharedsample_xplat_darwin_windows_state_autogen.go"} {
		if _, statErr := os.Stat(filepath.Join(sharedDir, removedName)); !os.IsNotExist(statErr) {
			t.Fatalf("expected %s to be removed, statErr=%v, removed=%v", removedName, statErr, rep.FilesRemoved)
		}
	}
}

func TestStructTagValidationAndAuxAutogenScoping(t *testing.T) {
	tmpRoot := t.TempDir()
	writeTestFile(t, filepath.Join(tmpRoot, "go.mod"), "module z.gfire.dev/gvx\n\ngo 1.27\n")

	// 1. Verify undocumented state:"zero" and state:"manual" fail fast.
	for _, badTag := range []string{"zero", "manual"} {
		badDir := filepath.Join(tmpRoot, "pkg", "bad_"+badTag)
		if err := os.MkdirAll(badDir, 0o755); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(badDir, "bad.go"), fmt.Sprintf("package bad\n\n// +stateify savable\ntype S struct {\n\tF int `state:%q`\n}\n", badTag))
		_, err := stateify.Run(stateify.Options{
			RootDir:         tmpRoot,
			Packages:        []string{"pkg/bad_" + badTag},
			PartitionByTier: true,
		})
		if err == nil || !strings.Contains(err.Error(), "unsupported state struct tag") {
			t.Fatalf("expected unsupported state struct tag error for %q, got: %v", badTag, err)
		}
	}

	// 2. Verify auxiliary Tier 3 arch_x86_impl_state_autogen.go (amd64) does not suppress arm64 State.
	archDir := filepath.Join(tmpRoot, "pkg", "archsample")
	if err := os.MkdirAll(archDir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(archDir, "arch_x86_impl_state_autogen.go"), `// automatically generated by stateify.

//go:build amd64

package archsample

func (s *State) StateTypeName() string { return "pkg/archsample.State" }
`)
	writeTestFile(t, filepath.Join(archDir, "arch_amd64.go"), `package archsample

// +stateify savable
type State struct {
	RAX uint64
}
`)
	writeTestFile(t, filepath.Join(archDir, "arch_arm64.go"), `package archsample

// +stateify savable
type State struct {
	X0 uint64
}
`)

	if _, err := stateify.Run(stateify.Options{
		RootDir:         tmpRoot,
		Packages:        []string{"pkg/archsample"},
		PartitionByTier: true,
	}); err != nil {
		t.Fatalf("Run archsample: %v", err)
	}

	if _, err := os.Stat(filepath.Join(archDir, "archsample_amd64_state_autogen.go")); !os.IsNotExist(err) {
		t.Fatalf("expected amd64 State claimed by auxiliary autogen not to emit archsample_amd64_state_autogen.go")
	}
	arm64Gen := readTestFile(t, filepath.Join(archDir, "archsample_arm64_state_autogen.go"))
	if !strings.Contains(arm64Gen, "//go:build arm64\n") || !strings.Contains(arm64Gen, "SaveUint64(0, &s.X0)") {
		t.Fatalf("expected arm64 State to be emitted despite x86 auxiliary autogen:\n%s", arm64Gen)
	}
}

func TestCheckDetectsContentAndStaleDrift(t *testing.T) {
	tmpRoot := t.TempDir()
	writeTestFile(t, filepath.Join(tmpRoot, "go.mod"), "module z.gfire.dev/gvx\n\ngo 1.27\n")

	pkgDir := filepath.Join(tmpRoot, "pkg", "sample")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	writeTestFile(t, filepath.Join(pkgDir, "sample.go"), `package sample

// +stateify savable
type Entry struct {
	ID uint32
}
`)

	var stdout, stderr bytes.Buffer
	if err := runCLI([]string{"-root", tmpRoot, "-pkg", "pkg/sample"}, &stdout, &stderr); err != nil {
		t.Fatalf("initial generate failed: %v", err)
	}
	if err := runCLI([]string{"-root", tmpRoot, "-pkg", "pkg/sample", "-check"}, &stdout, &stderr); err != nil {
		t.Fatalf("clean verify failed: %v", err)
	}

	// 1. Corrupt content on disk and verify -check fails with a diff.
	autogenPath := filepath.Join(pkgDir, "sample_state_autogen.go")
	origBytes, err := os.ReadFile(autogenPath)
	if err != nil {
		t.Fatalf("read autogen: %v", err)
	}
	corrupted := strings.Replace(string(origBytes), `"ID"`, `"DriftedField"`, 1)
	writeTestFile(t, autogenPath, corrupted)

	err = runCLI([]string{"-root", tmpRoot, "-pkg", "pkg/sample", "-check"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected -check to fail on drifted content, got nil")
	}
	if !strings.Contains(err.Error(), "DriftedField") || !strings.Contains(err.Error(), "content mismatch") {
		t.Fatalf("expected diff mentioning DriftedField, got: %v", err)
	}

	// Verify CRLF line endings from Windows git checkouts pass -check cleanly.
	crlfBytes := bytes.ReplaceAll(origBytes, []byte("\n"), []byte("\r\n"))
	writeTestFile(t, autogenPath, string(crlfBytes))
	if err := runCLI([]string{"-root", tmpRoot, "-pkg", "pkg/sample", "-check"}, &stdout, &stderr); err != nil {
		t.Fatalf("CRLF-checked-out verify failed: %v", err)
	}

	// Restore clean file, then plant stale _xplat_state_autogen.go and suffixed _windows_amd64_state_autogen.go files.
	writeTestFile(t, autogenPath, string(origBytes))
	for _, staleName := range []string{"sample_xplat_state_autogen.go", "sample_windows_amd64_state_autogen.go"} {
		stalePath := filepath.Join(pkgDir, staleName)
		writeTestFile(t, stalePath, "// automatically generated by stateify.\n\npackage sample\n")

		err = runCLI([]string{"-root", tmpRoot, "-pkg", "pkg/sample", "-check"}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "stale file exists on disk") {
			t.Fatalf("expected stale file error for %s, got: %v", staleName, err)
		}
		if rmErr := os.Remove(stalePath); rmErr != nil {
			t.Fatal(rmErr)
		}
	}
}

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readTestFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(data)
}
