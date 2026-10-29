package main

import (
	"errors"
	"strings"
	"testing"
)

const upstreamGoMod = `module gvisor.dev/gvisor

go 1.27.2

require (
	golang.org/x/mod v0.41.0
	golang.org/x/sys v0.48.0
	github.com/shared/lib v1.5.0
)
`

func TestMergeGoModKeepsLocalPinsAndTakesNewerUpstream(t *testing.T) {
	t.Parallel()

	local := `module z.gfire.dev/gvx

go 1.27.2

require (
	github.com/shared/lib v1.9.0
	golang.org/x/arch v0.32.0 // indirect
	golang.org/x/mod v0.40.0
	golang.org/x/sys v0.48.0
	golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f
)

replace golang.org/x/sys => ./internal/xsys
`
	out, err := MergeGoMod([]byte(upstreamGoMod), []byte(local))
	if err != nil {
		t.Fatalf("MergeGoMod: %v", err)
	}
	got := string(out)
	for _, want := range []string{
		"module z.gfire.dev/gvx",
		"github.com/shared/lib v1.9.0",
		"golang.org/x/arch v0.32.0",
		"golang.org/x/mod v0.41.0",
		"golang.zx2c4.com/wireguard v0.0.0-20261006164505-2631ce99a06f",
		"replace golang.org/x/sys => ./internal/xsys",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("merged go.mod lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "gvisor.dev/gvisor") {
		t.Errorf("merged go.mod kept the upstream module path:\n%s", got)
	}
}

func TestMergeGoModTakesXArchVersionFromUpstreamWhenListed(t *testing.T) {
	t.Parallel()

	up := upstreamGoMod + "\nrequire golang.org/x/arch v0.40.0\n"
	local := "module z.gfire.dev/gvx\n\ngo 1.27.2\n\nrequire golang.org/x/arch v0.32.0\n"
	out, err := MergeGoMod([]byte(up), []byte(local))
	if err != nil {
		t.Fatalf("MergeGoMod: %v", err)
	}
	if !strings.Contains(string(out), "golang.org/x/arch v0.40.0") || strings.Contains(string(out), "v0.32.0") {
		t.Fatalf("x/arch pin not derived from upstream:\n%s", out)
	}
}

func TestMergeGoModNeverInventsXArchPin(t *testing.T) {
	t.Parallel()

	if _, err := MergeGoMod([]byte(upstreamGoMod), []byte("module z.gfire.dev/gvx\n\ngo 1.27.2\n")); !errors.Is(err, errMissingXArch) {
		t.Fatalf("MergeGoMod err = %v, want %v", err, errMissingXArch)
	}
	if _, err := MergeGoMod([]byte(upstreamGoMod), nil); !errors.Is(err, errMissingXArch) {
		t.Fatalf("MergeGoMod without local file err = %v, want %v", err, errMissingXArch)
	}
}

func TestMergeGoModUsesGvxModulePathForFreshTree(t *testing.T) {
	t.Parallel()

	up := upstreamGoMod + "\nrequire golang.org/x/arch v0.32.0\n"
	out, err := MergeGoMod([]byte(up), nil)
	if err != nil {
		t.Fatalf("MergeGoMod: %v", err)
	}
	if !strings.Contains(string(out), "module "+targetModulePath) {
		t.Fatalf("fresh go.mod has the wrong module path:\n%s", out)
	}
}

func TestMergeGoModRaisesGoDirectiveToTheNewerOne(t *testing.T) {
	t.Parallel()

	up := strings.Replace(upstreamGoMod, "go 1.27.2", "go 1.28.0", 1) + "\nrequire golang.org/x/arch v0.32.0\n"
	out, err := MergeGoMod([]byte(up), []byte("module z.gfire.dev/gvx\n\ngo 1.27.2\n\nrequire golang.org/x/arch v0.32.0\n"))
	if err != nil {
		t.Fatalf("MergeGoMod: %v", err)
	}
	if !strings.Contains(string(out), "go 1.28.0") {
		t.Fatalf("go directive not raised:\n%s", out)
	}
}

func TestMergeGoModRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	if _, err := MergeGoMod([]byte("module"), nil); err == nil {
		t.Fatal("malformed upstream go.mod must fail")
	}
	if _, err := MergeGoMod([]byte(upstreamGoMod), []byte("require (")); err == nil {
		t.Fatal("malformed local go.mod must fail")
	}
}

func TestMergeGoSumIsSortedUnion(t *testing.T) {
	t.Parallel()

	got := string(MergeGoSum([]byte("b v1 h1:b\na v1 h1:a\n"), []byte("a v1 h1:a\nc v1 h1:c\n\n")))
	if got != "a v1 h1:a\nb v1 h1:b\nc v1 h1:c\n" {
		t.Fatalf("MergeGoSum = %q", got)
	}
	if MergeGoSum(nil, nil) != nil {
		t.Fatal("empty inputs must yield nil")
	}
}
