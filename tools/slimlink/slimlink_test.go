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

package main

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestPatchRejectsMissingAnchor(t *testing.T) {
	if _, err := patchDeadcodeSource("package ld\n"); err == nil {
		t.Fatal("patchDeadcodeSource succeeded on empty package, want anchor error")
	}
}

func TestPatchesApplyCleanlyToActiveGOROOT(t *testing.T) {
	goroot, err := goEnvValue("go", "", "GOROOT")
	if err != nil {
		t.Fatalf("go env GOROOT: %v", err)
	}
	deadcodePath := filepath.Join(goroot, "src", "cmd", "link", "internal", "ld", "deadcode.go")
	deadcodeRaw, err := os.ReadFile(deadcodePath)
	if err != nil {
		t.Fatalf("read deadcode.go: %v", err)
	}
	deadcodePatched, err := patchDeadcodeSource(string(deadcodeRaw))
	if err != nil {
		t.Fatalf("patchDeadcodeSource: %v", err)
	}
	fset := token.NewFileSet()
	if _, err := parser.ParseFile(fset, "deadcode.go", deadcodePatched, 0); err != nil {
		t.Fatalf("patched deadcode.go failed Go parse: %v", err)
	}
}

func TestJoinToolexecArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		want    string
		wantErr bool
	}{
		{
			name: "plain",
			args: []string{"/bin/slimlink", "-fix-reflect-methods=true"},
			want: "/bin/slimlink -fix-reflect-methods=true",
		},
		{
			name: "spaces and tabs",
			args: []string{"/dir with space/slimlink", "a\tb", "c\rd"},
			want: `'/dir with space/slimlink' 'a	b' 'c` + "\r" + `d'`,
		},
		{
			name: "single quote uses double quotes",
			args: []string{"/opt/a'b/slimlink"},
			want: `"/opt/a'b/slimlink"`,
		},
		{
			name: "double quote uses single quotes",
			args: []string{`/tmp/a"b/slimlink`},
			want: `'/tmp/a"b/slimlink'`,
		},
		{
			name: "empty arg",
			args: []string{"cmd", ""},
			want: "cmd ''",
		},
		{
			name:    "both quote types rejected",
			args:    []string{`a'b"c`},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := joinToolexecArgs(tc.args)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("joinToolexecArgs(%q) = %q, want error", tc.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("joinToolexecArgs(%q) unexpected error: %v", tc.args, err)
			}
			if got != tc.want {
				t.Fatalf("joinToolexecArgs(%q) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

func TestBuildGoBuildArgsAndValidation(t *testing.T) {
	cases := []struct {
		name      string
		in        []string
		wantDir   string
		wantArgs  []string
		wantError bool
	}{
		{
			name:     "no -C",
			in:       []string{"-trimpath", "./cmd/app"},
			wantArgs: []string{"build", "-toolexec=TX", "-trimpath", "./cmd/app"},
		},
		{
			name:     "separate -C",
			in:       []string{"-C", "/repo", "-trimpath", "./cmd/app"},
			wantDir:  "/repo",
			wantArgs: []string{"build", "-C", "/repo", "-toolexec=TX", "-trimpath", "./cmd/app"},
		},
		{
			name:     "equals --C",
			in:       []string{"--C=/repo", "-o", "out", "."},
			wantDir:  "/repo",
			wantArgs: []string{"build", "--C=/repo", "-toolexec=TX", "-o", "out", "."},
		},
		{
			name:      "rejects conflicting -toolexec",
			in:        []string{"-C", "/repo", "-toolexec=other", "."},
			wantError: true,
		},
		{
			name:      "rejects conflicting --toolexec after space-separated flag",
			in:        []string{"-o", "out", "--toolexec", "other", "."},
			wantError: true,
		},
		{
			name:     "allows non-flag arg after --",
			in:       []string{"-trimpath", "--", "-toolexec"},
			wantArgs: []string{"build", "-toolexec=TX", "-trimpath", "--", "-toolexec"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := validateAndExtractChangeDir(tc.in)
			if tc.wantError {
				if err == nil {
					t.Fatalf("validateAndExtractChangeDir(%q) succeeded, want error", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateAndExtractChangeDir(%q): %v", tc.in, err)
			}
			if dir != tc.wantDir {
				t.Fatalf("changeDir = %q, want %q", dir, tc.wantDir)
			}
			got := buildGoBuildArgs("TX", tc.in)
			if !reflect.DeepEqual(got, tc.wantArgs) {
				t.Fatalf("buildGoBuildArgs = %q, want %q", got, tc.wantArgs)
			}
		})
	}
}

func TestSlimBuildProducesSmallerRunnableBinary(t *testing.T) {
	tmp := t.TempDir()

	// Build slimlink binary itself so -toolexec points to a real executable.
	slimExe := filepath.Join(tmp, "slimlink")
	if runtime.GOOS == "windows" {
		slimExe += ".exe"
	}
	buildSelf := exec.Command("go", "build", "-o", slimExe, ".")
	if out, err := buildSelf.CombinedOutput(); err != nil {
		t.Fatalf("build slimlink: %v\n%s", err, out)
	}

	// Standalone probe exercising:
	// - dead-method elimination with an embedded reflect.Value wrapper and
	//   constant MethodByName("Methods")
	// - intact runtime.Caller file/line and runtime.FuncForPC names
	// - concurrent GC stack scanning under GOGC=5
	// - reflect.MakeFunc and MethodByName().Interface() across GC
	// - nil value-receiver wrapper panicwrap recovery via fmt.Sprint
	// - inlined helper inside deferwrap calling recover() (must return nil)
	// - direct defer recover() and bounds panic recovery
	progDir := filepath.Join(tmp, "probe")
	if err := os.MkdirAll(progDir, 0o755); err != nil {
		t.Fatal(err)
	}
	goMod := "module slimprobe\n\ngo 1.24\n"
	if err := os.WriteFile(filepath.Join(progDir, "go.mod"), []byte(goMod), 0o600); err != nil {
		t.Fatal(err)
	}
	probeSrc := `package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
)

type payload struct {
	Name  string ` + "`json:\"name\"`" + `
	Count int    ` + "`json:\"count\"`" + `
}

type valStringer struct{ label string }

func (v valStringer) String() string { return v.label }

type embeddedValue struct {
	reflect.Value
}

type serviceLike struct{ n int }

func (s serviceLike) Methods() int { return s.n }
func (s serviceLike) UnusedExportedA(x int) string {
	return fmt.Sprintf("unused-a-%d-%d", s.n, x)
}
func (s serviceLike) UnusedExportedB(x int) string {
	return fmt.Sprintf("unused-b-%d-%d", s.n, x)
}

func recurse(n int) int {
	var pad [1024]byte
	pad[0] = byte(n)
	if n <= 0 {
		runtime.GC()
		return int(pad[0])
	}
	return int(pad[0]) + recurse(n-1)
}

func recoverDirect() (recovered string) {
	defer func() {
		if r := recover(); r != nil {
			recovered = fmt.Sprint(r)
		}
	}()
	panic("expected-panic")
}

//go:noinline
func recoverLeaf(out *any) {
	*out = recover()
}

// Intentionally small so the compiler inlines it into deferwrap.
func inlinedMid(out *any) {
	recoverLeaf(out)
}

func verifyInlinedDeferDoesNotRecover() {
	var innerRecovered any = "sentinel"
	var outerRecovered any
	func() {
		defer func() { outerRecovered = recover() }()
		func() {
			defer inlinedMid(&innerRecovered)
			panic("must-propagate")
		}()
	}()
	if innerRecovered != nil {
		panic(fmt.Sprintf("inlinedMid recovered %v, want nil", innerRecovered))
	}
	if outerRecovered != "must-propagate" {
		panic(fmt.Sprintf("outer recovered %v, want must-propagate", outerRecovered))
	}
}

func verifyBoundsPanic() {
	var got any
	func() {
		defer func() { got = recover() }()
		s := make([]int, 2)
		idx := 5
		_ = s[idx]
	}()
	if got == nil {
		panic("bounds panic not recovered")
	}
}

func verifyReflectStubsAcrossGC() int {
	fnType := reflect.TypeOf((func(*int) int)(nil))
	made := reflect.MakeFunc(fnType, func(args []reflect.Value) []reflect.Value {
		recurse(48)
		p := args[0].Interface().(*int)
		return []reflect.Value{reflect.ValueOf(*p + 1)}
	}).Interface().(func(*int) int)
	x := 41
	a := made(&x)

	var iface any = serviceLike{n: 7}
	ev := embeddedValue{Value: reflect.ValueOf(iface)}
	var box any = ev // marks embeddedValue <UsedInIface>
	_ = box
	mv := ev.MethodByName("Methods").Interface().(func() int)
	b := mv()
	return a + b
}

func verifyConcurrentGCStress() {
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for iter := 0; iter < 6; iter++ {
				buf := make([][]byte, 64)
				for i := range buf {
					buf[i] = make([]byte, 512)
				}
				_ = recurse(32)
				_ = len(buf)
			}
		}(g)
	}
	wg.Wait()
}

func main() {
	// Exercise nil pointer value-receiver wrapper (runtime.panicwrap and fmt recovery).
	var nilStr fmt.Stringer = (*valStringer)(nil)
	nilOut := fmt.Sprint(nilStr)
	if nilOut != "<nil>" {
		panic("unexpected nil wrapper output: " + nilOut)
	}

	verifyInlinedDeferDoesNotRecover()
	verifyBoundsPanic()
	reflectSum := verifyReflectStubsAcrossGC()
	verifyConcurrentGCStress()

	sum := recurse(64)
	rec := recoverDirect()

	raw, err := json.Marshal(payload{Name: "ok", Count: reflectSum + sum})
	if err != nil {
		panic(err)
	}
	pc, file, line, ok := runtime.Caller(0)
	fn := runtime.FuncForPC(pc)
	if !ok || fn == nil || fn.Name() != "main.main" || filepath.Base(file) != "main.go" || line <= 0 {
		panic(fmt.Sprintf("unexpected Caller/FuncForPC: ok=%v fn=%v file=%q line=%d", ok, fn, file, line))
	}
	fmt.Printf("json=%s rec=%s file=%s\n", raw, rec, filepath.Base(file))
}
`
	if err := os.WriteFile(filepath.Join(progDir, "main.go"), []byte(probeSrc), 0o600); err != nil {
		t.Fatal(err)
	}

	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	baseEnv := replaceEnv(os.Environ(), map[string]string{"GOWORK": "off"})

	// 1. Compare stripped stock vs slim binary (using a relative -cache-dir to test Abs resolution).
	stockBin := filepath.Join(tmp, "probe-stock"+ext)
	slimBin := filepath.Join(tmp, "probe-slim"+ext)

	stockCmd := exec.Command("go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", stockBin, ".")
	stockCmd.Dir = progDir
	stockCmd.Env = baseEnv
	if out, err := stockCmd.CombinedOutput(); err != nil {
		t.Fatalf("stock go build: %v\n%s", err, out)
	}

	slimCmd := exec.Command(slimExe, "-cache-dir=./relcache", "--", "-trimpath", "-ldflags=-s -w -buildid=", "-o", slimBin, ".")
	slimCmd.Dir = progDir
	slimCmd.Env = baseEnv
	if out, err := slimCmd.CombinedOutput(); err != nil {
		t.Fatalf("slimlink build: %v\n%s", err, out)
	}

	stockInfo, err := os.Stat(stockBin)
	if err != nil {
		t.Fatal(err)
	}
	slimInfo, err := os.Stat(slimBin)
	if err != nil {
		t.Fatal(err)
	}
	if slimInfo.Size() >= stockInfo.Size() {
		t.Fatalf("slim binary (%d B) is not smaller than stock stripped binary (%d B)", slimInfo.Size(), stockInfo.Size())
	}

	// Execute the slim binary under aggressive GC (GOGC=5) and verify full traceback metadata remains intact.
	runCmd := exec.Command(slimBin)
	runCmd.Env = append(os.Environ(), "GOGC=5")
	runOut, err := runCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("slim binary execution failed: %v\n%s", err, runOut)
	}
	got := strings.TrimSpace(string(runOut))
	want := `json={"name":"ok","count":2129} rec=expected-panic file=main.go`
	if got != want {
		t.Fatalf("slim binary output = %q, want %q", got, want)
	}

	// 2. Verify deadcode DCE on unstripped binaries so go tool nm must succeed
	// and detect UnusedExportedA before vs after -fix-reflect-methods.
	dceOffBin := filepath.Join(tmp, "probe-dce-off"+ext)
	dceOnBin := filepath.Join(tmp, "probe-dce-on"+ext)

	dceOffCmd := exec.Command(slimExe, "-cache-dir=./relcache", "-fix-reflect-methods=false", "--", "-o", dceOffBin, ".")
	dceOffCmd.Dir = progDir
	dceOffCmd.Env = baseEnv
	if out, err := dceOffCmd.CombinedOutput(); err != nil {
		t.Fatalf("slimlink dce-off build: %v\n%s", err, out)
	}
	dceOnCmd := exec.Command(slimExe, "-cache-dir=./relcache", "-fix-reflect-methods=true", "--", "-o", dceOnBin, ".")
	dceOnCmd.Dir = progDir
	dceOnCmd.Env = baseEnv
	if out, err := dceOnCmd.CombinedOutput(); err != nil {
		t.Fatalf("slimlink dce-on build: %v\n%s", err, out)
	}

	nmOff, err := exec.Command("go", "tool", "nm", dceOffBin).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm dce-off: %v\n%s", err, nmOff)
	}
	if !strings.Contains(string(nmOff), "UnusedExportedA") {
		t.Fatalf("expected UnusedExportedA to be retained when -fix-reflect-methods=false")
	}

	nmOn, err := exec.Command("go", "tool", "nm", dceOnBin).CombinedOutput()
	if err != nil {
		t.Fatalf("go tool nm dce-on: %v\n%s", err, nmOn)
	}
	if strings.Contains(string(nmOn), "UnusedExportedA") {
		t.Fatalf("slim binary retained UnusedExportedA despite -fix-reflect-methods=true")
	}
}
