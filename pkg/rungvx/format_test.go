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
	"encoding/json"
	"math"
	"strings"
	"testing"
	stdtemplate "text/template"
	"time"
)

type embeddedMeta struct {
	EmbeddedTag string
}

type sampleFormatConfig struct {
	Cmd        []string            `json:"Cmd"`
	Labels     map[string]string   `json:"Labels"`
	WorkingDir string              `json:"WorkingDir"`
	Ports      map[string]struct{} `json:"Ports"`
}

type sampleFormatRow struct {
	embeddedMeta
	ID         string             `json:"ID"`
	Name       string             `json:"Name"`
	Count      int                `json:"Count"`
	ZeroCount  int                `json:"ZeroCount"`
	Score      float64            `json:"Score"`
	NaNVal     float64            `json:"-"`
	BigUint    uint64             `json:"-"`
	Active     bool               `json:"Active"`
	Created    time.Time          `json:"Created"`
	Config     sampleFormatConfig `json:"Config"`
	Ptr        *sampleFormatConfig
	NilPtr     *sampleFormatConfig
	StrPtr     *string
	Matrix     [][]string
	Nested     map[string][]string
	AnyMap     map[string]any
	EmptySlice []string
	NilSlice   []string
	EmptyMap   map[string]string
	NilMap     map[string]string
	NilMap2    map[string]string
	FixedArr   [2]string
	ChanVal    chan int `json:"-"`
	ChanRange  chan int `json:"-"`
	unexport   string
}

var stdFormatFuncMap = stdtemplate.FuncMap{
	"json": func(v any) (string, error) {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return "", err
		}
		return strings.TrimSuffix(buf.String(), "\n"), nil
	},
	"lower": strings.ToLower,
	"upper": strings.ToUpper,
	"join":  strings.Join,
	"split": strings.Split,
	"truncate": func(s string, maxLen int) string {
		if maxLen <= 0 {
			return ""
		}
		runes := []rune(s)
		if len(runes) <= maxLen {
			return s
		}
		return string(runes[:maxLen])
	},
}

func evalStdTemplate(spec string, data any) (string, error) {
	tmpl, err := stdtemplate.New("format").Funcs(stdFormatFuncMap).Option("missingkey=error").Parse(spec)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func newSampleFormatRow() sampleFormatRow {
	created := time.Date(2026, 5, 1, 12, 30, 0, 0, time.UTC)
	strVal := "hello-ptr"
	ch := make(chan int, 3)
	ch <- 10
	ch <- 20
	ch <- 30
	close(ch)
	return sampleFormatRow{
		embeddedMeta: embeddedMeta{EmbeddedTag: "emb-v1"},
		ID:           "sha256:abcdef123456",
		Name:         "Alpha-Beta",
		Count:        3,
		Score:        2.5,
		NaNVal:       math.NaN(),
		BigUint:      math.MaxUint64,
		Active:       true,
		Created:      created,
		Config: sampleFormatConfig{
			Cmd:        []string{"/bin/sh", "-c", "echo hi"},
			Labels:     map[string]string{"env": "prod", "app": "web", "org.opencontainers.image.version": "1.0"},
			WorkingDir: "/workspace",
			Ports:      map[string]struct{}{"80/tcp": {}},
		},
		Ptr:        &sampleFormatConfig{WorkingDir: "/ptr"},
		StrPtr:     &strVal,
		Matrix:     [][]string{{"r0c0", "r0c1"}, {"r1c0", "r1c1"}},
		Nested:     map[string][]string{"items": {"x", "y"}},
		AnyMap:     map[string]any{"k": "env", "empty": nil},
		EmptySlice: []string{},
		EmptyMap:   map[string]string{},
		FixedArr:   [2]string{"a0", "a1"},
		ChanVal:    make(chan int),
		ChanRange:  ch,
		unexport:   "secret",
	}
}

func TestFormatTemplateParityWithStdlib(t *testing.T) {
	specs := []struct {
		name string
		spec string
	}{
		{"nested fields and stringer", `{{.ID}} {{.Config.WorkingDir}} {{.Ptr.WorkingDir}} {{.Created}}`},
		{"embedded struct field", `{{.EmbeddedTag}}`},
		{"time methods", `{{.Created.Format "2006-01-02"}}|{{.Created.UTC.Unix}}|{{.Created.UnixMilli}}|{{.Created.UnixNano}}|{{.Created.IsZero}}`},
		{"pointer printing", `{{.StrPtr}}|{{.Ptr}}`},
		{"nil interface map entry print", `{{index .AnyMap "empty"}}`},
		{"custom functions and pipelines", `{{truncate (.Name | lower) 5}}|{{.Name | lower | upper}}|{{join .Config.Cmd ","}}|{{join (split .Name "-") "_"}}`},
		{"truncate utf8 and non-positive", `{{truncate "가나다라" 2}}|{{truncate "abc" 0}}|{{truncate "abc" -1}}`},
		{"json function", `{{json .Config.Cmd}}`},
		{"html js urlquery", `{{html "<b>&"}}|{{js "a\"<b"}}|{{urlquery "a b&c"}}`},
		{"if else if else and boolean ops", `{{if not .Active}}a{{else if gt .Count 2}}b{{else}}c{{end}}|{{if and .Active (gt .Count 2) (eq .Name "other" "Alpha-Beta")}}yes{{else}}no{{end}}|{{if or false (not .Active)}}bad{{else}}ok{{end}}`},
		{"short-circuit avoids error", `{{and false .NilPtr.WorkingDir}}|{{or true .NilPtr.WorkingDir}}`},
		{"integral float literals", `{{printf "%.2f" 1.0}}|{{gt .Score 1.0}}|{{eq .Score 2.5}}|{{lt 0.0 .Score}}`},
		{"nan comparisons", `{{lt .NaNVal 1.0}}|{{le .NaNVal .NaNVal}}|{{gt .NaNVal 1.0}}|{{ge .NaNVal 1.0}}|{{eq .NaNVal .NaNVal}}`},
		{"nil slice and nil map eq", `{{eq .NilSlice nil}}|{{eq .NilMap nil}}|{{eq .NilMap .NilMap2}}|{{eq .NilSlice .Config.Cmd}}|{{eq .NilMap .Config.Labels}}|{{eq .Config.Labels nil}}|{{eq .Ptr .Ptr}}|{{eq .Ptr .NilPtr}}`},
		{"pointer len slice printf", `{{len .StrPtr}}|{{slice .StrPtr 0 5}}|{{printf "%T" .StrPtr}}`},
		{"chain method arg uses outer dot", `{{(.Created).Format .Name}}`},
		{"with else and variable bindings", `{{with $c := .Config}}{{$c.WorkingDir}}:{{$c.Labels.app}}{{end}}|{{with .NilPtr}}bad{{else}}fallback{{end}}`},
		{"variable reassignment in range", `{{$acc := ""}}{{range .Config.Cmd}}{{$acc = printf "%s|%s" $acc .}}{{end}}{{$acc}}`},
		{"range slice with break continue", `{{range $i, $v := .Config.Cmd}}{{if eq $i 1}}{{continue}}{{end}}{{$i}}={{$v}};{{end}}`},
		{"nested range break inner only", `{{range $r := .Matrix}}[{{range $c := $r}}{{$c}}{{break}}{{end}}]{{end}}`},
		{"range map sorted keys", `{{range $k, $v := .Config.Labels}}{{$k}}={{$v}};{{end}}`},
		{"range int single var", `{{range $i := .Count}}{{$i}},{{end}}`},
		{"range else on empty collections", `{{range .EmptySlice}}x{{else}}es{{end}}|{{range .NilSlice}}x{{else}}ns{{end}}|{{range .EmptyMap}}x{{else}}em{{end}}|{{range .NilMap}}x{{else}}nm{{end}}|{{range .ZeroCount}}x{{else}}z{{end}}`},
		{"range closed buffered channel", `{{range .ChanRange}}{{.}},{{end}}`},
		{"whitespace trimming", `  {{- .Name -}}  `},
		{"multi-index lookups", `{{index .Matrix 1 0}}|{{index .Nested "items" 1}}|{{index .Config.Labels (index .AnyMap "k")}}`},
		{"index missing map key returns zero", `[{{index .Config.Labels "missing"}}]|{{index .Config.Labels "org.opencontainers.image.version"}}`},
		{"slice string and slice", `{{slice .ID 0 6}}|{{slice .ID 7 13}}|{{join (slice .Config.Cmd 1 3) " "}}`},
		{"define template and block", `{{define "item"}}[{{.Name}}]{{end}}{{template "item" .}}|{{block "hdr" .}}<{{.ID}}>{{end}}`},
		{"parenthesized chain", `{{(.Config).WorkingDir}}`},
		{"print println pipeline printf", `{{print .Name .Count}}|{{println .Name .Count}}|{{.Name | printf "<%s>"}}`},
		// Error cases verified against stdlib error presence.
		{"syntax error", `{{.ID`},
		{"unknown function", `{{bogus .ID}}`},
		{"missing struct field", `{{.NoSuchField}}`},
		{"unexported struct field", `{{.unexport}}`},
		{"missing map key via dot", `{{.Config.Labels.missing}}`},
		{"nil pointer dereference", `{{.NilPtr.WorkingDir}}`},
		{"index int key on string map", `{{index .Config.Labels 65}}`},
		{"index out of bounds", `{{index .Config.Cmd 99}}`},
		{"slice unaddressable array", `{{slice .FixedArr 0 1}}`},
		{"slice 3-index string", `{{slice .ID 0 3 6}}`},
		{"ordered compare with nil", `{{lt nil 1}}`},
		{"eq pointer with int", `{{eq .Ptr 5}}`},
		{"nil as command", `{{nil}}`},
		{"print chan", `{{.ChanVal}}`},
		{"range int two vars", `{{range $i, $v := .Count}}{{$i}}{{end}}`},
		{"recursive template depth limit", `{{define "r"}}{{template "r" .}}{{end}}{{template "r" .}}`},
	}

	for _, tc := range specs {
		t.Run(tc.name, func(t *testing.T) {
			stdOut, stdErr := evalStdTemplate(tc.spec, newSampleFormatRow())

			tmpl, parseErr := parseFormatTemplate(tc.spec)
			var gotBuf bytes.Buffer
			var gotErr error
			if parseErr != nil {
				gotErr = parseErr
			} else {
				gotErr = tmpl.Execute(&gotBuf, newSampleFormatRow())
			}

			if (stdErr != nil) != (gotErr != nil) {
				t.Fatalf("error mismatch for %q:\n  stdlib: out=%q err=%v\n  custom: out=%q err=%v", tc.spec, stdOut, stdErr, gotBuf.String(), gotErr)
			}
			if stdErr == nil && gotBuf.String() != stdOut {
				t.Fatalf("output mismatch for %q:\n  got:  %q\n  want: %q", tc.spec, gotBuf.String(), stdOut)
			}
		})
	}
}

func FuzzFormatTemplateParityWithStdlib(f *testing.F) {
	seeds := []string{
		`{{.ID}}`,
		`{{.Name | lower | upper}}`,
		`{{if and .Active (gt .Count 1)}}{{.Config.WorkingDir}}{{else}}no{{end}}`,
		`{{range $k, $v := .Config.Labels}}{{$k}}={{$v}};{{end}}`,
		`{{index .Matrix 1 0}}`,
		`{{slice .ID 0 6}}`,
		`{{eq .NilSlice nil}}`,
		`{{with $c := .Config}}{{$c.WorkingDir}}{{end}}`,
		`{{printf "%s:%d" .Name .Count}}`,
		`{{block "b" .}}[{{.EmbeddedTag}}]{{end}}`,
		`{{and false .NilPtr.WorkingDir}}`,
		`{{truncate .Name 4}}`,
		`{{json .Config.Cmd}}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, spec string) {
		if len(spec) > 256 {
			return
		}
		// Exclude documented intentional differences (call builtin, arbitrary
		// time.Time methods beyond the explicit read-only set, and large
		// integer range loops that could allocate unbounded output).
		if strings.Contains(spec, "call") || strings.Contains(spec, "Created.") || strings.Contains(spec, "Created).") ||
			strings.Contains(spec, "range") || strings.Contains(spec, "ChanVal") {
			return
		}
		row := newSampleFormatRow()
		stdOut, stdErr := evalStdTemplate(spec, row)

		tmpl, parseErr := parseFormatTemplate(spec)
		var gotBuf bytes.Buffer
		var gotErr error
		if parseErr != nil {
			gotErr = parseErr
		} else {
			gotErr = tmpl.Execute(&gotBuf, row)
		}

		if (stdErr != nil) != (gotErr != nil) {
			t.Fatalf("error mismatch for %q:\n  stdlib: out=%q err=%v\n  custom: out=%q err=%v", spec, stdOut, stdErr, gotBuf.String(), gotErr)
		}
		if stdErr == nil && gotBuf.String() != stdOut {
			t.Fatalf("output mismatch for %q:\n  got:  %q\n  want: %q", spec, gotBuf.String(), stdOut)
		}
	})
}

func TestFormatTemplateUnsignedOverflowAndModes(t *testing.T) {
	row := sampleFormatRow{
		ID:      "id1",
		BigUint: math.MaxUint64,
	}
	var errBuf bytes.Buffer
	if usageErr, writeErr := renderSingleFormat(&errBuf, `{{truncate "abc" .BigUint}}`, row, nil); usageErr == nil || writeErr != nil {
		t.Fatalf("overflow truncate: usageErr=%v writeErr=%v, want non-nil usageErr", usageErr, writeErr)
	}

	var listBuf bytes.Buffer
	rows := []sampleFormatRow{
		{ID: "short", Name: "first"},
		{ID: "longer-id", Name: "second"},
	}
	if usageErr, writeErr := renderListFormat(&listBuf, `table {{.ID}}\t{{.Name}}`, rows, nil); usageErr != nil || writeErr != nil {
		t.Fatalf("table render failed: usage=%v write=%v", usageErr, writeErr)
	}
	lines := strings.Split(strings.TrimSpace(listBuf.String()), "\n")
	if len(lines) != 2 || strings.Contains(listBuf.String(), `\t`) {
		t.Fatalf("unexpected table output: %q", listBuf.String())
	}
	if strings.Index(lines[0], "first") != strings.Index(lines[1], "second") {
		t.Fatalf("table columns not aligned:\n%s", listBuf.String())
	}

	var inspectBuf bytes.Buffer
	if usageErr, writeErr := renderInspectFormat(&inspectBuf, "json", rows); usageErr != nil || writeErr != nil {
		t.Fatalf("inspect json failed: usage=%v write=%v", usageErr, writeErr)
	}
	var decoded []sampleFormatRow
	if err := json.Unmarshal(inspectBuf.Bytes(), &decoded); err != nil || len(decoded) != 2 {
		t.Fatalf("inspect json decode: err=%v len=%d", err, len(decoded))
	}
}
