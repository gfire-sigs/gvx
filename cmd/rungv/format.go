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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"text/template"

	"z.gfire.dev/gvx/pkg/oci"
)

var formatFuncMap = template.FuncMap{
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

func compileFormatTemplate(raw string) (*template.Template, bool, error) {
	spec := strings.TrimSpace(raw)
	isTable := false
	if spec == "table" {
		return nil, true, nil
	}
	if strings.HasPrefix(spec, "table ") || strings.HasPrefix(spec, "table\t") {
		isTable = true
		spec = strings.TrimSpace(spec[len("table"):])
	}
	spec = unescapeOutsideActions(spec)
	tmpl, err := template.New("format").Funcs(formatFuncMap).Option("missingkey=error").Parse(spec)
	if err != nil {
		return nil, false, err
	}
	return tmpl, isTable, nil
}

// unescapeOutsideActions expands literal \t and \n sequences outside Go
// template actions so expressions such as `table {{.Repository}}\t{{.Tag}}`
// align columns as in Docker CLI.
func unescapeOutsideActions(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inAction := false
	for i := 0; i < len(s); i++ {
		if !inAction && i+1 < len(s) && s[i] == '{' && s[i+1] == '{' {
			inAction = true
			b.WriteString("{{")
			i++
			continue
		}
		if inAction && i+1 < len(s) && s[i] == '}' && s[i+1] == '}' {
			inAction = false
			b.WriteString("}}")
			i++
			continue
		}
		if !inAction && i+1 < len(s) && s[i] == '\\' {
			switch s[i+1] {
			case 't':
				b.WriteByte('\t')
				i++
				continue
			case 'n':
				b.WriteByte('\n')
				i++
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// renderListFormat formats a slice of items as a default table, NDJSON, or a Go
// text/template (including `table <template>`). A non-nil usageErr indicates an
// invalid --format value or template evaluation failure (exit code 2).
func renderListFormat[T any](w io.Writer, formatSpec string, items []T, writeDefaultTable func(io.Writer) error) (usageErr error, writeErr error) {
	spec := strings.TrimSpace(formatSpec)
	switch spec {
	case "", "table":
		return nil, writeDefaultTable(w)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)
		for _, item := range items {
			if err := enc.Encode(item); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}

	tmpl, isTable, err := compileFormatTemplate(spec)
	if err != nil {
		return fmt.Errorf("invalid --format template: %w", err), nil
	}
	if tmpl == nil {
		return nil, writeDefaultTable(w)
	}
	out := w
	var tw *tabwriter.Writer
	if isTable {
		tw = tabwriter.NewWriter(w, 10, 1, 3, ' ', 0)
		out = tw
	}
	for _, item := range items {
		var line bytes.Buffer
		if err := tmpl.Execute(&line, item); err != nil {
			return fmt.Errorf("evaluate --format template: %w", err), nil
		}
		if _, err := fmt.Fprintln(out, line.String()); err != nil {
			return nil, err
		}
	}
	if tw != nil {
		if err := tw.Flush(); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// renderInspectFormat formats inspected objects as an indented JSON array when
// formatSpec is empty or "json", or evaluates a Go text/template per object.
func renderInspectFormat[T any](w io.Writer, formatSpec string, items []T) (usageErr error, writeErr error) {
	spec := strings.TrimSpace(formatSpec)
	if spec == "" || spec == "json" {
		raw, err := json.MarshalIndent(items, "", "    ")
		if err != nil {
			return nil, err
		}
		_, err = fmt.Fprintf(w, "%s\n", raw)
		return nil, err
	}
	tmpl, isTable, err := compileFormatTemplate(spec)
	if err != nil {
		return fmt.Errorf("invalid --format template: %w", err), nil
	}
	if tmpl == nil {
		return fmt.Errorf("invalid --format %q: table requires a Go template expression", formatSpec), nil
	}
	out := w
	var tw *tabwriter.Writer
	if isTable {
		tw = tabwriter.NewWriter(w, 10, 1, 3, ' ', 0)
		out = tw
	}
	for _, item := range items {
		var line bytes.Buffer
		if err := tmpl.Execute(&line, item); err != nil {
			return fmt.Errorf("evaluate --format template: %w", err), nil
		}
		if _, err := fmt.Fprintln(out, line.String()); err != nil {
			return nil, err
		}
	}
	if tw != nil {
		if err := tw.Flush(); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// renderSingleFormat formats one summary struct using a default writer,
// indented JSON ("json"), or a Go text/template.
func renderSingleFormat[T any](w io.Writer, formatSpec string, item T, writeDefault func(io.Writer) error) (usageErr error, writeErr error) {
	spec := strings.TrimSpace(formatSpec)
	switch spec {
	case "", "table":
		return nil, writeDefault(w)
	case "json":
		raw, err := json.MarshalIndent(item, "", "    ")
		if err != nil {
			return nil, err
		}
		_, err = fmt.Fprintf(w, "%s\n", raw)
		return nil, err
	}
	tmpl, isTable, err := compileFormatTemplate(spec)
	if err != nil {
		return fmt.Errorf("invalid --format template: %w", err), nil
	}
	if tmpl == nil {
		return nil, writeDefault(w)
	}
	var line bytes.Buffer
	if err := tmpl.Execute(&line, item); err != nil {
		return fmt.Errorf("evaluate --format template: %w", err), nil
	}
	if isTable {
		tw := tabwriter.NewWriter(w, 10, 1, 3, ' ', 0)
		if _, err := fmt.Fprintln(tw, line.String()); err != nil {
			return nil, err
		}
		return nil, tw.Flush()
	}
	_, err = fmt.Fprintln(w, line.String())
	return nil, err
}

// confirmPrune prompts on stdout unless force is true and reads a y/yes answer
// from stdin.
func confirmPrune(stdin io.Reader, stdout io.Writer, force bool, warning string) (bool, error) {
	if force {
		return true, nil
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	_, _ = fmt.Fprintf(stdout, "WARNING! %s\nAre you sure you want to continue? [y/N] ", warning)
	ans, err := oci.ReadLine(stdin)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(ans)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}
