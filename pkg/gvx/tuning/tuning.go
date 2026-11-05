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

// Package tuning holds the one registry of host-side tunables of gvx.
//
// A tunable is a limit or a time value of the host process that Linux has no
// knob for. Linux limits do not belong here: the guest sets them through its
// own sysctl files, module parameters, and netlink requests. Every entry has a
// dotted name, a type, a default, a range, a unit, and a one-sentence
// description. The Go SDK (gvx.Config.Tuning), the rungv flags (--tune and
// --tune-file), "rungv tune list", and the table in docs/cli.md all come from
// the same registry.
//
// A Values holds the settings of one sandbox. The zero value holds the
// defaults. A Values is immutable: Set and the With methods return a copy.
package tuning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Kind is the type of a tunable.
type Kind int

const (
	// Int is a plain count, such as a number of sessions.
	Int Kind = iota + 1
	// Duration is a time span. The text form is a Go duration, such as "250ms".
	Duration
	// Bool is a switch. The text form is "true" or "false".
	Bool
	// Size is a byte count. The text form accepts a binary suffix, such as "64MiB".
	Size
)

// String returns the name of the kind in the table of the documentation.
func (k Kind) String() string {
	switch k {
	case Int:
		return "int"
	case Duration:
		return "duration"
	case Bool:
		return "bool"
	case Size:
		return "size"
	}
	return "invalid"
}

// Entry describes one tunable. Default, Min, and Max use the unit of the
// kind: the count for Int, nanoseconds for Duration, 0 or 1 for Bool, and
// bytes for Size.
type Entry struct {
	Name    string
	Kind    Kind
	Default int64
	Min     int64
	Max     int64
	// Unit names what the number counts, such as "bytes" or "sessions".
	Unit string
	// Doc is one sentence that tells what the tunable does.
	Doc string
}

// registry is the table of tunables. Define fills it while the package
// initializes, in the order of the declarations in registry.go.
var registry []Entry

// index maps a name to its position in registry.
var index = map[string]int{}

func define(e Entry) int {
	if e.Name == "" || e.Doc == "" || e.Unit == "" {
		panic("tuning: an entry needs a name, a unit, and a description: " + e.Name)
	}
	if _, dup := index[e.Name]; dup {
		panic("tuning: duplicate key " + e.Name)
	}
	if e.Min > e.Max || e.Default < e.Min || e.Default > e.Max {
		panic("tuning: default or range of " + e.Name + " is inconsistent")
	}
	registry = append(registry, e)
	index[e.Name] = len(registry) - 1
	return len(registry) - 1
}

// IntKey is the typed handle of an Int tunable.
type IntKey struct{ slot int }

// DurationKey is the typed handle of a Duration tunable.
type DurationKey struct{ slot int }

// BoolKey is the typed handle of a Bool tunable.
type BoolKey struct{ slot int }

// SizeKey is the typed handle of a Size tunable.
type SizeKey struct{ slot int }

func defineInt(name string, def, lo, hi int64, unit, doc string) IntKey {
	return IntKey{define(Entry{Name: name, Kind: Int, Default: def, Min: lo, Max: hi, Unit: unit, Doc: doc})}
}

func defineDuration(name string, def, lo, hi time.Duration, doc string) DurationKey {
	return DurationKey{define(Entry{Name: name, Kind: Duration, Default: int64(def), Min: int64(lo), Max: int64(hi), Unit: "time", Doc: doc})}
}

func defineSize(name string, def, lo, hi int64, doc string) SizeKey {
	return SizeKey{define(Entry{Name: name, Kind: Size, Default: def, Min: lo, Max: hi, Unit: "bytes", Doc: doc})}
}

// Entries returns a copy of the registry in table order.
func Entries() []Entry {
	return slices.Clone(registry)
}

// Lookup returns the entry of a name.
func Lookup(name string) (Entry, bool) {
	i, ok := index[name]
	if !ok {
		return Entry{}, false
	}
	return registry[i], true
}

// Values holds the settings of one sandbox. The zero value holds the
// defaults.
type Values struct {
	set map[string]int64
}

func (v Values) get(slot int) int64 {
	e := registry[slot]
	if n, ok := v.set[e.Name]; ok {
		return n
	}
	return e.Default
}

// Int returns the value of an Int tunable.
func (v Values) Int(k IntKey) int { return int(v.get(k.slot)) }

// Duration returns the value of a Duration tunable.
func (v Values) Duration(k DurationKey) time.Duration { return time.Duration(v.get(k.slot)) }

// Bool returns the value of a Bool tunable.
func (v Values) Bool(k BoolKey) bool { return v.get(k.slot) != 0 }

// Size returns the value of a Size tunable in bytes.
func (v Values) Size(k SizeKey) int64 { return v.get(k.slot) }

// Get returns the value of a tunable in the unit of its entry. The second
// result is false for an unknown name.
func (v Values) Get(name string) (int64, bool) {
	i, ok := index[name]
	if !ok {
		return 0, false
	}
	return v.get(i), true
}

// Set returns a copy of v with the tunable name set to the value that text
// holds. It rejects an unknown name, a text that does not parse, and a value
// outside the range of the entry. The error names the key.
func (v Values) Set(name, text string) (Values, error) {
	i, ok := index[name]
	if !ok {
		return Values{}, fmt.Errorf("tuning: unknown key %q", name)
	}
	e := registry[i]
	n, err := parseValue(e, text)
	if err != nil {
		return Values{}, fmt.Errorf("tuning: %s: %w", name, err)
	}
	return v.store(e, n)
}

// WithInt returns a copy of v with an Int tunable set.
func (v Values) WithInt(k IntKey, n int) (Values, error) {
	return v.store(registry[k.slot], int64(n))
}

// WithDuration returns a copy of v with a Duration tunable set.
func (v Values) WithDuration(k DurationKey, d time.Duration) (Values, error) {
	return v.store(registry[k.slot], int64(d))
}

// WithBool returns a copy of v with a Bool tunable set.
func (v Values) WithBool(k BoolKey, b bool) (Values, error) {
	n := int64(0)
	if b {
		n = 1
	}
	return v.store(registry[k.slot], n)
}

// WithSize returns a copy of v with a Size tunable set, in bytes.
func (v Values) WithSize(k SizeKey, bytes int64) (Values, error) {
	return v.store(registry[k.slot], bytes)
}

func (v Values) store(e Entry, n int64) (Values, error) {
	if n < e.Min || n > e.Max {
		return Values{}, fmt.Errorf("tuning: %s: %s is outside the range %s to %s", e.Name, e.format(n), e.format(e.Min), e.format(e.Max))
	}
	out := Values{set: maps.Clone(v.set)}
	if out.set == nil {
		out.set = map[string]int64{}
	}
	out.set[e.Name] = n
	return out, nil
}

// Parse builds Values from name and text pairs. It reports every bad pair in
// one error, in the order of the names.
func Parse(assignments map[string]string) (Values, error) {
	var v Values
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(assignments)) {
		next, err := v.Set(name, assignments[name])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		v = next
	}
	return v, errors.Join(errs...)
}

// ParseJSON builds Values from a JSON object that maps names to values. A
// value is a JSON string, number, or boolean. The string form is the text
// form of the entry, so a Duration is "250ms" and a Size may be "64MiB".
func ParseJSON(data []byte) (Values, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return Values{}, fmt.Errorf("tuning: want a JSON object of key and value pairs: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Values{}, errors.New("tuning: unexpected data after the JSON object")
	}
	text := make(map[string]string, len(raw))
	for name, val := range raw {
		switch x := val.(type) {
		case string:
			text[name] = x
		case json.Number:
			text[name] = x.String()
		case bool:
			text[name] = strconv.FormatBool(x)
		default:
			return Values{}, fmt.Errorf("tuning: %s: want a string, a number, or a boolean", name)
		}
	}
	return Parse(text)
}

func parseValue(e Entry, text string) (int64, error) {
	text = strings.TrimSpace(text)
	switch e.Kind {
	case Int:
		n, err := strconv.ParseInt(text, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%q is not an integer", text)
		}
		return n, nil
	case Duration:
		d, err := time.ParseDuration(text)
		if err != nil {
			return 0, fmt.Errorf("%q is not a duration such as 250ms or 30s", text)
		}
		return int64(d), nil
	case Bool:
		b, err := strconv.ParseBool(text)
		if err != nil {
			return 0, fmt.Errorf("%q is not true or false", text)
		}
		if b {
			return 1, nil
		}
		return 0, nil
	case Size:
		return parseSize(text)
	}
	return 0, errors.New("invalid kind")
}

// sizeUnits maps a suffix to its binary multiple.
var sizeUnits = map[string]int64{
	"": 1, "b": 1,
	"k": 1 << 10, "kb": 1 << 10, "kib": 1 << 10,
	"m": 1 << 20, "mb": 1 << 20, "mib": 1 << 20,
	"g": 1 << 30, "gb": 1 << 30, "gib": 1 << 30,
	"t": 1 << 40, "tb": 1 << 40, "tib": 1 << 40,
}

func parseSize(text string) (int64, error) {
	lower := strings.ToLower(text)
	split := strings.IndexFunc(lower, func(r rune) bool { return r < '0' || r > '9' })
	num, unit := lower, ""
	if split >= 0 {
		num, unit = lower[:split], lower[split:]
	}
	mult, ok := sizeUnits[unit]
	if !ok {
		return 0, fmt.Errorf("%q has an unknown unit %q: use b, k, m, g, or t", text, unit)
	}
	n, err := strconv.ParseInt(num, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a size such as 4096 or 64MiB", text)
	}
	if n > math.MaxInt64/mult {
		return 0, fmt.Errorf("%q is too large", text)
	}
	return n * mult, nil
}

// Format returns the text form of a value of the entry. Set accepts the text.
func (e Entry) Format(n int64) string { return e.format(n) }

func (e Entry) format(n int64) string {
	switch e.Kind {
	case Duration:
		return formatDuration(time.Duration(n))
	case Bool:
		return strconv.FormatBool(n != 0)
	case Size:
		return formatSize(n)
	}
	return strconv.FormatInt(n, 10)
}

func formatDuration(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = s[:len(s)-2]
	}
	if strings.HasSuffix(s, "h0m") {
		s = s[:len(s)-2]
	}
	return s
}

func formatSize(n int64) string {
	for _, u := range []struct {
		suffix string
		shift  uint
	}{{"TiB", 40}, {"GiB", 30}, {"MiB", 20}, {"KiB", 10}} {
		if n >= 1<<u.shift && n%(1<<u.shift) == 0 {
			return strconv.FormatInt(n>>u.shift, 10) + u.suffix
		}
	}
	return strconv.FormatInt(n, 10)
}

// DefaultText returns the default of the entry in its text form.
func (e Entry) DefaultText() string { return e.format(e.Default) }

// RangeText returns the range of the entry as "min to max".
func (e Entry) RangeText() string {
	if e.Kind == Bool {
		return "true or false"
	}
	return e.format(e.Min) + " to " + e.format(e.Max)
}

// MarkdownTable returns the table of the registry for docs/cli.md. The test
// of the package keeps the documentation equal to this text.
func MarkdownTable() string {
	var b strings.Builder
	b.WriteString("| Key | Type | Default | Range | Unit | Description |\n")
	b.WriteString("| :--- | :--- | ---: | :--- | :--- | :--- |\n")
	for _, e := range registry {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s | %s | %s |\n", e.Name, e.Kind, e.DefaultText(), e.RangeText(), e.Unit, e.Doc)
	}
	return b.String()
}
