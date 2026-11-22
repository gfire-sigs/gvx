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

//go:build darwin || windows || linux

package e2e

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const maxCTSListDepth = 8

// ctsPage is one page of a run: a CTS path below sdk/tests and the WebGL
// version of its context.
type ctsPage struct {
	WebGL int    `json:"webgl"`
	Path  string `json:"page"`
	Slow  bool   `json:"slow,omitempty"`
	Retry bool   `json:"-"`
}

// ID returns "<webgl>/<path>", the key of every record, such as
// "2/conformance2/rendering/draw-buffers.html".
func (p ctsPage) ID() string {
	return strconv.Itoa(p.WebGL) + "/" + p.Path
}

// ctsStatus orders page outcomes from best to worst for comparison and
// expectation matching.
type ctsStatus string

const (
	ctsPass     ctsStatus = "pass"
	ctsFail     ctsStatus = "fail"
	ctsTimeout  ctsStatus = "timeout"
	ctsCrash    ctsStatus = "crash"
	ctsError    ctsStatus = "error"
	ctsNotRun   ctsStatus = "not-run"
	ctsSoftware ctsStatus = "software"
	ctsAny      ctsStatus = "any"
)

// ctsDelta is one page whose GPU status differs from its SwiftShader status, or
// a SwiftShader non-pass entry.
type ctsDelta struct {
	ID             string    `json:"id"`
	Mode           string    `json:"mode"`
	Reference      ctsStatus `json:"swiftshader"`
	Status         ctsStatus `json:"status"`
	Reason         string    `json:"reason,omitempty"`
	Failed         int       `json:"failed"`
	Messages       []string  `json:"messages,omitempty"`
	Flaky          bool      `json:"flaky,omitempty"`
	SoftwareRender bool      `json:"software_renderer,omitempty"`
	Expected       string    `json:"expected,omitempty"`
	Kind           string    `json:"kind"` // regression, degradation, improvement
}

// ctsSelector is one line of webgl-cts-subset.txt or GVX_E2E_WEBGL_CTS_PAGES.
type ctsSelector struct {
	WebGL   int
	Pattern string // ends in "/": every page below; else path.Match on the page path
	Exclude bool   // the line starts with "!"
	Line    int
}

// ctsExpectation is one parsed rule from webgl-cts-expectations.txt.
type ctsExpectation struct {
	Mode     string
	Pattern  string
	Reason   string
	WebGL    int // 0 means "*"
	Statuses []ctsStatus
	Line     int
}

// ctsRawAttempt is one JSON line from results.jsonl written by webgl-cts.js.
type ctsRawAttempt struct {
	Kind           string    `json:"kind"`
	Index          int       `json:"i"`
	Attempt        int       `json:"attempt"`
	WebGL          int       `json:"webgl"`
	Page           string    `json:"page"`
	Status         ctsStatus `json:"status"`
	Reason         string    `json:"reason"`
	Passed         int       `json:"passed"`
	Failed         int       `json:"failed"`
	Skipped        int       `json:"skipped"`
	Millis         int       `json:"ms"`
	StartUnixMs    int64     `json:"start_unix_ms"`
	ContextLost    int       `json:"context_lost"`
	ForeignReports int       `json:"foreign_reports"`
	Launch         int       `json:"launch"`
	Renderers      []string  `json:"renderers"`
	SoftwareRender bool      `json:"software_renderer"`
	Messages       []string  `json:"messages"`
	DeviceAlive    *bool     `json:"device_alive"`
	RendererLost   bool      `json:"renderer_lost"`
}

// ctsVersionAtLeast reports greaterThanOrEqualToVersion(have, want) with the
// rules of js/webgl-test-harness.js: compare each dot field of want in order,
// treating a missing field of have as 0.
func ctsVersionAtLeast(have, want string) bool {
	h := parseCTSVersionFields(have)
	w := parseCTSVersionFields(want)
	for i, wv := range w {
		hv := 0
		if i < len(h) {
			hv = h[i]
		}
		if hv > wv {
			return true
		}
		if hv < wv {
			return false
		}
	}
	return true
}

func parseCTSVersionFields(v string) []int {
	parts := strings.Split(v, ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		n, _ := strconv.Atoi(p)
		out[i] = n
	}
	return out
}

func validateCTSVersion(v string) error {
	if v == "" {
		return errors.New("empty version")
	}
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return fmt.Errorf("invalid version %q", v)
		}
	}
	return nil
}

// expandCTSList returns the pages of the list file name in fsys for version
// (such as "1.0.4"), in list order, with the rules of getFileList in
// js/webgl-test-harness.js. It fails on an unknown option, a missing nested
// list, a name that leaves fsys, and a nested depth above 8.
func expandCTSList(fsys fs.FS, name, version string, webgl int) ([]ctsPage, error) {
	if err := validateCTSVersion(version); err != nil {
		return nil, err
	}
	if strings.Contains(name, "\\") || path.IsAbs(name) {
		return nil, fmt.Errorf("list path %q leaves filesystem", name)
	}
	clean := path.Clean(name)
	if !fs.ValidPath(clean) {
		return nil, fmt.Errorf("list path %q leaves filesystem", name)
	}
	var out []ctsPage
	if err := walkCTSList(fsys, clean, version, webgl, "1.0", "", false, 0, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func walkCTSList(fsys fs.FS, listPath, version string, webgl int, defaultMin, defaultMax string, defaultSlow bool, depth int, out *[]ctsPage) error {
	if depth > maxCTSListDepth {
		return fmt.Errorf("list %s exceeds maximum nesting depth %d", listPath, maxCTSListDepth)
	}
	data, err := fs.ReadFile(fsys, listPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", listPath, err)
	}
	dir := path.Dir(listPath)
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		s := strings.TrimSpace(sc.Text())
		if len(s) <= 4 || strings.HasPrefix(s, "#") || strings.HasPrefix(s, ";") || strings.HasPrefix(s, "//") {
			continue
		}
		toks := strings.Fields(s)
		minVer, maxVer, slow := defaultMin, defaultMax, defaultSlow
		var rest []string
		for i := 0; i < len(toks); i++ {
			t := toks[i]
			switch {
			case t == "--slow":
				slow = true
			case t == "--min-version":
				if i+1 >= len(toks) {
					return fmt.Errorf("%s:%d: --min-version requires a value", listPath, lineNo)
				}
				i++
				if err := validateCTSVersion(toks[i]); err != nil {
					return fmt.Errorf("%s:%d: %w", listPath, lineNo, err)
				}
				minVer = toks[i]
			case t == "--max-version":
				if i+1 >= len(toks) {
					return fmt.Errorf("%s:%d: --max-version requires a value", listPath, lineNo)
				}
				i++
				if err := validateCTSVersion(toks[i]); err != nil {
					return fmt.Errorf("%s:%d: %w", listPath, lineNo, err)
				}
				maxVer = toks[i]
			case strings.HasPrefix(t, "-"):
				return fmt.Errorf("%s:%d: unknown option %q", listPath, lineNo, t)
			default:
				rest = append(rest, t)
			}
		}
		if len(rest) == 0 {
			return fmt.Errorf("%s:%d: missing file path", listPath, lineNo)
		}
		target := strings.Join(rest, " ")
		if strings.Contains(target, "\\") || path.IsAbs(target) {
			return fmt.Errorf("%s:%d: path %q leaves filesystem", listPath, lineNo, target)
		}
		joined := path.Clean(path.Join(dir, target))
		if !fs.ValidPath(joined) {
			return fmt.Errorf("%s:%d: path %q leaves filesystem", listPath, lineNo, target)
		}
		if strings.HasSuffix(joined, ".txt") {
			if err := walkCTSList(fsys, joined, version, webgl, minVer, maxVer, slow, depth+1, out); err != nil {
				return err
			}
			continue
		}
		if !ctsVersionAtLeast(version, minVer) {
			continue
		}
		if maxVer != "" && !ctsVersionAtLeast(maxVer, version) {
			continue
		}
		*out = append(*out, ctsPage{WebGL: webgl, Path: joined, Slow: slow})
	}
	return sc.Err()
}

// parseCTSSubset parses subset selector lines from r.
func parseCTSSubset(r io.Reader) ([]ctsSelector, error) {
	var out []ctsSelector
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		exclude := false
		if strings.HasPrefix(line, "!") {
			exclude = true
			line = strings.TrimSpace(strings.TrimPrefix(line, "!"))
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("subset line %d: want '<webgl> <pattern>', got %q", lineNo, sc.Text())
		}
		webgl, err := strconv.Atoi(fields[0])
		if err != nil || (webgl != 1 && webgl != 2) {
			return nil, fmt.Errorf("subset line %d: webgl must be 1 or 2, got %q", lineNo, fields[0])
		}
		pattern := fields[1]
		if err := validateCTSPattern(pattern); err != nil {
			return nil, fmt.Errorf("subset line %d: %w", lineNo, err)
		}
		out = append(out, ctsSelector{WebGL: webgl, Pattern: pattern, Exclude: exclude, Line: lineNo})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func validateCTSPattern(pattern string) error {
	if pattern == "" {
		return errors.New("empty pattern")
	}
	if strings.HasSuffix(pattern, "/") {
		return nil
	}
	if _, err := path.Match(pattern, ""); err != nil {
		return fmt.Errorf("invalid pattern %q: %w", pattern, err)
	}
	return nil
}

func matchCTSPattern(pattern, pagePath string) bool {
	if strings.HasSuffix(pattern, "/") {
		return strings.HasPrefix(pagePath, pattern)
	}
	ok, err := path.Match(pattern, pagePath)
	return err == nil && ok
}

// selectCTSPages returns the pages that an include selector matches and no
// exclude selector matches, in list order. It returns an error for any selector
// that matches no page.
func selectCTSPages(pages []ctsPage, sel []ctsSelector) ([]ctsPage, error) {
	matched := make([]bool, len(sel))
	var out []ctsPage
	for _, p := range pages {
		included := false
		for i, s := range sel {
			if s.Exclude {
				continue
			}
			if s.WebGL == p.WebGL && matchCTSPattern(s.Pattern, p.Path) {
				matched[i] = true
				included = true
			}
		}
		if !included {
			continue
		}
		excluded := false
		for i, s := range sel {
			if !s.Exclude {
				continue
			}
			if s.WebGL == p.WebGL && matchCTSPattern(s.Pattern, p.Path) {
				matched[i] = true
				excluded = true
			}
		}
		if !excluded {
			out = append(out, p)
		}
	}
	for i, s := range sel {
		if !matched[i] {
			prefix := ""
			if s.Exclude {
				prefix = "! "
			}
			return nil, fmt.Errorf("subset line %d (%s%d %s) matched no pages", s.Line, prefix, s.WebGL, s.Pattern)
		}
	}
	return out, nil
}

// writeCTSRunList writes one line for each page: "<webgl> <path>" plus " slow"
// for a --slow page and " retry" for a resumed attempt-2 page.
func writeCTSRunList(w io.Writer, pages []ctsPage) error {
	for _, p := range pages {
		var flags strings.Builder
		if p.Slow {
			flags.WriteString(" slow")
		}
		if p.Retry {
			flags.WriteString(" retry")
		}
		if _, err := fmt.Fprintf(w, "%d %s%s\n", p.WebGL, p.Path, flags.String()); err != nil {
			return err
		}
	}
	return nil
}

func isValidRawCTSStatus(s ctsStatus) bool {
	switch s {
	case ctsPass, ctsFail, ctsTimeout, ctsCrash, ctsError:
		return true
	default:
		return false
	}
}

// ctsRunInput describes one sandbox run for mergeCTSRuns: its results.jsonl
// stream and whether the Sentry log reported an unexpected renderer loss.
type ctsRunInput struct {
	Results       io.Reader
	RendererLost  bool
	LossEventLine string
}

// ctsMergeOutput holds merged page records, valid timing windows, and
// renderer-loss attributions across one or more sandbox runs.
type ctsMergeOutput struct {
	Pages              map[string]*ctsRecordPage
	Windows            map[string][][2]int64
	Truncated          int
	Invalidated        int
	LossPages          []string
	UnattributedLosses []int // 1-based run numbers with Sentry renderer loss but no blamed page
	PlacedEvents       map[string]bool
}

// readCTSResults reads one or more results.jsonl streams in run order and
// merges valid attempts by page ID. The last valid attempt sets the final
// status. The function marks a page Flaky when it fails an earlier attempt and
// passes its final attempt. It ignores a truncated trailing line and counts it
// in truncated.
func readCTSResults(readers ...io.Reader) (map[string]*ctsRecordPage, map[string][][2]int64, int, error) {
	runs := make([]ctsRunInput, len(readers))
	for i, r := range readers {
		runs[i] = ctsRunInput{Results: r}
	}
	out, err := mergeCTSRuns(runs)
	if err != nil {
		var trunc int
		if out != nil {
			trunc = out.Truncated
		}
		return nil, nil, trunc, err
	}
	return out.Pages, out.Windows, out.Truncated, nil
}

// mergeCTSRuns reads results.jsonl streams in run order without clock
// correlation. The function accepts a result line only when device_alive is
// true. It converts a renderer_lost record or an in-flight start during a host
// renderer loss into status crash with reason renderer-lost. It records any
// Sentry renderer loss without a blamed page in UnattributedLosses.
func mergeCTSRuns(runs []ctsRunInput) (*ctsMergeOutput, error) {
	out := &ctsMergeOutput{
		Pages:        map[string]*ctsRecordPage{},
		Windows:      map[string][][2]int64{},
		PlacedEvents: map[string]bool{},
	}
	hadNonPass := map[string]bool{}

	recordLossPage := func(id, lossEventLine string, keepAttempts bool) {
		prev, seen := out.Pages[id]
		nAttempts := 1
		var hostEvents []string
		if seen {
			if keepAttempts {
				nAttempts = prev.Attempts
			} else {
				nAttempts = prev.Attempts + 1
			}
			hostEvents = append(hostEvents, prev.HostEvents...)
		}
		hadNonPass[id] = true
		ev := strings.TrimSpace(lossEventLine)
		if ev == "" {
			ev = "renderer-lost"
		} else {
			out.PlacedEvents[ev] = true
		}
		hostEvents = append(hostEvents, ev)
		out.Pages[id] = &ctsRecordPage{
			Status:     ctsCrash,
			Reason:     "renderer-lost",
			Attempts:   nAttempts,
			HostEvents: hostEvents,
		}
	}

	for rIdx, run := range runs {
		var inFlight *ctsRawAttempt
		attributedLoss := false
		lossPageID := ""

		if run.Results != nil {
			data, err := io.ReadAll(run.Results)
			if err != nil {
				return out, fmt.Errorf("read results stream %d: %w", rIdx+1, err)
			}
			rawLines := strings.Split(string(data), "\n")
			// Trim trailing empty strings from final newline so the last non-empty
			// line identifies a possible truncation boundary.
			for len(rawLines) > 0 && strings.TrimSpace(rawLines[len(rawLines)-1]) == "" {
				rawLines = rawLines[:len(rawLines)-1]
			}
			for i, line := range rawLines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var raw ctsRawAttempt
				if err := json.Unmarshal([]byte(line), &raw); err != nil {
					if i == len(rawLines)-1 {
						out.Truncated++
						break
					}
					return out, fmt.Errorf("decode results stream %d line %d: %w", rIdx+1, i+1, err)
				}
				if raw.Kind == "start" {
					if raw.Page == "" || (raw.WebGL != 1 && raw.WebGL != 2) {
						if i == len(rawLines)-1 {
							out.Truncated++
							break
						}
						return out, fmt.Errorf("results stream %d line %d: invalid start page or webgl", rIdx+1, i+1)
					}
					cp := raw
					inFlight = &cp
					continue
				}
				if raw.Page == "" || (raw.WebGL != 1 && raw.WebGL != 2) || !isValidRawCTSStatus(raw.Status) {
					if i == len(rawLines)-1 {
						out.Truncated++
						break
					}
					return out, fmt.Errorf("results stream %d line %d: invalid page, webgl, or status %q", rIdx+1, i+1, raw.Status)
				}

				id := (ctsPage{WebGL: raw.WebGL, Path: raw.Page}).ID()
				if inFlight != nil && inFlight.WebGL == raw.WebGL && inFlight.Page == raw.Page {
					inFlight = nil
				}

				if raw.RendererLost {
					attributedLoss = true
					lossPageID = id
					out.Invalidated++
					recordLossPage(id, run.LossEventLine, raw.Reason == "delayed-gpu-process-crash")
					continue
				}
				if raw.DeviceAlive == nil || !*raw.DeviceAlive {
					out.Invalidated++
					continue
				}

				prev, seen := out.Pages[id]
				nAttempts := 1
				var prevHostEvents []string
				if seen {
					if raw.Reason == "delayed-gpu-process-crash" {
						nAttempts = prev.Attempts
					} else {
						nAttempts = prev.Attempts + 1
					}
					prevHostEvents = prev.HostEvents
				}
				if raw.Status != ctsPass {
					hadNonPass[id] = true
				}
				rec := &ctsRecordPage{
					Status:         raw.Status,
					Reason:         raw.Reason,
					Passed:         raw.Passed,
					Failed:         raw.Failed,
					Skipped:        raw.Skipped,
					Millis:         raw.Millis,
					Attempts:       nAttempts,
					Flaky:          raw.Status == ctsPass && hadNonPass[id],
					ContextLost:    raw.ContextLost,
					Renderers:      raw.Renderers,
					SoftwareRender: raw.SoftwareRender,
					Messages:       raw.Messages,
					HostEvents:     prevHostEvents,
				}
				out.Pages[id] = rec
				if raw.StartUnixMs > 0 {
					out.Windows[id] = append(out.Windows[id], [2]int64{raw.StartUnixMs, raw.StartUnixMs + int64(raw.Millis)})
				}
			}
		}

		if inFlight != nil {
			id := (ctsPage{WebGL: inFlight.WebGL, Path: inFlight.Page}).ID()
			if run.RendererLost && !attributedLoss {
				attributedLoss = true
				lossPageID = id
				recordLossPage(id, run.LossEventLine, false)
			} else if !attributedLoss {
				prev, seen := out.Pages[id]
				nAttempts := 1
				var prevHostEvents []string
				if seen {
					nAttempts = prev.Attempts + 1
					prevHostEvents = prev.HostEvents
				}
				hadNonPass[id] = true
				out.Pages[id] = &ctsRecordPage{
					Status:     ctsTimeout,
					Reason:     "in-flight",
					Attempts:   nAttempts,
					HostEvents: prevHostEvents,
				}
			}
		}

		if run.RendererLost || attributedLoss {
			out.LossPages = append(out.LossPages, lossPageID)
		}
		if run.RendererLost && !attributedLoss {
			out.UnattributedLosses = append(out.UnattributedLosses, rIdx+1)
		}
	}
	return out, nil
}

// ctsStatusRank orders page outcomes from best (0) to worst (5).
func ctsStatusRank(s ctsStatus) int {
	switch s {
	case ctsPass:
		return 0
	case ctsFail:
		return 1
	case ctsTimeout:
		return 2
	case ctsCrash:
		return 3
	case ctsError:
		return 4
	case ctsNotRun:
		return 5
	default:
		return 6
	}
}

// diffCTSModes compares the final records of one GPU mode with the SwiftShader
// records, page by page, in sorted page ID order.
func diffCTSModes(mode string, ref, gpu map[string]*ctsRecordPage) []ctsDelta {
	ids := make([]string, 0, len(ref))
	for id := range ref {
		if _, ok := gpu[id]; ok {
			ids = append(ids, id)
		}
	}
	slices.Sort(ids)

	var deltas []ctsDelta
	for _, id := range ids {
		r := ref[id]
		g := gpu[id]
		switch {
		case r.Status == ctsPass && (g.Status != ctsPass || g.SoftwareRender):
			status := g.Status
			reason := g.Reason
			if g.Status == ctsPass && g.SoftwareRender {
				status = ctsSoftware
				reason = "software-renderer"
			}
			deltas = append(deltas, ctsDelta{
				ID:             id,
				Mode:           mode,
				Reference:      r.Status,
				Status:         status,
				Reason:         reason,
				Failed:         g.Failed,
				Messages:       g.Messages,
				Flaky:          g.Flaky,
				SoftwareRender: g.SoftwareRender,
				Kind:           "regression",
			})
		case r.Status != ctsPass && g.Status == ctsPass && !g.SoftwareRender:
			deltas = append(deltas, ctsDelta{
				ID:        id,
				Mode:      mode,
				Reference: r.Status,
				Status:    g.Status,
				Reason:    g.Reason,
				Failed:    g.Failed,
				Messages:  g.Messages,
				Flaky:     g.Flaky,
				Kind:      "improvement",
			})
		case r.Status != ctsPass && ctsStatusRank(g.Status) > ctsStatusRank(r.Status):
			deltas = append(deltas, ctsDelta{
				ID:             id,
				Mode:           mode,
				Reference:      r.Status,
				Status:         g.Status,
				Reason:         g.Reason,
				Failed:         g.Failed,
				Messages:       g.Messages,
				Flaky:          g.Flaky,
				SoftwareRender: g.SoftwareRender,
				Kind:           "degradation",
			})
		case r.Status != ctsPass && g.SoftwareRender:
			status := g.Status
			reason := g.Reason
			if status == ctsPass {
				status = ctsSoftware
			}
			if reason == "" {
				reason = "software-renderer"
			}
			deltas = append(deltas, ctsDelta{
				ID:             id,
				Mode:           mode,
				Reference:      r.Status,
				Status:         status,
				Reason:         reason,
				Failed:         g.Failed,
				Messages:       g.Messages,
				Flaky:          g.Flaky,
				SoftwareRender: true,
				Kind:           "regression",
			})
		}
	}
	return deltas
}

// parseCTSExpectations parses webgl-cts-expectations.txt lines from r.
func parseCTSExpectations(r io.Reader) ([]ctsExpectation, error) {
	var out []ctsExpectation
	sc := bufio.NewScanner(r)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		body, reason, hasHash := strings.Cut(raw, "#")
		reason = strings.TrimSpace(reason)
		if !hasHash || reason == "" {
			return nil, fmt.Errorf("expectations line %d: missing '# <reason>'", lineNo)
		}
		fields := strings.Fields(body)
		if len(fields) != 4 {
			return nil, fmt.Errorf("expectations line %d: want '<mode> <webgl> <pattern> <statuses> # <reason>', got %q", lineNo, raw)
		}
		mode := fields[0]
		switch mode {
		case "swiftshader", "venus", "virgl", "*":
		default:
			return nil, fmt.Errorf("expectations line %d: unknown mode %q", lineNo, mode)
		}
		var webgl int
		switch fields[1] {
		case "*":
			webgl = 0
		case "1":
			webgl = 1
		case "2":
			webgl = 2
		default:
			return nil, fmt.Errorf("expectations line %d: unknown webgl %q", lineNo, fields[1])
		}
		pattern := fields[2]
		if err := validateCTSPattern(pattern); err != nil {
			return nil, fmt.Errorf("expectations line %d: %w", lineNo, err)
		}
		var statuses []ctsStatus
		for _, tok := range strings.Split(fields[3], ",") {
			st := ctsStatus(tok)
			switch st {
			case ctsFail, ctsTimeout, ctsCrash, ctsNotRun, ctsSoftware, ctsAny:
				statuses = append(statuses, st)
			default:
				return nil, fmt.Errorf("expectations line %d: unknown status %q", lineNo, tok)
			}
		}
		out = append(out, ctsExpectation{
			Mode:     mode,
			Pattern:  pattern,
			Reason:   reason,
			WebGL:    webgl,
			Statuses: statuses,
			Line:     lineNo,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func splitCTSPageID(id string) (int, string) {
	v, p, ok := strings.Cut(id, "/")
	if !ok {
		return 0, id
	}
	n, _ := strconv.Atoi(v)
	return n, p
}

// matchCTSExpectationIndex returns the index of the first expectation that
// matches d, or -1. Mode "*" matches only GPU modes (venus and virgl), never
// swiftshader.
func matchCTSExpectationIndex(exps []ctsExpectation, d ctsDelta) int {
	webgl, pagePath := splitCTSPageID(d.ID)
	for i, exp := range exps {
		if exp.Mode == "*" {
			if d.Mode != "venus" && d.Mode != "virgl" {
				continue
			}
		} else if exp.Mode != d.Mode {
			continue
		}
		if exp.WebGL != 0 && exp.WebGL != webgl {
			continue
		}
		if !matchCTSPattern(exp.Pattern, pagePath) {
			continue
		}
		if d.SoftwareRender || d.Status == ctsSoftware {
			if !slices.Contains(exp.Statuses, ctsSoftware) {
				continue
			}
			if d.Status != ctsSoftware && !slices.Contains(exp.Statuses, d.Status) && !slices.Contains(exp.Statuses, ctsAny) {
				continue
			}
			return i
		}
		if slices.Contains(exp.Statuses, d.Status) || slices.Contains(exp.Statuses, ctsAny) {
			return i
		}
	}
	return -1
}

// collectCTSRenderers returns all distinct non-empty WebGL renderer strings
// observed across pages, in sorted page ID order.
func collectCTSRenderers(pages map[string]*ctsRecordPage) []string {
	ids := make([]string, 0, len(pages))
	for id := range pages {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		for _, r := range pages[id].Renderers {
			if r == "" || seen[r] {
				continue
			}
			seen[r] = true
			out = append(out, r)
		}
	}
	return out
}

// markCTSSoftwareRenderers marks SoftwareRender on any page of a GPU mode
// whose reported renderers include a software renderer.
func markCTSSoftwareRenderers(mode string, pages map[string]*ctsRecordPage) {
	if mode != "venus" && mode != "virgl" {
		return
	}
	for _, rec := range pages {
		if rec == nil || rec.SoftwareRender {
			continue
		}
		for _, r := range rec.Renderers {
			if softwareRendererRE.MatchString(r) {
				rec.SoftwareRender = true
				break
			}
		}
	}
}

// pickCTSModeRenderer returns the representative renderer string for mode: the
// first non-software renderer in GPU modes (falling back to renderers[0] when
// all renderers are software), or renderers[0] for swiftshader.
func pickCTSModeRenderer(mode string, renderers []string) string {
	if len(renderers) == 0 {
		return ""
	}
	if mode == "venus" || mode == "virgl" {
		for _, r := range renderers {
			if !softwareRendererRE.MatchString(r) {
				return r
			}
		}
	}
	return renderers[0]
}

// validateModeRenderers verifies that mode reported at least one WebGL renderer
// string and that every applicable renderer satisfies the mode rule. For GPU
// modes, it requires at least one non-software renderer and verifies every
// non-software string. Per-page software fallbacks pass through diffCTSModes
// and expectation matching.
func validateModeRenderers(mode string, renderers []string, fail func(format string, args ...any)) bool {
	if len(renderers) == 0 {
		fail("%s reported no WebGL renderer string", mode)
		return false
	}
	ok := true
	wrapFail := func(format string, args ...any) {
		ok = false
		fail(format, args...)
	}
	if mode == "swiftshader" {
		for _, r := range renderers {
			if !softwareRendererRE.MatchString(r) {
				wrapFail("swiftshader renderer = %q, want a software renderer", r)
			}
		}
		return ok
	}
	nonSoftware := 0
	for _, r := range renderers {
		if softwareRendererRE.MatchString(r) {
			continue
		}
		nonSoftware++
		switch mode {
		case "venus":
			requireGPURenderer(r, "venus", wrapFail)
		case "virgl":
			requireGLRenderer(r, "virgl", wrapFail)
		}
	}
	if nonSoftware == 0 {
		fail("%s reported only software renderers (%q)", mode, renderers[0])
		return false
	}
	return ok
}

// parseCTSAbortReason extracts the reason from a "GVX-CTS abort=<reason>" line
// in stdout, or returns "" when stdout has no abort line.
func parseCTSAbortReason(stdout string) string {
	for _, line := range strings.Split(stdout, "\n") {
		if reason, ok := strings.CutPrefix(strings.TrimSpace(line), "GVX-CTS abort="); ok {
			return strings.TrimSpace(reason)
		}
	}
	return ""
}

// ctsRunFinishedCleanly reports whether a guest CTS sandbox run completed its
// run list with exit code 0 and no timeout, abort, or driver error.
func ctsRunFinishedCleanly(res gpuRunResult) bool {
	return res.code == 0 &&
		!res.timedOut &&
		strings.Contains(res.stdout, "GVX-CTS done") &&
		parseCTSAbortReason(res.stdout) == "" &&
		!strings.Contains(res.stdout, "GVX-CTS error=")
}

// ctsRemainingPages returns pages that still need a run after an interrupted
// sandbox. It queues unseen pages with Retry=false and non-pass or
// software-fallback pages with fewer than two attempts with Retry=true.
// It skips pages with reason renderer-lost so resume does not kill the new
// renderer immediately.
func ctsRemainingPages(pages []ctsPage, seen map[string]*ctsRecordPage, retryEnabled bool) []ctsPage {
	var next []ctsPage
	for _, p := range pages {
		rec, ok := seen[p.ID()]
		if !ok {
			np := p
			np.Retry = false
			next = append(next, np)
			continue
		}
		if rec.Reason == "renderer-lost" {
			continue
		}
		if retryEnabled && (rec.Status != ctsPass || rec.SoftwareRender) && rec.Attempts < 2 {
			rp := p
			rp.Retry = true
			next = append(next, rp)
		}
	}
	return next
}

// findStaleCTSExpectations reports expectation lines that did not match any
// delta even though their mode ran and their pattern matches at least one
// selected page.
func findStaleCTSExpectations(exps []ctsExpectation, used []bool, ranModes map[string]bool, selected []ctsPage) []string {
	stale := []string{}
	for i, exp := range exps {
		if i < len(used) && used[i] {
			continue
		}
		if exp.Mode == "*" {
			if !ranModes["venus"] && !ranModes["virgl"] {
				continue
			}
		} else if !ranModes[exp.Mode] {
			continue
		}
		matchedSelected := false
		for _, p := range selected {
			if (exp.WebGL == 0 || exp.WebGL == p.WebGL) && matchCTSPattern(exp.Pattern, p.Path) {
				matchedSelected = true
				break
			}
		}
		if !matchedSelected {
			continue
		}
		w := "*"
		if exp.WebGL != 0 {
			w = strconv.Itoa(exp.WebGL)
		}
		st := make([]string, len(exp.Statuses))
		for j, s := range exp.Statuses {
			st[j] = string(s)
		}
		stale = append(stale, fmt.Sprintf("line %d: %s %s %s %s", exp.Line, exp.Mode, w, exp.Pattern, strings.Join(st, ",")))
	}
	return stale
}

// matchCTSExpectation returns the first expectation that matches d, or nil.
func matchCTSExpectation(exps []ctsExpectation, d ctsDelta) *ctsExpectation {
	idx := matchCTSExpectationIndex(exps, d)
	if idx < 0 {
		return nil
	}
	return &exps[idx]
}

// glogTimeRE parses the leading glog timestamp ("I1122 03:46:25.123456").
var glogTimeRE = regexp.MustCompile(`^[IWEFD](\d{2})(\d{2}) (\d{2}):(\d{2}):(\d{2})\.(\d+)`)

func parseGlogUnixMs(line string, year int, loc *time.Location) (int64, bool) {
	m := glogTimeRE.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}
	month, _ := strconv.Atoi(m[1])
	day, _ := strconv.Atoi(m[2])
	hour, _ := strconv.Atoi(m[3])
	minute, _ := strconv.Atoi(m[4])
	sec, _ := strconv.Atoi(m[5])
	frac := m[6]
	if len(frac) > 9 {
		frac = frac[:9]
	}
	for len(frac) < 9 {
		frac += "0"
	}
	nsec, _ := strconv.Atoi(frac)
	if loc == nil {
		loc = time.Local
	}
	t := time.Date(year, time.Month(month), day, hour, minute, sec, nsec, loc)
	return t.UnixMilli(), true
}

// firstRendererLostLine returns the first unexpected renderer-lost line in
// lines, or "" when none matches.
func firstRendererLostLine(lines []string) string {
	for _, raw := range lines {
		if isRendererLostLine(raw) {
			return strings.TrimSpace(raw)
		}
	}
	return ""
}

func isCTSHostEvent(line string) bool {
	if kd1ContextLostRE.MatchString(line) {
		return true
	}
	return isRendererLostLine(line)
}

// placeHostEvents scans logText for device context-lost and renderer-lost lines
// and attaches each event to the page whose [start_unix_ms, start_unix_ms + ms]
// window contains the line timestamp. This placement is best-effort for review
// output and never affects result validity.
func placeHostEvents(logText string, year int, loc *time.Location, pages map[string]*ctsRecordPage, windows map[string][][2]int64) []string {
	return placeHostEventsSkip(logText, year, loc, pages, windows, nil)
}

// placeHostEventsSkip behaves like placeHostEvents and omits trimmed lines
// present in skip so events attributed by the device probe do not duplicate.
func placeHostEventsSkip(logText string, year int, loc *time.Location, pages map[string]*ctsRecordPage, windows map[string][][2]int64, skip map[string]bool) []string {
	ids := make([]string, 0, len(windows))
	for id := range windows {
		ids = append(ids, id)
	}
	slices.Sort(ids)

	var unplaced []string
	sc := bufio.NewScanner(strings.NewReader(logText))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !isCTSHostEvent(line) {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if skip[trimmed] {
			continue
		}
		ts, ok := parseGlogUnixMs(trimmed, year, loc)
		placed := false
		if ok {
			for _, id := range ids {
				for _, w := range windows[id] {
					if ts >= w[0] && ts <= w[1] {
						if p, exists := pages[id]; exists {
							p.HostEvents = append(p.HostEvents, trimmed)
							placed = true
							break
						}
					}
				}
				if placed {
					break
				}
			}
		}
		if !placed {
			unplaced = append(unplaced, trimmed)
		}
	}
	return unplaced
}

func firstCTSMessage(d ctsDelta) string {
	if len(d.Messages) > 0 && strings.TrimSpace(d.Messages[0]) != "" {
		return singleLine(d.Messages[0], 200)
	}
	if d.Reason != "" {
		return singleLine(d.Reason, 200)
	}
	return ""
}

func singleLine(s string, maxLen int) string {
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.Join(strings.Fields(s), " ")
	if maxLen > 0 && len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// writeCTSCandidates writes one expectations candidate line for each unexpected
// delta, with reason TODO and the first failure message as a comment.
func writeCTSCandidates(w io.Writer, deltas []ctsDelta) error {
	if _, err := fmt.Fprintln(w, "# Unexpected WebGL CTS deltas. Replace TODO with a known defect (KD-n) or a host limit."); err != nil {
		return err
	}
	for _, d := range deltas {
		if d.Expected != "" {
			continue
		}
		if d.Kind != "regression" && d.Kind != "degradation" && d.Kind != "swiftshader-fail" {
			continue
		}
		webgl, pagePath := splitCTSPageID(d.ID)
		if msg := firstCTSMessage(d); msg != "" {
			if _, err := fmt.Fprintf(w, "# %s\n", msg); err != nil {
				return err
			}
		}
		status := string(d.Status)
		if d.SoftwareRender && d.Status != ctsSoftware {
			status = string(d.Status) + "," + string(ctsSoftware)
		} else if d.SoftwareRender {
			status = string(ctsSoftware)
		}
		if _, err := fmt.Fprintf(w, "%s %d %s %s # TODO\n", d.Mode, webgl, pagePath, status); err != nil {
			return err
		}
	}
	return nil
}

func ctsDirectoryKey(id string) string {
	_, p := splitCTSPageID(id)
	dir := path.Dir(p)
	if dir == "." {
		return "(root)"
	}
	return dir + "/"
}

// writeCTSQA writes QA.md for the WebGL CTS gate in seven sections: verdict
// and flags, mode summary table, unexpected deltas, expected deltas,
// SwiftShader non-pass and flaky pages with stale expectations, refused ioctls
// and host events, and reviewer actions.
func writeCTSQA(w io.Writer, rec *ctsRecord, modeResults map[string]*ctsModeResult, deltas []ctsDelta, swFailures []ctsDelta, unplacedEvents map[string][]string) error {
	var sb strings.Builder
	modeOrder := []string{"swiftshader", "venus", "virgl"}

	// Part 1: Verdict, scope, CTS commit, and flags of each mode.
	fmt.Fprintf(&sb, "# Gate WebGL CTS Review\n\n")
	fmt.Fprintf(&sb, "Automatic verdict: `pass=%v`. Scope: `%s`. CTS commit: `%s`. Pages: %d.\n\n",
		rec.Pass, rec.Scope, rec.CTSCommit, rec.Pages)
	if rec.Diagnosis != "" {
		fmt.Fprintf(&sb, "**Diagnosis run:** `%s=%s` replaced `webgl-cts-subset.txt`. Expectation rules did not fail the gate.\n\n",
			webglCTSPagesEnv, rec.Diagnosis)
	}
	if len(rec.Failures) > 0 {
		sb.WriteString("Gate failures:\n\n")
		for _, f := range rec.Failures {
			fmt.Fprintf(&sb, "- %s\n", f)
		}
		sb.WriteString("\n")
	}
	sb.WriteString("Chromium flags by mode:\n\n")
	for _, m := range modeOrder {
		if sum, ok := rec.Modes[m]; ok {
			fmt.Fprintf(&sb, "- `%s`: `%s`\n", m, sum.ChromiumFlags)
		}
	}
	sb.WriteString("\n")

	// Part 2: Mode summary table.
	sb.WriteString("## Mode Summary\n\n")
	sb.WriteString("| Mode | Pages | Pass | Fail | Timeout | Crash | Not-run | Flaky | Wall (s) | Renderer |\n")
	sb.WriteString("| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :--- |\n")
	for _, m := range modeOrder {
		sum, ok := rec.Modes[m]
		if !ok {
			continue
		}
		renderer := strings.ReplaceAll(sum.Renderer, "|", "\\|")
		fmt.Fprintf(&sb, "| `%s` | %d | %d | %d | %d | %d | %d | %d | %d | `%s` |\n",
			m, rec.Pages, sum.Counts["pass"], sum.Counts["fail"], sum.Counts["timeout"],
			sum.Counts["crash"], sum.Counts["not-run"], sum.Flaky, sum.WallSec, renderer)
	}
	sb.WriteString("\n")

	// Part 3: Unexpected regressions and degradations grouped by mode and directory.
	sb.WriteString("## Unexpected Regressions and Degradations\n\n")
	unexpectedCount := 0
	for _, m := range []string{"venus", "virgl"} {
		byDir := map[string][]ctsDelta{}
		for _, d := range deltas {
			if d.Mode != m || d.Expected != "" {
				continue
			}
			if d.Kind != "regression" && d.Kind != "degradation" {
				continue
			}
			dir := ctsDirectoryKey(d.ID)
			byDir[dir] = append(byDir[dir], d)
			unexpectedCount++
		}
		if len(byDir) == 0 {
			continue
		}
		fmt.Fprintf(&sb, "### %s\n\n", m)
		dirs := make([]string, 0, len(byDir))
		for dir := range byDir {
			dirs = append(dirs, dir)
		}
		slices.Sort(dirs)
		for _, dir := range dirs {
			fmt.Fprintf(&sb, "#### %s\n\n", dir)
			for _, d := range byDir[dir] {
				msg := firstCTSMessage(d)
				if msg != "" {
					fmt.Fprintf(&sb, "- `%s` (%s, swiftshader=%s, %s=%s): %s\n", d.ID, d.Kind, d.Reference, d.Mode, d.Status, msg)
				} else {
					fmt.Fprintf(&sb, "- `%s` (%s, swiftshader=%s, %s=%s)\n", d.ID, d.Kind, d.Reference, d.Mode, d.Status)
				}
			}
			sb.WriteString("\n")
		}
	}
	if unexpectedCount == 0 {
		sb.WriteString("None.\n\n")
	}

	// Part 4: Expected deltas with reasons.
	sb.WriteString("## Expected Deltas\n\n")
	expectedCount := 0
	for _, d := range deltas {
		if d.Expected == "" {
			continue
		}
		expectedCount++
		fmt.Fprintf(&sb, "- `%s` `%s` (%s, %s): %s\n", d.Mode, d.ID, d.Kind, d.Status, d.Expected)
	}
	if expectedCount == 0 {
		sb.WriteString("None.\n\n")
	} else {
		sb.WriteString("\n")
	}

	// Part 5: SwiftShader failures, flaky pages, stale expectations.
	sb.WriteString("## SwiftShader Non-Pass Pages, Flaky Pages, and Stale Expectations\n\n")
	sb.WriteString("SwiftShader non-pass pages:\n\n")
	if len(swFailures) == 0 {
		sb.WriteString("- None.\n\n")
	} else {
		for _, d := range swFailures {
			extra := ""
			if d.Expected != "" {
				extra = " (expected: " + d.Expected + ")"
			}
			fmt.Fprintf(&sb, "- `%s` (%s)%s\n", d.ID, d.Status, extra)
		}
		sb.WriteString("\n")
	}

	sb.WriteString("Flaky pages (passed on retry):\n\n")
	flakyCount := 0
	for _, m := range modeOrder {
		mr, ok := modeResults[m]
		if !ok {
			continue
		}
		ids := make([]string, 0, len(mr.Pages))
		for id, p := range mr.Pages {
			if p.Flaky {
				ids = append(ids, id)
			}
		}
		slices.Sort(ids)
		for _, id := range ids {
			flakyCount++
			fmt.Fprintf(&sb, "- `%s` `%s` (attempts=%d)\n", m, id, mr.Pages[id].Attempts)
		}
	}
	if flakyCount == 0 {
		sb.WriteString("- None.\n\n")
	} else {
		sb.WriteString("\n")
	}

	sb.WriteString("Stale expectations:\n\n")
	if len(rec.Stale) == 0 {
		sb.WriteString("- None.\n\n")
	} else {
		for _, s := range rec.Stale {
			fmt.Fprintf(&sb, "- %s\n", s)
		}
		sb.WriteString("\n")
	}

	// Part 6: Refused ioctls, KD-1 counts, and host events.
	sb.WriteString("## Refused Ioctls, KD-1 Counts, and Host Events\n\n")
	sb.WriteString("Refused ioctls:\n\n")
	refusedAny := false
	for _, m := range modeOrder {
		sum, ok := rec.Modes[m]
		if !ok {
			continue
		}
		for _, r := range sum.RefusedIoctls {
			refusedAny = true
			fmt.Fprintf(&sb, "- `%s`: `%s` (nr %s, cmd %s): %s (files %d)\n", m, r.Name, r.Nr, r.Cmd, r.Error, r.Files)
		}
	}
	if !refusedAny {
		sb.WriteString("- None.\n\n")
	} else {
		sb.WriteString("\n")
	}

	sb.WriteString("KD-1 counts:\n\n")
	for _, m := range modeOrder {
		if k, ok := rec.KD1[m]; ok {
			fmt.Fprintf(&sb, "- `%s`: %s\n", m, k)
		}
	}
	fmt.Fprintf(&sb, "\nKD-1 report required: %v.\n\n", rec.KD1Report)

	sb.WriteString("Host events (renderer lost or device context lost):\n\n")
	hostEventAny := false
	for _, m := range modeOrder {
		if mr, ok := modeResults[m]; ok {
			ids := make([]string, 0, len(mr.Pages))
			for id, p := range mr.Pages {
				if len(p.HostEvents) > 0 {
					ids = append(ids, id)
				}
			}
			slices.Sort(ids)
			for _, id := range ids {
				for _, ev := range mr.Pages[id].HostEvents {
					hostEventAny = true
					fmt.Fprintf(&sb, "- `%s` `%s`: `%s`\n", m, id, ev)
				}
			}
		}
		for _, ev := range unplacedEvents[m] {
			hostEventAny = true
			fmt.Fprintf(&sb, "- `%s` `(between pages)`: `%s`\n", m, ev)
		}
	}
	if !hostEventAny {
		sb.WriteString("- None.\n\n")
	} else {
		sb.WriteString("\n")
	}

	// Part 7: Reviewer classification instruction.
	sb.WriteString("## Reviewer Action\n\n")
	sb.WriteString("Classify each unexpected delta into one of three categories:\n\n")
	sb.WriteString("1. A gvx defect: record it in `known-defects.md` and report it to the parent session.\n")
	sb.WriteString("2. A host driver limit: add an expectation line in `e2e/testdata/gpu/webgl-cts-expectations.txt` with the reason.\n")
	sb.WriteString("3. A CTS or Chromium defect: add an expectation line that names the Chromium expectation or the CTS issue.\n")

	_, err := io.WriteString(w, sb.String())
	return err
}

const venusMesaBuildCmd = "scripts/gpu/build-renderer.sh --driver-source mesa-source"

// verifyVenusMesaPatches verifies that the renderer bundle holding
// rendererPath declares SOURCE=mesa-source in BUILDINFO and lists matching
// MESA_PATCH digests for every *.patch file in patchesDir.
func verifyVenusMesaPatches(rendererPath, patchesDir string) error {
	entries, err := os.ReadDir(patchesDir)
	if err != nil {
		return fmt.Errorf("read Mesa patch directory %s: %w", patchesDir, err)
	}
	var wantNames []string
	wantDigests := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".patch") {
			continue
		}
		p := filepath.Join(patchesDir, e.Name())
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return fmt.Errorf("read Mesa patch %s: %w", p, readErr)
		}
		wantNames = append(wantNames, e.Name())
		wantDigests[e.Name()] = sha256Hex(data)
	}
	if len(wantNames) == 0 {
		return fmt.Errorf("no *.patch files found in %s", patchesDir)
	}

	if strings.TrimSpace(rendererPath) == "" {
		return fmt.Errorf("renderer path is empty; build the patched driver with: %s", venusMesaBuildCmd)
	}
	absRenderer, err := filepath.Abs(rendererPath)
	if err != nil {
		return fmt.Errorf("resolve renderer path %s: %w; build the patched driver with: %s", rendererPath, err, venusMesaBuildCmd)
	}
	resolvedRenderer, err := filepath.EvalSymlinks(absRenderer)
	if err != nil {
		return fmt.Errorf("resolve renderer symlink %s: %w; build the patched driver with: %s", rendererPath, err, venusMesaBuildCmd)
	}
	resolvedRenderer, err = filepath.Abs(resolvedRenderer)
	if err != nil {
		return fmt.Errorf("resolve absolute renderer path %s: %w; build the patched driver with: %s", resolvedRenderer, err, venusMesaBuildCmd)
	}
	binDir := filepath.Dir(resolvedRenderer)
	if filepath.Base(binDir) != "bin" {
		return fmt.Errorf("renderer executable %s must reside in a bin directory (got %s); build the patched driver with: %s", resolvedRenderer, binDir, venusMesaBuildCmd)
	}
	bundleDir := filepath.Dir(binDir)
	if bundleDir == binDir || bundleDir == string(filepath.Separator) {
		return fmt.Errorf("renderer bundle root for %s cannot be filesystem root; build the patched driver with: %s", resolvedRenderer, venusMesaBuildCmd)
	}

	buildInfoPath := filepath.Join(bundleDir, "BUILDINFO")
	raw, err := os.ReadFile(buildInfoPath)
	if err != nil {
		return fmt.Errorf("read renderer BUILDINFO %s: %w; build the patched driver with: %s", buildInfoPath, err, venusMesaBuildCmd)
	}

	source := ""
	gotDigests := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if val, ok := strings.CutPrefix(line, "SOURCE="); ok {
			if source != "" && source != val {
				return fmt.Errorf("%s declares conflicting SOURCE values (%q and %q); rebuild with: %s", buildInfoPath, source, val, venusMesaBuildCmd)
			}
			source = val
			continue
		}
		if val, ok := strings.CutPrefix(line, "MESA_PATCH="); ok {
			fields := strings.Fields(val)
			if len(fields) != 2 {
				return fmt.Errorf("%s has malformed MESA_PATCH line %q; rebuild with: %s", buildInfoPath, line, venusMesaBuildCmd)
			}
			name, digest := fields[0], fields[1]
			if prev, dup := gotDigests[name]; dup {
				return fmt.Errorf("%s lists duplicate MESA_PATCH %s (%s and %s); rebuild with: %s", buildInfoPath, name, prev, digest, venusMesaBuildCmd)
			}
			gotDigests[name] = digest
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("scan %s: %w", buildInfoPath, err)
	}

	if source != "mesa-source" {
		return fmt.Errorf("venus WebGL CTS requires SOURCE=mesa-source in %s (got %q); rebuild with: %s", buildInfoPath, source, venusMesaBuildCmd)
	}

	var mismatches []string
	for _, name := range wantNames {
		want := wantDigests[name]
		got, ok := gotDigests[name]
		if !ok {
			mismatches = append(mismatches, fmt.Sprintf("missing MESA_PATCH %s", name))
			continue
		}
		if got != want {
			mismatches = append(mismatches, fmt.Sprintf("MESA_PATCH %s digest mismatch (got %s, want %s)", name, got, want))
		}
	}
	var extraNames []string
	for name := range gotDigests {
		if _, ok := wantDigests[name]; !ok {
			extraNames = append(extraNames, name)
		}
	}
	slices.Sort(extraNames)
	for _, name := range extraNames {
		mismatches = append(mismatches, fmt.Sprintf("unexpected MESA_PATCH %s", name))
	}
	if len(mismatches) > 0 {
		return fmt.Errorf("renderer BUILDINFO %s does not match %s: %s; rebuild with: %s",
			buildInfoPath, patchesDir, strings.Join(mismatches, "; "), venusMesaBuildCmd)
	}
	return nil
}
