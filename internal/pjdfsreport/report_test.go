package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	passingRun = "@@ BEGIN chmod/00.t\n1..3\nok 1\nnot ok 2 # TODO pending\nok 3\n@@ END chmod/00.t rc=0\n"
	failingRun = "@@ BEGIN rename/09.t\n1..2\nok 1\nnot ok 2 - tried 'rename a b', expected 0, got EXDEV\n@@ END rename/09.t rc=0\n"
	crashedRun = "@@ BEGIN link/00.t\n1..5\nok 1\n@@ END link/00.t rc=139\n"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func runReport(t *testing.T, known string, logs ...string) (string, error) {
	t.Helper()
	args := []string{"-fs", "hostfs", "-os", "windows", "-known", writeFile(t, "known.txt", known)}
	for i, l := range logs {
		args = append(args, writeFile(t, "out"+string(rune('a'+i))+".log", l))
	}
	var out strings.Builder
	err := run(args, &out)
	return out.String(), err
}

func TestReportVerdicts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		known     string
		logs      []string
		wantErr   bool
		wantLines []string
	}{
		{
			name:  "todo lines count as passes",
			known: "",
			logs:  []string{passingRun},
		},
		{
			name:      "unlisted failure fails the run",
			known:     "",
			logs:      []string{passingRun, failingRun},
			wantErr:   true,
			wantLines: []string{"FAIL: rename/09.t:2 tried 'rename a b', expected 0, got EXDEV"},
		},
		{
			name:      "listed failure passes the run",
			known:     "hostfs windows rename/09.t:2 NTFS cannot rename across volumes\n",
			logs:      []string{failingRun},
			wantLines: []string{"known: rename/09.t:2"},
		},
		{
			name:    "entry of another os does not cover the failure",
			known:   "hostfs linux rename/09.t:2 reason\n",
			logs:    []string{failingRun},
			wantErr: true,
		},
		{
			name:    "entry of another file system does not cover the failure",
			known:   "ext4lite windows rename/09.t:2 reason\n",
			logs:    []string{failingRun},
			wantErr: true,
		},
		{
			name:      "crash fails the run as a whole-file failure",
			known:     "",
			logs:      []string{crashedRun},
			wantErr:   true,
			wantLines: []string{"FAIL: link/00.t:* rc=139 plan=5 reported=1"},
		},
		{
			name:  "whole-file entry covers a crash and numbered failures",
			known: "hostfs windows link/00.t:* reason\nhostfs windows rename/09.t:* reason\n",
			logs:  []string{crashedRun, failingRun},
		},
		{
			name:      "entry for a test that passed is stale",
			known:     "hostfs windows chmod/00.t:1 fixed long ago\n",
			logs:      []string{passingRun},
			wantErr:   true,
			wantLines: []string{"STALE:", "chmod/00.t:1 passed"},
		},
		{
			name:  "entry for a file that did not run is not stale",
			known: "hostfs windows mknod/03.t:4 reason\n",
			logs:  []string{passingRun},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := runReport(t, tc.known, tc.logs...)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, want error %v\n%s", err, tc.wantErr, out)
			}
			if err != nil && !errors.Is(err, errMismatch) {
				t.Fatalf("err = %v, want %v", err, errMismatch)
			}
			for _, want := range tc.wantLines {
				if !strings.Contains(out, want) {
					t.Errorf("output lacks %q:\n%s", want, out)
				}
			}
		})
	}
}

func TestReportRejectsTruncatedOutput(t *testing.T) {
	_, err := runReport(t, "", "@@ BEGIN open/00.t\n1..2\nok 1\n")
	if err == nil || errors.Is(err, errMismatch) {
		t.Fatalf("err = %v, want a parse error", err)
	}
}

func TestReportRejectsEntryWithoutReason(t *testing.T) {
	_, err := runReport(t, "hostfs windows open/00.t:1\n", passingRun)
	if !errors.Is(err, errBadEntry) {
		t.Fatalf("err = %v, want %v", err, errBadEntry)
	}
}
