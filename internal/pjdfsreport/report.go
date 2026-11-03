package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// wholeFile is the test number of a known failure that covers every failure
// of one file, including a crash or a short plan.
const wholeFile = "*"

var (
	planRE  = regexp.MustCompile(`^1\.\.([0-9]+)`)
	okRE    = regexp.MustCompile(`^ok [0-9]+`)
	notOkRE = regexp.MustCompile(`^not ok ([0-9]+)(.*)$`)
	beginRE = regexp.MustCompile(`^@@ BEGIN (\S+)$`)
	endRE   = regexp.MustCompile(`^@@ END (\S+) rc=([0-9]+)$`)
)

// failure is one failed test of a file. Num is a test number, or wholeFile
// when the file did not complete its plan.
type failure struct {
	File   string
	Num    string
	Detail string
}

func (f failure) key() string { return f.File + ":" + f.Num }

// fileResult holds the failures of one test file that ran to its END marker.
type fileResult struct {
	File     string
	Failures []failure
}

// parseRuns reads guest output and returns one result for each test file.
// It rejects a file with a BEGIN marker and no END marker, because the
// guest stopped before the file completed.
func parseRuns(r io.Reader) ([]fileResult, error) {
	var (
		results []fileResult
		cur     string
		plan    = -1
		passed  int
		failed  []failure
	)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if m := beginRE.FindStringSubmatch(line); m != nil {
			if cur != "" {
				return nil, fmt.Errorf("%s: no END marker before %s", cur, m[1])
			}
			cur, plan, passed, failed = m[1], -1, 0, nil
			continue
		}
		if cur == "" {
			continue
		}
		if m := endRE.FindStringSubmatch(line); m != nil {
			if m[1] != cur {
				return nil, fmt.Errorf("END marker for %s inside %s", m[1], cur)
			}
			rc, _ := strconv.Atoi(m[2])
			if rc != 0 || plan < 0 || passed+len(failed) != plan {
				failed = append(failed, failure{
					File:   cur,
					Num:    wholeFile,
					Detail: fmt.Sprintf("rc=%d plan=%d reported=%d", rc, plan, passed+len(failed)),
				})
			}
			results = append(results, fileResult{File: cur, Failures: failed})
			cur = ""
			continue
		}
		switch {
		case plan < 0 && planRE.MatchString(line):
			plan, _ = strconv.Atoi(planRE.FindStringSubmatch(line)[1])
		case okRE.MatchString(line):
			passed++
		case notOkRE.MatchString(line):
			m := notOkRE.FindStringSubmatch(line)
			if strings.Contains(m[2], "# TODO") {
				passed++
				continue
			}
			failed = append(failed, failure{File: cur, Num: m[1], Detail: strings.TrimSpace(strings.TrimPrefix(m[2], " -"))})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if cur != "" {
		return nil, fmt.Errorf("%s: output ends before the END marker", cur)
	}
	return results, nil
}

// knownFailure is one entry of the known-failures file.
type knownFailure struct {
	Line   int
	FS     string
	OS     string
	File   string
	Num    string
	Reason string
}

func (k knownFailure) key() string { return k.File + ":" + k.Num }

var errBadEntry = errors.New("malformed known-failures entry")

// parseKnown reads lines of the form "<fs> <os> <file>:<num|*> <reason>".
// It ignores blank lines and lines that start with "#". Every entry needs a
// reason, so that the list states why the host cannot pass the test.
func parseKnown(r io.Reader) ([]knownFailure, error) {
	var out []knownFailure
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			return nil, fmt.Errorf("%w: line %d needs a file system, an OS, a test, and a reason", errBadEntry, n)
		}
		file, num, ok := strings.Cut(fields[2], ":")
		if !ok || file == "" || num == "" {
			return nil, fmt.Errorf("%w: line %d: test %q is not <file>:<num|*>", errBadEntry, n, fields[2])
		}
		if num != wholeFile {
			if _, err := strconv.Atoi(num); err != nil {
				return nil, fmt.Errorf("%w: line %d: test number %q", errBadEntry, n, num)
			}
		}
		out = append(out, knownFailure{
			Line: n, FS: fields[0], OS: fields[1], File: file, Num: num,
			Reason: strings.Join(fields[3:], " "),
		})
	}
	return out, sc.Err()
}

// verdict is the result of the comparison.
type verdict struct {
	Files      int
	Expected   []failure
	Unexpected []failure
	// Stale lists known failures of this file system and OS for files that
	// ran and passed the listed test.
	Stale []knownFailure
}

func (v verdict) ok() bool { return len(v.Unexpected) == 0 && len(v.Stale) == 0 }

// compare matches the failures against the known failures of fs and goos.
func compare(results []fileResult, known []knownFailure, fs, goos string) verdict {
	byKey := make(map[string]knownFailure)
	for _, k := range known {
		if k.FS == fs && k.OS == goos {
			byKey[k.key()] = k
		}
	}
	used := make(map[string]bool)
	ran := make(map[string]bool)
	v := verdict{Files: len(results)}
	for _, res := range results {
		ran[res.File] = true
		for _, f := range res.Failures {
			key := f.key()
			if _, ok := byKey[key]; !ok {
				key = f.File + ":" + wholeFile
			}
			if _, ok := byKey[key]; !ok {
				v.Unexpected = append(v.Unexpected, f)
				continue
			}
			used[key] = true
			v.Expected = append(v.Expected, f)
		}
	}
	for key, k := range byKey {
		if ran[k.File] && !used[key] {
			v.Stale = append(v.Stale, k)
		}
	}
	sort.Slice(v.Stale, func(i, j int) bool { return v.Stale[i].Line < v.Stale[j].Line })
	return v
}
