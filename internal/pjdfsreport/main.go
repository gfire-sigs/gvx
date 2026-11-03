// Command pjdfsreport compares the pjdfstest output of guest runs with the
// list of known failures for one file system and one host OS.
//
// The guest harness (scripts/pjdfstest/guest-run.sh) brackets the TAP output of
// each test file with "@@ BEGIN <file>" and "@@ END <file> rc=<status>". A test
// file passes when its status is 0, it prints a plan, and every planned test
// prints "ok" or a "not ok ... # TODO" line.
//
// The command exits with status 1 when a failure is not in the list, or when
// a listed failure of a file that ran did not occur.
//
//	pjdfsreport -fs hostfs -os linux -known known-failures.txt out1.log out2.log
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "pjdfsreport:", err)
		os.Exit(1)
	}
}

var errMismatch = errors.New("results differ from the known failures")

func run(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("pjdfsreport", flag.ContinueOnError)
	fsName := fs.String("fs", "", "file system driver of the run: ext4lite or hostfs")
	goos := fs.String("os", "", "host OS of the run: linux, windows, or darwin")
	knownPath := fs.String("known", "", "path of the known-failures file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fsName == "" || *goos == "" || *knownPath == "" || fs.NArg() == 0 {
		return errors.New("usage: pjdfsreport -fs FS -os OS -known FILE LOG...")
	}

	kf, err := os.Open(*knownPath)
	if err != nil {
		return err
	}
	known, err := parseKnown(kf)
	kf.Close()
	if err != nil {
		return fmt.Errorf("%s: %w", *knownPath, err)
	}

	var results []fileResult
	for _, path := range fs.Args() {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		res, err := parseRuns(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		results = append(results, res...)
	}
	if len(results) == 0 {
		return errors.New("no test file ran")
	}

	v := compare(results, known, *fsName, *goos)
	fmt.Fprintf(stdout, "pjdfstest %s on %s: %d files, %d known failures, %d unexpected failures, %d stale entries\n",
		*fsName, *goos, v.Files, len(v.Expected), len(v.Unexpected), len(v.Stale))
	for _, f := range v.Expected {
		fmt.Fprintf(stdout, "known: %s %s\n", f.key(), f.Detail)
	}
	for _, f := range v.Unexpected {
		fmt.Fprintf(stdout, "FAIL: %s %s\n", f.key(), f.Detail)
	}
	for _, k := range v.Stale {
		fmt.Fprintf(stdout, "STALE: %s:%d %s passed; remove the entry (%s)\n", *knownPath, k.Line, k.key(), k.Reason)
	}
	if !v.ok() {
		return errMismatch
	}
	return nil
}
