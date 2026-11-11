// Command gostateify generates reflection-free pkg/state code for Go packages.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"z.gfire.dev/gvx/tools/gostateify/stateify"
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	*s = append(*s, val)
	return nil
}

func main() {
	if err := runCLI(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gostateify: %v\n", err)
		os.Exit(1)
	}
}

func runCLI(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gostateify", flag.ContinueOnError)
	fs.SetOutput(stderr)

	var pkgs stringSliceFlag
	var opts stateify.Options
	fs.Var(&pkgs, "pkg", "package path, directory, or ... pattern (repeatable or comma-separated)")
	fs.StringVar(&opts.PackagesFile, "packages-file", "", "file listing registered packages, one per line")
	fs.StringVar(&opts.RootDir, "root", ".", "repository or module root directory")
	fs.BoolVar(&opts.PartitionByTier, "partition-by-tier", true, "partition generated files by Tier 1/2/3 isolation rules")
	fs.BoolVar(&opts.Tier2Only, "tier2-only", false, "emit or verify only Tier 2 sibling autogen files")
	fs.BoolVar(&opts.Check, "check", false, "verify on-disk *_state_autogen.go files match generated output")

	if err := fs.Parse(args); err != nil {
		return err
	}
	opts.Packages = append([]string(pkgs), fs.Args()...)

	report, err := stateify.Run(opts)
	if err != nil {
		return err
	}
	if opts.Check {
		fmt.Fprintf(stdout, "gostateify: verified %d file(s) across %d package(s)\n", report.FilesVerified, report.PackagesInspected)
		return nil
	}
	for _, p := range report.FilesWritten {
		fmt.Fprintf(stdout, "wrote %s\n", p)
	}
	for _, p := range report.FilesRemoved {
		fmt.Fprintf(stdout, "removed %s\n", p)
	}
	return nil
}
