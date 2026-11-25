package main

import (
	"bytes"
	"slices"
	"strings"
	"testing"
)

func TestCollectWatchlistChanges(t *testing.T) {
	t.Parallel()

	oldTree := &UpstreamTree{
		Files: map[string][]byte{
			"pkg/sentry/vfs/options.go":        []byte("old options"),
			"pkg/sentry/vfs/vfs.go":            []byte("unchanged"),
			"pkg/sentry/kernel/auth/cap.go":    []byte("old cap"),
			"pkg/sentry/fsimpl/tmpfs/xattr.go": []byte("deleted"),
			"pkg/tcpip/stack/stack.go":         []byte("old stack"),
		},
	}
	newTree := &UpstreamTree{
		Files: map[string][]byte{
			"pkg/sentry/vfs/options.go":           []byte("new options"),
			"pkg/sentry/vfs/vfs.go":               []byte("unchanged"),
			"pkg/sentry/kernel/auth/cap.go":       []byte("old cap"),
			"pkg/sentry/fsimpl/memxattr/xattr.go": []byte("added"),
			"pkg/tcpip/stack/stack.go":            []byte("new stack"),
		},
	}

	got := CollectWatchlistChanges(oldTree, newTree)
	want := []string{
		"pkg/sentry/fsimpl/memxattr/xattr.go",
		"pkg/sentry/fsimpl/tmpfs/xattr.go",
		"pkg/sentry/vfs/options.go",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("CollectWatchlistChanges = %v, want %v", got, want)
	}
	if got := CollectWatchlistChanges(nil, newTree); len(got) != 0 {
		t.Fatalf("CollectWatchlistChanges(nil, new) = %v, want empty", got)
	}
}

func TestFilterWatchlistPathsAndPrintNotice(t *testing.T) {
	t.Parallel()

	got := FilterWatchlistPaths([]string{
		"./pkg/sentry/vfs/options.go",
		"pkg/sentry/vfs/options.go",
		"pkg/sentry/kernel/auth/user_namespace.go",
		"pkg/tcpip/tcpip.go",
		"",
	})
	want := []string{
		"pkg/sentry/kernel/auth/user_namespace.go",
		"pkg/sentry/vfs/options.go",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("FilterWatchlistPaths = %v, want %v", got, want)
	}

	var buf bytes.Buffer
	printWatchlistNotice(&buf, nil)
	if buf.Len() != 0 {
		t.Fatalf("printWatchlistNotice(nil) wrote %q, want empty", buf.String())
	}

	printWatchlistNotice(&buf, got)
	out := buf.String()
	for _, needle := range []string{"2 upstream file(s)", "watchlist: pkg/sentry/vfs/options.go", "watchlist: pkg/sentry/kernel/auth/user_namespace.go"} {
		if !strings.Contains(out, needle) {
			t.Fatalf("printWatchlistNotice output %q missing %q", out, needle)
		}
	}
}
