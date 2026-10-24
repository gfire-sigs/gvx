//go:build linux || darwin

package gvxshim

import (
	"os"
	"strings"
	"testing"
)

func TestProcessDeleteWithoutTaskPath(t *testing.T) {
	f := newProcessFixture(t)
	record := f.start()
	lease := holdProcessLease(t, record)
	client, ctx := processClient(t, record)
	assertProcessConnect(t, ctx, client, record)
	if err := os.Remove(strings.TrimPrefix(record.Task.Address, "unix://")); err != nil {
		t.Fatalf("make Task path unavailable: %v", err)
	}
	assertProcessConnect(t, ctx, client, record)
	if _, stderr, err := f.command(ctx, "delete", nil); err != nil {
		t.Fatalf("delete with unavailable Task path: %v; stderr=%s", err, stderr)
	}
	awaitProcessExit(t, lease, record)
}
