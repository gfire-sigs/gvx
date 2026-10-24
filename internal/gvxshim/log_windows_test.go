package gvxshim

import (
	"testing"
	"time"
)

func TestWindowsLogPipeRejectsCrossInstanceCollision(t *testing.T) {
	first := platformFixture(t)
	second := platformFixture(t)
	file, firstRef, err := createDiagnostics(first)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	file, secondRef, err := createDiagnostics(second)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	firstLog, err := openLog(t.Context(), first, firstRef, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer firstLog.Close(t.Context())
	if secondLog, err := openLog(t.Context(), second, secondRef, time.Second); err == nil {
		secondLog.Close(t.Context())
		t.Fatal("log pipe collision attached to another instance")
	}
	if err := firstLog.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	secondLog, err := openLog(t.Context(), second, secondRef, time.Second)
	if err != nil {
		t.Fatalf("released log name cannot be rebound: %v", err)
	}
	if err := secondLog.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
}
