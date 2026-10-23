//go:build linux

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func main() {
	runtime.GOMAXPROCS(1)
	mode := flag.String("mode", "hello", "Workload: hello, idle, cpu, syscall, or http")
	count := flag.Uint64("count", 10000, "Loop iterations")
	port := flag.Uint("port", 8080, "HTTP listen port")
	flag.Parse()
	if *count == 0 || *count > 1_000_000_000 || *port == 0 || *port > 65535 {
		fmt.Fprintln(os.Stderr, "count or port outside the supported range")
		os.Exit(2)
	}
	if err := run(*mode, *count, *port); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func emit(value any) error {
	return json.NewEncoder(os.Stdout).Encode(value)
}

func run(mode string, count uint64, port uint) error {
	switch mode {
	case "hello":
		return emit(map[string]any{"mode": mode, "arch": runtime.GOARCH})
	case "idle":
		if err := emit(map[string]any{"mode": mode, "ready": true}); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, os.Stdin)
		return err
	case "cpu":
		value := uint64(1)
		start := time.Now()
		for range count {
			value ^= value << 13
			value ^= value >> 7
			value ^= value << 17
		}
		return emit(map[string]any{"mode": mode, "count": count, "checksum": value, "elapsed_ns": time.Since(start).Nanoseconds()})
	case "syscall":
		start := time.Now()
		for range count {
			pid, _, errno := syscall.RawSyscall(syscall.SYS_GETPID, 0, 0, 0)
			if errno != 0 || pid == 0 {
				return fmt.Errorf("getpid returned pid=%d errno=%d", pid, errno)
			}
		}
		return emit(map[string]any{"mode": mode, "count": count, "elapsed_ns": time.Since(start).Nanoseconds()})
	case "http":
		return serve(port)
	default:
		return fmt.Errorf("unknown mode %q", mode)
	}
}

func serve(port uint) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}
	defer listener.Close()
	payload := strings.Repeat("a", 1024)
	server := &http.Server{
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = io.WriteString(w, payload)
		}),
	}
	if err := emit(map[string]any{"mode": "http", "ready": true}); err != nil {
		return err
	}
	go func() {
		_, _ = io.Copy(io.Discard, os.Stdin)
		_ = server.Close()
	}()
	err = server.Serve(listener)
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}
