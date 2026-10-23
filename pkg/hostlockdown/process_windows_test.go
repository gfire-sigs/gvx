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

package hostlockdown

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

type appContainerInput struct{ Workspace, Secret, TCP, UDP string }
type appContainerReport struct {
	Status                                     Status
	FileErrors                                 []string
	WriteError, TCPError, UDPError, SpawnError string
}

func runAppContainerWorker() error {
	var input appContainerInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		return err
	}
	root, err := os.OpenRoot(input.Workspace)
	if err != nil {
		return err
	}
	defer root.Close()
	var report appContainerReport
	var winsock windows.WSAData
	if err := windows.WSAStartup(0x202, &winsock); err != nil {
		return err
	}
	connection, warmErr := net.DialTimeout("udp", input.UDP, time.Second)
	if warmErr != nil && !errors.Is(warmErr, windows.WSAEACCES) {
		return fmt.Errorf("initialize UDP provider: %w", warmErr)
	}
	if connection != nil {
		connection.Close()
	}
	report.Status, err = Apply(Options{Mounts: []HostMount{{Path: input.Workspace}}})
	if err != nil {
		return err
	}
	if err := exec.Command(os.Args[0]).Run(); err != nil {
		report.SpawnError = err.Error()
	}
	result := make(chan string, 8)
	release := make(chan struct{})
	done := make(chan struct{}, 8)
	for range 8 {
		go func() {
			runtime.LockOSThread()
			_, err := os.ReadFile(input.Secret)
			if !errors.Is(err, fs.ErrPermission) {
				result <- fmt.Sprintf("outside read: %v", err)
			} else {
				result <- ""
			}
			<-release
			done <- struct{}{}
		}()
	}
	for range 8 {
		report.FileErrors = append(report.FileErrors, <-result)
	}
	close(release)
	for range 8 {
		<-done
	}
	if err := root.WriteFile("worker.txt", []byte("confined"), 0o600); err != nil {
		report.WriteError = err.Error()
	}
	for _, target := range []struct {
		network, address string
		result           *string
	}{{"tcp", input.TCP, &report.TCPError}, {"udp", input.UDP, &report.UDPError}} {
		conn, err := net.DialTimeout(target.network, target.address, time.Second)
		if err == nil {
			err = conn.SetWriteDeadline(time.Now().Add(time.Second))
			if err == nil {
				_, err = conn.Write([]byte("forbidden"))
			}
			conn.Close()
		}
		if err != nil {
			*target.result = err.Error()
		}
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func TestAppContainerConfinesNewThreads(t *testing.T) {
	workspace := t.TempDir()
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("host-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	udpControl, err := net.Dial("udp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := udpControl.Write([]byte("control")); err != nil {
		t.Fatal(err)
	}
	udpControl.Close()
	if err := udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var packet [64]byte
	if n, _, err := udp.ReadFrom(packet[:]); err != nil || string(packet[:n]) != "control" {
		t.Fatalf("UDP control: %q, %v", packet[:n], err)
	}
	control, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		t.Fatalf("TCP control: %v", err)
	}
	control.Close()
	inputRead, inputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inputRead.Close()
	defer inputWrite.Close()
	outputRead, outputWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputRead.Close()
	defer outputWrite.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child, err := StartProcess(ProcessOptions{Executable: executable, Arguments: []string{"appcontainer-worker"}, Stdin: inputRead, Stdout: outputWrite, Stderr: outputWrite, WorkspacePath: workspace})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := child.Close(); err != nil {
			t.Error(err)
		}
	}()
	inputRead.Close()
	outputWrite.Close()
	input := appContainerInput{Workspace: workspace, Secret: secret, TCP: tcp.Addr().String(), UDP: udp.LocalAddr().String()}
	if err := json.NewEncoder(inputWrite).Encode(input); err != nil {
		t.Fatal(err)
	}
	var report appContainerReport
	if err := json.NewDecoder(outputRead).Decode(&report); err != nil {
		t.Fatal(err)
	}
	code, err := child.Wait()
	if err != nil || code != 0 {
		t.Fatalf("worker exit: %d, %v", code, err)
	}
	if len(report.FileErrors) != 8 {
		t.Fatalf("file probes: %v", report.FileErrors)
	}
	if !report.Status.Applied || !report.Status.AppContainer || !report.Status.NetworkOutboundBlocked || !report.Status.UnboundFileOpenBlocked {
		t.Errorf("AppContainer status: %+v", report.Status)
	}
	if report.SpawnError == "" {
		t.Error("AppContainer spawned a child")
	}
	for _, failure := range report.FileErrors {
		if failure != "" {
			t.Error(failure)
		}
	}
	if report.WriteError != "" {
		t.Errorf("workspace write: %s", report.WriteError)
	}
	data, err := os.ReadFile(filepath.Join(workspace, "worker.txt"))
	if err != nil || string(data) != "confined" {
		t.Errorf("workspace result: %q, %v", data, err)
	}
	if report.TCPError == "" {
		t.Error("AppContainer opened a TCP connection")
	}
	// Winsock can accept a datagram before WFP drops it.
	if err := udp.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := udp.ReadFrom(packet[:]); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("UDP delivery: %q, %v; want a timeout", packet[:n], err)
	}
}
