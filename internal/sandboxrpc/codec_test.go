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

package sandboxrpc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/rpc"
	"testing"
	"time"
)

type EchoRequest struct {
	Data       []byte
	ReplyBytes int
}
type EchoReply struct{ Data []byte }
type echoService struct{}

func (*echoService) Echo(request EchoRequest, reply *EchoReply) error {
	if request.ReplyBytes != 0 {
		reply.Data = make([]byte, request.ReplyBytes)
	} else {
		reply.Data = bytes.Clone(request.Data)
	}
	return nil
}

func testServer(t *testing.T) (net.Conn, *Server, <-chan struct{}) {
	t.Helper()
	left, right := net.Pipe()
	server, err := NewServer(left, "Echo", &echoService{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { server.Serve(); close(done) }()
	t.Cleanup(func() { server.Close(); right.Close(); <-done })
	return right, server, done
}

func TestConcurrentCallsKeepResponsesSeparated(t *testing.T) {
	connection, _, _ := testServer(t)
	client := NewClient(connection)
	defer client.Close()
	results := make(chan error, 64)
	for index := range 64 {
		go func() {
			input := []byte(fmt.Sprintf("request-%d\x00", index))
			var reply EchoReply
			err := client.Call("Echo.Echo", EchoRequest{Data: input}, &reply)
			if err == nil && !bytes.Equal(reply.Data, input) {
				err = fmt.Errorf("request %d received %q", index, reply.Data)
			}
			results <- err
		}()
	}
	for range 64 {
		if err := <-results; err != nil {
			t.Error(err)
		}
	}
}

func TestOversizedFrameClosesBeforeReadingBody(t *testing.T) {
	connection, _, _ := testServer(t)
	if err := connection.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], 1<<30)
	if _, err := connection.Write(header[:]); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	if _, err := connection.Read(data[:]); err != io.EOF {
		t.Fatalf("oversized frame: %v; want EOF", err)
	}
}

func TestOversizedResponseStopsPendingCall(t *testing.T) {
	connection, _, _ := testServer(t)
	client := NewClient(connection)
	defer client.Close()
	call := client.Go("Echo.Echo", EchoRequest{ReplyBytes: 200000}, new(EchoReply), make(chan *rpc.Call, 1))
	select {
	case result := <-call.Done:
		if result.Error == nil {
			t.Fatal("oversized response succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("oversized response left the call blocked")
	}
}
