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

// Package sandboxrpc bounds requests across the worker boundary.
package sandboxrpc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/rpc"
	"sync"
)

const maxFrame = 1 << 20
const maxRPCFrame = 128 << 10
const maxPending = 256

type frame struct {
	Sequence uint64
	Method   string
	Error    string
	Body     json.RawMessage
}

type codec struct {
	connection io.ReadWriteCloser
	writeMu    sync.Mutex
	body       json.RawMessage
	closeOnce  sync.Once
	closed     chan struct{}
	pending    chan struct{}
	closeErr   error
}

// NewClient takes ownership of connection. Close the client to stop pending calls.
func NewClient(connection io.ReadWriteCloser) *rpc.Client {
	return rpc.NewClientWithCodec(&clientCodec{codec: newCodec(connection)})
}

func newCodec(connection io.ReadWriteCloser) *codec {
	return &codec{connection: connection, closed: make(chan struct{}), pending: make(chan struct{}, maxPending)}
}

func (c *codec) read() (frame, error) {
	var value frame
	if err := readMessage(c.connection, &value, maxRPCFrame); err != nil {
		return frame{}, err
	}
	if len(value.Method) > 128 {
		return frame{}, errors.New("sandboxrpc: method name exceeds 128 bytes")
	}
	c.body = value.Body
	return value, nil
}

// ReadMessage reads one bounded JSON message.
func ReadMessage(reader io.Reader, value any) error {
	return readMessage(reader, value, maxFrame)
}

func readMessage(reader io.Reader, value any, limit uint32) error {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return err
	}
	size := binary.LittleEndian.Uint32(header[:])
	if size == 0 || size > limit {
		return fmt.Errorf("sandboxrpc: invalid frame size %d", size)
	}
	data := make([]byte, int(size))
	if _, err := io.ReadFull(reader, data); err != nil {
		return err
	}
	return json.Unmarshal(data, value)
}

func (c *codec) write(value frame, body any) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	value.Body = data
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return writeMessage(c.connection, value, maxRPCFrame)
}

// WriteMessage writes one bounded JSON message.
func WriteMessage(writer io.Writer, value any) error {
	return writeMessage(writer, value, maxFrame)
}

func writeMessage(writer io.Writer, value any, limit int) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > limit {
		return errors.New("sandboxrpc: response exceeds the frame limit")
	}
	var header [4]byte
	binary.LittleEndian.PutUint32(header[:], uint32(len(encoded)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, encoded)
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func (c *codec) readBody(body any) error {
	defer func() { c.body = nil }()
	if body == nil {
		return nil
	}
	return json.Unmarshal(c.body, body)
}

func (c *codec) Close() error {
	c.closeOnce.Do(func() { close(c.closed); c.closeErr = c.connection.Close() })
	return c.closeErr
}

type clientCodec struct{ *codec }

func (c *clientCodec) WriteRequest(request *rpc.Request, body any) error {
	return c.write(frame{Sequence: request.Seq, Method: request.ServiceMethod}, body)
}
func (c *clientCodec) ReadResponseHeader(response *rpc.Response) error {
	value, err := c.read()
	if err != nil {
		return err
	}
	response.Seq, response.Error = value.Sequence, value.Error
	return nil
}
func (c *clientCodec) ReadResponseBody(body any) error { return c.readBody(body) }

// Server registers one service and owns its connection.
// Close interrupts request reads. The service must stop its operations before Serve returns.
type Server struct {
	server *rpc.Server
	codec  *serverCodec
}

func NewServer(connection io.ReadWriteCloser, name string, service any) (*Server, error) {
	server := rpc.NewServer()
	if err := server.RegisterName(name, service); err != nil {
		return nil, err
	}
	return &Server{server: server, codec: &serverCodec{codec: newCodec(connection)}}, nil
}
func (s *Server) Serve()       { s.server.ServeCodec(s.codec) }
func (s *Server) Close() error { return s.codec.Close() }

// Register adds a service before Serve starts.
func (s *Server) Register(name string, service any) error {
	return s.server.RegisterName(name, service)
}

type serverCodec struct{ *codec }

func (c *serverCodec) ReadRequestHeader(request *rpc.Request) error {
	select {
	case c.pending <- struct{}{}:
	case <-c.closed:
		return io.EOF
	}
	value, err := c.read()
	if err != nil {
		<-c.pending
		return err
	}
	request.Seq, request.ServiceMethod = value.Sequence, value.Method
	return nil
}
func (c *serverCodec) ReadRequestBody(body any) error { return c.readBody(body) }
func (c *serverCodec) WriteResponse(response *rpc.Response, body any) error {
	defer func() { <-c.pending }()
	err := c.write(frame{Sequence: response.Seq, Error: response.Error}, body)
	if err != nil {
		_ = c.Close()
	}
	return err
}

// Pipe joins the read and write ends of two inherited pipes.
type Pipe struct {
	Reader io.ReadCloser
	Output io.WriteCloser
}

func (p *Pipe) Read(data []byte) (int, error)  { return p.Reader.Read(data) }
func (p *Pipe) Write(data []byte) (int, error) { return p.Output.Write(data) }
func (p *Pipe) Close() error                   { return errors.Join(p.Reader.Close(), p.Output.Close()) }
