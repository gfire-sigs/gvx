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

package gvx

import (
	"errors"
	"net/rpc"

	"z.gfire.dev/gvx/pkg/hostlockdown"
)

type consoleInputService struct{ reader *hostlockdown.ConsoleReader }

func (s *consoleInputService) Read(length int, reply *NetworkReply) error {
	if length <= 0 || length > brokerDatagramSize {
		return errors.New("gvx: invalid console read size")
	}
	data := make([]byte, length)
	n, err := s.reader.Read(data)
	reply.Data = data[:n]
	reply.Count = n
	reply.setError(err)
	return nil
}

type consoleInputProxy struct{ client *rpc.Client }

func (p *consoleInputProxy) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	var reply NetworkReply
	if err := p.client.Call("Input.Read", min(len(data), brokerDatagramSize), &reply); err != nil {
		return 0, err
	}
	if reply.Count != len(reply.Data) || len(reply.Data) > len(data) {
		return 0, errors.New("gvx: invalid console read result")
	}
	return copy(data, reply.Data), reply.operationError()
}
