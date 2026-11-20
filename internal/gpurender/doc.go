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

// Package gpurender starts the GPU renderer process (gvx-gpu-renderer) of one
// sandbox and runs the protocol of package gpuproto with it.
//
// Start must run before the host lockdown: it creates a socketpair and starts
// a process. The renderer inherits its end of the socketpair as descriptor 3,
// confines itself, and answers HELLO. The Client then serves concurrent calls:
// a call writes one request frame, and one reader goroutine matches each reply
// to its request by sequence number. Blob replies carry a POSIX shared-memory
// descriptor in an SCM_RIGHTS message.
//
// The renderer is untrusted. A protocol violation, end of file, process exit,
// or reply timeout loses the renderer. On loss, the Client kills the process,
// fails every pending and later call with gpuproto.ErrRendererLost, and
// reports the loss once to EventSink. The Client never starts a second process.
//
// The renderer runs only on darwin/arm64. On every other OS, Start returns
// ErrUnsupported.
package gpurender
