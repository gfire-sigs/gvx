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

// Package gpuproto defines the protocol between the Sentry and the GPU
// renderer process (gvx-gpu-renderer) of one sandbox.
//
// The two processes share one AF_UNIX SOCK_STREAM socketpair. The renderer
// inherits its end as descriptor SocketFD. Each message is a 24-byte
// little-endian Header and then PayloadLen payload bytes. The Sentry sends
// requests; the renderer sends one reply for each request, with the same
// Seq, and events with Seq 0. A BLOB_CREATE reply for a mappable blob and
// every successful RES_CREATE reply carry one POSIX shared-memory descriptor
// in an SCM_RIGHTS control message. The renderer attaches that control message
// to the sendmsg call with the first byte of its header.
//
// The renderer is untrusted. A receiver rejects a message that breaks any
// rule of ParseHeader or of the payload decoders, and then stops using the
// connection.
//
// This package is the single definition of the format. CHeader writes the
// same constants and layouts as ext/workers/gpu-renderer/gvx_gpu_protocol.h, and a test
// fails when the checked-in header differs from the generated text.
package gpuproto

//go:generate go run ./gen -o ../../../workers/gpu-renderer/gvx_gpu_protocol.h
