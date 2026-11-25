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

//go:build unix

package rungvx

import (
	"encoding/base64"
	"os"
	"strconv"
	"syscall"
	"testing"
)

func TestCLIPushAuthFD(t *testing.T) {
	srcReg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.run("pull", "-keep-blobs", srcReg.ref("v1")).mustSucceed(t, "pull")
	srcReg.Close()

	dstReg := startCLIPushRegistry(t, "fduser", "fdpass")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	defer r.Close()
	payload := base64.StdEncoding.EncodeToString([]byte(`{"username":"fduser","password":"fdpass"}`))
	if _, err := w.WriteString(payload); err != nil {
		_ = w.Close()
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	dupFD, err := syscall.Dup(int(r.Fd()))
	if err != nil {
		t.Fatalf("syscall.Dup: %v", err)
	}
	env.run("push", "--auth-fd", strconv.Itoa(dupFD), srcReg.ref("v1"), dstReg.host+"/fd/app:v1").mustSucceed(t, "push --auth-fd")
}
