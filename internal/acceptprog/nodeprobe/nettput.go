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

//go:build linux

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"time"
)

// tputChunk is the size of one read or write of the throughput checks.
const tputChunk = 64 << 10

// tputDownload reads mib MiB from the server at addr and returns the rate in
// MiB/s. The request line is "D <bytes>\n", and the server answers with that
// many bytes.
func tputDownload(addr string, mib int) (float64, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	size := int64(mib) << 20
	start := time.Now()
	if _, err := fmt.Fprintf(c, "D %d\n", size); err != nil {
		return 0, err
	}
	n, err := io.Copy(io.Discard, io.LimitReader(c, size))
	if err != nil || n != size {
		return 0, fmt.Errorf("downloaded %d of %d bytes: %v", n, size, err)
	}
	return float64(mib) / time.Since(start).Seconds(), nil
}

// tputUpload writes mib MiB to the server at addr and returns the rate in
// MiB/s. The request line is "U <bytes>\n". The server reads that many bytes
// and answers "OK\n", so the rate covers delivery and not only the send buffer.
func tputUpload(addr string, mib int) (float64, error) {
	c, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	size := int64(mib) << 20
	start := time.Now()
	if _, err := fmt.Fprintf(c, "U %d\n", size); err != nil {
		return 0, err
	}
	chunk := make([]byte, tputChunk)
	for sent := int64(0); sent < size; {
		n := min(int64(len(chunk)), size-sent)
		if _, err := c.Write(chunk[:n]); err != nil {
			return 0, err
		}
		sent += n
	}
	if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || line != "OK\n" {
		return 0, fmt.Errorf("the server answered %q with error %v", line, err)
	}
	return float64(mib) / time.Since(start).Seconds(), nil
}

// tputChecks measures the TCP throughput of the guest to the server at addr, in
// MiB/s, for a download and an upload of mib MiB. The checks print the rates.
func tputChecks(addr string, mib int) []check {
	return []check{
		{"download", func() error {
			rate, err := tputDownload(addr, mib)
			if err == nil {
				fmt.Printf("TPUT download %.1f MiB/s\n", rate)
			}
			return err
		}},
		{"upload", func() error {
			rate, err := tputUpload(addr, mib)
			if err == nil {
				fmt.Printf("TPUT upload %.1f MiB/s\n", rate)
			}
			return err
		}},
	}
}
