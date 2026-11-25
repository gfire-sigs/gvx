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

// Command gpuprobe opens the virtio-gpu render node and issues one
// DRM_IOCTL_VIRTGPU_CONTEXT_INIT ioctl for the requested mode.
// Exit codes: 0 for alive, 2 for EIO (renderer lost), 1 for probe error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"syscall"
	"time"
	"unsafe"
)

const (
	// cmdVirtgpuContextInit encodes DRM_IOCTL_VIRTGPU_CONTEXT_INIT:
	// _IOWR('d', 0x4b, struct drm_virtgpu_context_init).
	cmdVirtgpuContextInit = 0xc010644b

	virtgpuContextParamCapsetID = 0x0001
	virtgpuCapsetVirgl2         = 2
	virtgpuCapsetVenus          = 4

	exitAlive = 0
	exitError = 1
	exitLost  = 2

	maxENOSPCTries = 5
	enospcWait     = 50 * time.Millisecond
)

type virtgpuContextSetParam struct {
	Param uint64
	Value uint64
}

type virtgpuContextInit struct {
	NumParams    uint32
	Pad          uint32
	CtxSetParams uint64
}

func run() int {
	devPath := flag.String("device", "/dev/dri/renderD128", "render node path")
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "gpuprobe: usage: gpuprobe [-device path] <venus|virgl>")
		return exitError
	}

	var capset uint64
	switch flag.Arg(0) {
	case "venus":
		capset = virtgpuCapsetVenus
	case "virgl":
		capset = virtgpuCapsetVirgl2
	default:
		fmt.Fprintf(os.Stderr, "gpuprobe: unknown mode %q\n", flag.Arg(0))
		return exitError
	}

	fd, err := syscall.Open(*devPath, syscall.O_RDWR|syscall.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gpuprobe: open %s: %v\n", *devPath, err)
		if errors.Is(err, syscall.EIO) {
			return exitLost
		}
		return exitError
	}
	defer syscall.Close(fd)

	params := [1]virtgpuContextSetParam{
		{Param: virtgpuContextParamCapsetID, Value: capset},
	}
	req := virtgpuContextInit{
		NumParams:    1,
		CtxSetParams: uint64(uintptr(unsafe.Pointer(&params[0]))),
	}

	enospcCount := 0
	for {
		_, _, errno := syscall.Syscall(
			syscall.SYS_IOCTL,
			uintptr(fd),
			uintptr(cmdVirtgpuContextInit),
			uintptr(unsafe.Pointer(&req)),
		)
		runtime.KeepAlive(&params)
		runtime.KeepAlive(&req)

		switch errno {
		case 0:
			return exitAlive
		case syscall.EINTR:
			continue
		case syscall.ENOSPC:
			enospcCount++
			if enospcCount >= maxENOSPCTries {
				fmt.Fprintf(os.Stderr, "gpuprobe: CONTEXT_INIT capset %d: %v\n", capset, errno)
				return exitError
			}
			time.Sleep(enospcWait)
			continue
		case syscall.EIO:
			fmt.Fprintf(os.Stderr, "gpuprobe: CONTEXT_INIT capset %d: %v\n", capset, errno)
			return exitLost
		default:
			fmt.Fprintf(os.Stderr, "gpuprobe: CONTEXT_INIT capset %d: %v\n", capset, errno)
			return exitError
		}
	}
}

func main() {
	os.Exit(run())
}
