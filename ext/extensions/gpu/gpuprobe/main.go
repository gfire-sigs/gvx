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

// Command gpuprobe exercises the virtio-gpu render node and its sysfs tree
// inside a Linux guest.
//
// Usage:
//
//	gpuprobe absent
//	gpuprobe hold
//	gpuprobe fork-hold
//	gpuprobe fill [max]
//	gpuprobe full
//	gpuprobe virgl
//	gpuprobe virgl-fill [max]
package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	renderNodePath  = "/dev/dri/renderD128"
	sysfsDevLink    = "/sys/dev/char/226:128/device"
	sysfsClassDRM   = "/sys/class/drm"
	blobSize        = 0x4000
	aliasOffset     = 8
	aliasPattern    = uint64(0x1122334455667788)
	fencePollMs     = 2000
	holdSleepPeriod = 600 * time.Second

	// Gallium and virglrenderer resource constants for virgl buffer probes.
	pipeBuffer            = 0     // PIPE_BUFFER (gallium enum pipe_texture_target)
	virglFormatR8Unorm    = 64    // VIRGL_FORMAT_R8_UNORM (virgl_formats.h)
	virglBindVertexBuffer = 0x10  // VIRGL_BIND_VERTEX_BUFFER (virglrenderer.h)
	virglResSize          = 65536 // 64 KiB test buffer
)

const usageText = "usage: gpuprobe absent|hold|fork-hold|fill [max]|full|virgl|virgl-fill [max]"

func parseFillMax(args []string) int {
	if len(args) != 3 {
		return 0
	}
	n, err := strconv.Atoi(args[2])
	if err != nil || n < 1 {
		fmt.Fprintf(os.Stderr, "gpuprobe: invalid fill max %q\n", args[2])
		os.Exit(2)
	}
	return n
}

func main() {
	if len(os.Args) < 2 || len(os.Args) > 3 {
		fmt.Fprintln(os.Stderr, usageText)
		os.Exit(2)
	}
	mode := os.Args[1]
	if mode != "fill" && mode != "virgl-fill" && len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, usageText)
		os.Exit(2)
	}
	switch mode {
	case "absent":
		runAbsent()
	case "hold":
		runHold()
	case "fork-hold":
		runForkHold()
	case "fill":
		runFill(parseFillMax(os.Args))
	case "full":
		runFull()
	case "virgl":
		runVirgl()
	case "virgl-fill":
		runVirglFill(parseFillMax(os.Args))
	default:
		fmt.Fprintf(os.Stderr, "gpuprobe: unknown mode %q\n", mode)
		os.Exit(2)
	}
}

func errnoString(err error) string {
	if errno, ok := err.(unix.Errno); ok {
		if name := unix.ErrnoName(errno); name != "" {
			return name
		}
	}
	return err.Error()
}

func fail(step string, err error) {
	if errno, ok := err.(unix.Errno); ok {
		if name := unix.ErrnoName(errno); name != "" {
			fmt.Printf("FAIL %s: %s (%v)\n", step, name, errno)
			os.Exit(1)
		}
	}
	fmt.Printf("FAIL %s: %v\n", step, err)
	os.Exit(1)
}

func drmIoctl(fd int, req uint32, arg unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func runAbsent() {
	fd, err := unix.Open(renderNodePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		fail("open", errors.New("render node opened unexpectedly"))
	}
	if !errors.Is(err, unix.ENOENT) {
		fail("open", fmt.Errorf("got %v, want ENOENT", err))
	}
	var st unix.Stat_t
	err = unix.Stat(sysfsClassDRM, &st)
	if err == nil {
		fail("stat", errors.New("/sys/class/drm exists unexpectedly"))
	}
	if !errors.Is(err, unix.ENOENT) {
		fail("stat", fmt.Errorf("got %v, want ENOENT", err))
	}
	fmt.Println("ABSENT OK")
}

func openAndVersion() (int, string, int32, int32, int32) {
	fd, err := unix.Open(renderNodePath, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		fail("open", err)
	}
	var v drmVersion
	if err := drmIoctl(fd, cmdVersion, unsafe.Pointer(&v)); err != nil {
		fail("version", err)
	}
	nameBuf := make([]byte, v.NameLen)
	dateBuf := make([]byte, v.DateLen)
	descBuf := make([]byte, v.DescLen)
	if len(nameBuf) > 0 {
		v.Name = uint64(uintptr(unsafe.Pointer(&nameBuf[0])))
	}
	if len(dateBuf) > 0 {
		v.Date = uint64(uintptr(unsafe.Pointer(&dateBuf[0])))
	}
	if len(descBuf) > 0 {
		v.Desc = uint64(uintptr(unsafe.Pointer(&descBuf[0])))
	}
	if err := drmIoctl(fd, cmdVersion, unsafe.Pointer(&v)); err != nil {
		fail("version", err)
	}
	runtime.KeepAlive(nameBuf)
	runtime.KeepAlive(dateBuf)
	runtime.KeepAlive(descBuf)
	n := min(v.NameLen, uint64(len(nameBuf)))
	return fd, string(nameBuf[:n]), v.VersionMajor, v.VersionMinor, v.VersionPatchlevel
}

func initVenusContext(fd int) {
	params := [3]virtgpuContextSetParam{
		{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVenus},
		{Param: virtgpuContextParamNumRings, Value: 64},
		{Param: virtgpuContextParamPollRingsMask, Value: 0},
	}
	req := virtgpuContextInit{
		NumParams:    uint32(len(params)),
		CtxSetParams: uint64(uintptr(unsafe.Pointer(&params[0]))),
	}
	if err := drmIoctl(fd, cmdVirtgpuContextInit, unsafe.Pointer(&req)); err != nil {
		fail("context", err)
	}
	runtime.KeepAlive(&params)
}

func createMappableBlob(fd int) (resHandle, boHandle uint32) {
	req := virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		BlobID:    0,
		Size:      blobSize,
	}
	if err := drmIoctl(fd, cmdVirtgpuResourceCreateBlob, unsafe.Pointer(&req)); err != nil {
		fail("blob", err)
	}
	return req.ResHandle, req.BoHandle
}

func mapAndVerifyAlias(fd int, boHandle uint32, unmap bool) uint64 {
	mapReq := virtgpuMap{Handle: boHandle}
	if err := drmIoctl(fd, cmdVirtgpuMap, unsafe.Pointer(&mapReq)); err != nil {
		fail("map", err)
	}
	mapA, err := unix.Mmap(fd, int64(mapReq.Offset), blobSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		fail("mmap_a", err)
	}
	mapB, err := unix.Mmap(fd, int64(mapReq.Offset), blobSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		fail("mmap_b", err)
	}
	binary.LittleEndian.PutUint64(mapA[aliasOffset:aliasOffset+8], aliasPattern)
	got := binary.LittleEndian.Uint64(mapB[aliasOffset : aliasOffset+8])
	if got != aliasPattern {
		fail("alias", fmt.Errorf("read %#x, want %#x", got, aliasPattern))
	}
	if unmap {
		if err := unix.Munmap(mapA); err != nil {
			fail("munmap_a", err)
		}
		if err := unix.Munmap(mapB); err != nil {
			fail("munmap_b", err)
		}
	}
	return mapReq.Offset
}

func runHold() {
	fd, _, _, _, _ := openAndVersion()
	initVenusContext(fd)
	_, boHandle := createMappableBlob(fd)
	mapAndVerifyAlias(fd, boHandle, false)
	fmt.Println("HOLDING")
	time.Sleep(holdSleepPeriod)
}

func runForkHold() {
	cmd := exec.Command("/proc/self/exe", "hold")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fail("fork_pipe", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		fail("fork_start", err)
	}
	sc := bufio.NewScanner(stdout)
	for sc.Scan() {
		if sc.Text() == "HOLDING" {
			fmt.Println("CHILD_HOLDING")
			os.Exit(0)
		}
	}
	if err := sc.Err(); err != nil {
		fail("fork_scan", err)
	}
	fail("fork_hold", errors.New("child exited before HOLDING"))
}

func runFill(maxBlobs int) {
	fd, _, _, _, _ := openAndVersion()
	initVenusContext(fd)
	created := 0
	for maxBlobs == 0 || created < maxBlobs {
		req := virtgpuResourceCreateBlob{
			BlobMem:   virtgpuBlobMemHost3D,
			BlobFlags: virtgpuBlobFlagUseMappable,
			BlobID:    0,
			Size:      blobSize,
		}
		if err := drmIoctl(fd, cmdVirtgpuResourceCreateBlob, unsafe.Pointer(&req)); err != nil {
			fmt.Printf("blobs=%d errno=%s\n", created, errnoString(err))
			_ = unix.Close(fd)
			return
		}
		created++
	}
	fmt.Printf("blobs=%d errno=OK\n", created)
	_ = unix.Close(fd)
}

func runVirglFill(maxResources int) {
	fd, _, _, _, _ := openAndVersion()
	created := 0
	for maxResources == 0 || created < maxResources {
		req := virtgpuResourceCreate{
			Target:    pipeBuffer,
			Format:    virglFormatR8Unorm,
			Bind:      virglBindVertexBuffer,
			Width:     blobSize,
			Height:    1,
			Depth:     1,
			ArraySize: 1,
			Size:      blobSize,
		}
		if err := drmIoctl(fd, cmdVirtgpuResourceCreate, unsafe.Pointer(&req)); err != nil {
			fmt.Printf("blobs=%d errno=%s\n", created, errnoString(err))
			_ = unix.Close(fd)
			return
		}
		created++
	}
	fmt.Printf("blobs=%d errno=OK\n", created)
	_ = unix.Close(fd)
}

func runVirgl() {
	// Step 1: open render node and query DRM_IOCTL_VERSION.
	fd, name, major, minor, patch := openAndVersion()
	fmt.Printf("version=%s %d.%d.%d\n", name, major, minor, patch)

	// Step 2: GETPARAM 1..8 and 9.
	paramIDs := [8]uint64{
		virtgpuParam3DFeatures,
		virtgpuParamCapsetQueryFix,
		virtgpuParamResourceBlob,
		virtgpuParamHostVisible,
		virtgpuParamCrossDevice,
		virtgpuParamContextInit,
		virtgpuParamSupportedCapsetIDs,
		virtgpuParamExplicitDebugName,
	}
	var vals [8]uint64
	for i, id := range paramIDs {
		var val uint64
		req := virtgpuGetparam{
			Param: id,
			Value: uint64(uintptr(unsafe.Pointer(&val))),
		}
		if err := drmIoctl(fd, cmdVirtgpuGetparam, unsafe.Pointer(&req)); err != nil {
			fail("params", err)
		}
		runtime.KeepAlive(&val)
		vals[i] = val
	}
	fmt.Printf("params=%d,%d,%d,%d,%d,%d,%d,%d\n",
		vals[0], vals[1], vals[2], vals[3], vals[4], vals[5], vals[6], vals[7])

	var alignVal uint64
	alignReq := virtgpuGetparam{
		Param: virtgpuParamBlobAlignment,
		Value: uint64(uintptr(unsafe.Pointer(&alignVal))),
	}
	err := drmIoctl(fd, cmdVirtgpuGetparam, unsafe.Pointer(&alignReq))
	runtime.KeepAlive(&alignVal)
	if !errors.Is(err, unix.EINVAL) {
		fail("blob_alignment", fmt.Errorf("got %v, want EINVAL", err))
	}
	fmt.Printf("blob_alignment=%s\n", errnoString(err))

	// Step 3: GET_CAPS(2, 0, size 4096).
	capBuf := make([]byte, 4096)
	capsReq := virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVirgl2,
		CapSetVer: 0,
		Addr:      uint64(uintptr(unsafe.Pointer(&capBuf[0]))),
		Size:      uint32(len(capBuf)),
	}
	if err := drmIoctl(fd, cmdVirtgpuGetCaps, unsafe.Pointer(&capsReq)); err != nil {
		fail("caps2", err)
	}
	runtime.KeepAlive(capBuf)
	fmt.Printf("caps2_word0=%d\n", binary.LittleEndian.Uint32(capBuf[:4]))

	// Step 4: GET_CAPS(4, 0) must return EINVAL.
	caps4Req := virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVenus,
		CapSetVer: 0,
		Addr:      uint64(uintptr(unsafe.Pointer(&capBuf[0]))),
		Size:      uint32(len(capBuf)),
	}
	err = drmIoctl(fd, cmdVirtgpuGetCaps, unsafe.Pointer(&caps4Req))
	runtime.KeepAlive(capBuf)
	if !errors.Is(err, unix.EINVAL) {
		fail("caps4", fmt.Errorf("got %v, want EINVAL", err))
	}
	fmt.Printf("caps4=%s\n", errnoString(err))

	// Step 5: RESOURCE_CREATE on the fresh file creates an implicit context.
	createReq := virtgpuResourceCreate{
		Target:    pipeBuffer,
		Format:    virglFormatR8Unorm,
		Bind:      virglBindVertexBuffer,
		Width:     virglResSize,
		Height:    1,
		Depth:     1,
		ArraySize: 1,
		Size:      virglResSize,
	}
	if err := drmIoctl(fd, cmdVirtgpuResourceCreate, unsafe.Pointer(&createReq)); err != nil {
		fail("create", err)
	}
	boHandle := createReq.BoHandle
	fmt.Printf("create=ok bo=%d\n", boHandle)

	// Step 6: CONTEXT_INIT(capset 2) must return EEXIST after implicit creation.
	ctxParams := [1]virtgpuContextSetParam{
		{Param: virtgpuContextParamCapsetID, Value: virtgpuCapsetVirgl2},
	}
	ctxReq := virtgpuContextInit{
		NumParams:    uint32(len(ctxParams)),
		CtxSetParams: uint64(uintptr(unsafe.Pointer(&ctxParams[0]))),
	}
	err = drmIoctl(fd, cmdVirtgpuContextInit, unsafe.Pointer(&ctxReq))
	runtime.KeepAlive(&ctxParams)
	if !errors.Is(err, unix.EEXIST) {
		fail("context_init", fmt.Errorf("got %v, want EEXIST", err))
	}
	fmt.Printf("context_init=%s\n", errnoString(err))

	// Step 7: RESOURCE_INFO.
	infoReq := virtgpuResourceInfo{BoHandle: boHandle}
	if err := drmIoctl(fd, cmdVirtgpuResourceInfo, unsafe.Pointer(&infoReq)); err != nil {
		fail("info", err)
	}
	fmt.Printf("info=blob_mem:%d size:%d\n", infoReq.BlobMem, infoReq.Size)

	// Step 8: MAP and mmap, then write the test pattern.
	mapReq := virtgpuMap{Handle: boHandle}
	if err := drmIoctl(fd, cmdVirtgpuMap, unsafe.Pointer(&mapReq)); err != nil {
		fail("map", err)
	}
	mapped, err := unix.Mmap(fd, int64(mapReq.Offset), virglResSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		fail("mmap", err)
	}
	for i := range mapped {
		mapped[i] = byte(i*7 + 3)
	}

	// Step 9: TRANSFER_TO_HOST, clear mapping, TRANSFER_FROM_HOST, compare.
	xfer := virtgpu3DTransfer{
		BoHandle: boHandle,
		Box: virtgpu3DBox{
			X: 0,
			Y: 0,
			Z: 0,
			W: virglResSize,
			H: 1,
			D: 1,
		},
	}
	if err := drmIoctl(fd, cmdVirtgpuTransferToHost, unsafe.Pointer(&xfer)); err != nil {
		fail("transfer_to_host", err)
	}
	clear(mapped)
	if err := drmIoctl(fd, cmdVirtgpuTransferFromHost, unsafe.Pointer(&xfer)); err != nil {
		fail("transfer_from_host", err)
	}
	for i, got := range mapped {
		want := byte(i*7 + 3)
		if got != want {
			fail("transfer", fmt.Errorf("byte %d = %#x, want %#x", i, got, want))
		}
	}
	fmt.Println("transfer=ok")

	// Step 10: EXECBUFFER with size 0 and bo_handles = [bo]; blocking WAIT.
	handles := [1]uint32{boHandle}
	execReq := virtgpuExecbuffer{
		Size:         0,
		BoHandles:    uint64(uintptr(unsafe.Pointer(&handles[0]))),
		NumBoHandles: uint32(len(handles)),
		FenceFD:      -1,
	}
	if err := drmIoctl(fd, cmdVirtgpuExecbuffer, unsafe.Pointer(&execReq)); err != nil {
		fail("execbuffer", err)
	}
	runtime.KeepAlive(&handles)
	waitReq := virtgpu3DWait{Handle: boHandle, Flags: 0}
	if err := drmIoctl(fd, cmdVirtgpuWait, unsafe.Pointer(&waitReq)); err != nil {
		fail("wait", err)
	}
	fmt.Println("wait=0")

	// Step 11: WAIT with unknown handle 999 must return ENOENT.
	badWaitReq := virtgpu3DWait{Handle: 999, Flags: 0}
	if err := drmIoctl(fd, cmdVirtgpuWait, unsafe.Pointer(&badWaitReq)); !errors.Is(err, unix.ENOENT) {
		fail("wait_bad", fmt.Errorf("got %v, want ENOENT", err))
	} else {
		fmt.Printf("wait_bad=%s\n", errnoString(err))
	}

	// Step 12: RESOURCE_CREATE_BLOB must return EINVAL in virgl mode.
	blobReq := virtgpuResourceCreateBlob{
		BlobMem:   virtgpuBlobMemHost3D,
		BlobFlags: virtgpuBlobFlagUseMappable,
		Size:      blobSize,
	}
	if err := drmIoctl(fd, cmdVirtgpuResourceCreateBlob, unsafe.Pointer(&blobReq)); !errors.Is(err, unix.EINVAL) {
		fail("blob", fmt.Errorf("got %v, want EINVAL", err))
	} else {
		fmt.Printf("blob=%s\n", errnoString(err))
	}

	// Step 13: TRANSFER_TO_HOST with non-zero stride must return EINVAL.
	badXfer := virtgpu3DTransfer{
		BoHandle: boHandle,
		Box: virtgpu3DBox{
			X: 0,
			Y: 0,
			Z: 0,
			W: 4,
			H: 1,
			D: 1,
		},
		Stride: 4,
	}
	if err := drmIoctl(fd, cmdVirtgpuTransferToHost, unsafe.Pointer(&badXfer)); !errors.Is(err, unix.EINVAL) {
		fail("transfer_stride", fmt.Errorf("got %v, want EINVAL", err))
	} else {
		fmt.Printf("transfer_stride=%s\n", errnoString(err))
	}

	// Step 14: GEM_CLOSE, munmap, close.
	closeReq := drmGemClose{Handle: boHandle}
	if err := drmIoctl(fd, cmdGemClose, unsafe.Pointer(&closeReq)); err != nil {
		fail("gem_close", err)
	}
	if err := unix.Munmap(mapped); err != nil {
		fail("munmap", err)
	}
	if err := unix.Close(fd); err != nil {
		fail("close", err)
	}
	fmt.Println("VIRGL OK")
}

func runFull() {
	// Step 1: sysfs PCI identity.
	devPath, err := filepath.EvalSymlinks(sysfsDevLink)
	if err != nil {
		fail("sysfs", err)
	}
	parent := filepath.Dir(devPath)
	vendorBytes, err := os.ReadFile(filepath.Join(parent, "vendor"))
	if err != nil {
		fail("sysfs", err)
	}
	deviceBytes, err := os.ReadFile(filepath.Join(parent, "device"))
	if err != nil {
		fail("sysfs", err)
	}
	fmt.Printf("sysfs=%s vendor=%s device=%s\n", devPath, strings.TrimSpace(string(vendorBytes)), strings.TrimSpace(string(deviceBytes)))

	// Step 2: open render node and query DRM_IOCTL_VERSION.
	fd, name, major, minor, patch := openAndVersion()
	fmt.Printf("version=%s %d.%d.%d\n", name, major, minor, patch)

	// Step 3: DRM_IOCTL_GET_CAP(DRM_CAP_SYNCOBJ).
	capReq := drmGetCap{Capability: drmCapSyncobj}
	if err := drmIoctl(fd, cmdGetCap, unsafe.Pointer(&capReq)); err != nil {
		fail("syncobj", err)
	}
	fmt.Printf("syncobj=%d\n", capReq.Value)

	// Step 4: GETPARAM for 3D_FEATURES, RESOURCE_BLOB, HOST_VISIBLE, CONTEXT_INIT, BLOB_ALIGNMENT.
	paramIDs := [5]uint64{
		virtgpuParam3DFeatures,
		virtgpuParamResourceBlob,
		virtgpuParamHostVisible,
		virtgpuParamContextInit,
		virtgpuParamBlobAlignment,
	}
	var vals [5]uint64
	for i, id := range paramIDs {
		var val uint64
		req := virtgpuGetparam{
			Param: id,
			Value: uint64(uintptr(unsafe.Pointer(&val))),
		}
		if err := drmIoctl(fd, cmdVirtgpuGetparam, unsafe.Pointer(&req)); err != nil {
			fail("params", err)
		}
		runtime.KeepAlive(&val)
		vals[i] = val
	}
	fmt.Printf("params=%d,%d,%d,%d,%d\n", vals[0], vals[1], vals[2], vals[3], vals[4])

	// Step 5: GET_CAPS(4, 0, size 4096).
	capBuf := make([]byte, 4096)
	capsReq := virtgpuGetCaps{
		CapSetID:  virtgpuCapsetVenus,
		CapSetVer: 0,
		Addr:      uint64(uintptr(unsafe.Pointer(&capBuf[0]))),
		Size:      uint32(len(capBuf)),
	}
	if err := drmIoctl(fd, cmdVirtgpuGetCaps, unsafe.Pointer(&capsReq)); err != nil {
		fail("caps", err)
	}
	runtime.KeepAlive(capBuf)
	fmt.Printf("capset_wire_format=%d\n", binary.LittleEndian.Uint32(capBuf[:4]))

	// Step 6: CONTEXT_INIT.
	initVenusContext(fd)
	fmt.Println("context=ok")

	// Step 7: RESOURCE_CREATE_BLOB.
	resHandle, boHandle := createMappableBlob(fd)
	fmt.Printf("res_handle=%d bo_handle=%d\n", resHandle, boHandle)

	// Step 8: MAP and double MAP_SHARED alias check.
	offset := mapAndVerifyAlias(fd, boHandle, true)
	fmt.Println("alias=ok")

	// Step 9: MAP_PRIVATE must fail with EINVAL.
	priv, err := unix.Mmap(fd, int64(offset), blobSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err == nil {
		_ = unix.Munmap(priv)
		fail("private", errors.New("MAP_PRIVATE succeeded unexpectedly"))
	}
	if !errors.Is(err, unix.EINVAL) {
		fail("private", fmt.Errorf("got %v, want EINVAL", err))
	}
	fmt.Println("private=refused")

	// Step 10: EXECBUFFER with FENCE_FD_OUT and poll(POLLIN, 2000 ms).
	execReq := virtgpuExecbuffer{
		Flags:   virtgpuExecbufRingIdx | virtgpuExecbufFenceFDOut,
		Size:    0,
		RingIdx: 0,
		FenceFD: -1,
	}
	if err := drmIoctl(fd, cmdVirtgpuExecbuffer, unsafe.Pointer(&execReq)); err != nil {
		fail("fence", err)
	}
	if execReq.FenceFD < 0 {
		fail("fence", fmt.Errorf("invalid fence_fd %d", execReq.FenceFD))
	}
	pfds := []unix.PollFd{{Fd: execReq.FenceFD, Events: unix.POLLIN}}
	deadline := time.Now().Add(fencePollMs * time.Millisecond)
	var n int
	for {
		rem := time.Until(deadline)
		ms := int(rem.Milliseconds())
		if ms < 0 {
			ms = 0
		}
		n, err = unix.Poll(pfds, ms)
		if errors.Is(err, unix.EINTR) && rem > 0 {
			continue
		}
		break
	}
	if err != nil {
		fail("fence", err)
	}
	if n != 1 || pfds[0].Revents&unix.POLLIN == 0 {
		fail("fence", fmt.Errorf("poll n=%d revents=%#x", n, pfds[0].Revents))
	}
	fmt.Println("fence=ok")

	// Step 11: GEM_CLOSE once, then a second time must fail with EINVAL.
	closeReq := drmGemClose{Handle: boHandle}
	if err := drmIoctl(fd, cmdGemClose, unsafe.Pointer(&closeReq)); err != nil {
		fail("gem_close", err)
	}
	err = drmIoctl(fd, cmdGemClose, unsafe.Pointer(&closeReq))
	if !errors.Is(err, unix.EINVAL) {
		fail("gem_close", fmt.Errorf("second GEM_CLOSE got %v, want EINVAL", err))
	}
	fmt.Println("gem_close=ok")

	// Step 12: close all descriptors.
	if err := unix.Close(int(execReq.FenceFD)); err != nil {
		fail("close", err)
	}
	if err := unix.Close(fd); err != nil {
		fail("close", err)
	}
	fmt.Println("PASS")
}
