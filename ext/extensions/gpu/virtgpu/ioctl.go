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

package virtgpu

import (
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/usermem"
)

// ioctlFunc serves one request. arg holds the argument structure with at least
// the size in the uAPI header. It starts with the guest input bytes followed
// by zeros. The dispatcher copies arg back to the guest after the call, as
// Linux drm_ioctl does.
type ioctlFunc func(fd *renderFD, ctx context.Context, uio usermem.IO, arg []byte) error

// ioctlEntry describes one DRM request number.
type ioctlEntry struct {
	name  string    // uAPI macro name, for the refusal log
	cmd   uint32    // request as the uAPI header encodes it; 0 for a refused entry
	fn    ioctlFunc // nil for a refused entry
	err   error     // errno of a refused entry
	modes modeMask  // served entries: modes that serve it; zero in the table literal means modeAll
}

// refusal describes one explicitly refused DRM request number.
type refusal struct {
	name string
	err  error
}

var servedIoctls = map[uint32]ioctlEntry{
	nrVersion: {
		name: "DRM_IOCTL_VERSION",
		cmd:  cmdVersion,
		fn:   (*renderFD).version,
	},
	nrGemClose: {
		name: "DRM_IOCTL_GEM_CLOSE",
		cmd:  cmdGemClose,
		fn:   (*renderFD).gemClose,
	},
	nrGetCap: {
		name: "DRM_IOCTL_GET_CAP",
		cmd:  cmdGetCap,
		fn:   (*renderFD).getCap,
	},
	nrVirtgpuMap: {
		name: "DRM_IOCTL_VIRTGPU_MAP",
		cmd:  cmdVirtgpuMap,
		fn:   (*renderFD).mapBlob,
	},
	nrVirtgpuExecbuffer: {
		name: "DRM_IOCTL_VIRTGPU_EXECBUFFER",
		cmd:  cmdVirtgpuExecbuffer,
		fn:   (*renderFD).execbuffer,
	},
	nrVirtgpuGetparam: {
		name: "DRM_IOCTL_VIRTGPU_GETPARAM",
		cmd:  cmdVirtgpuGetparam,
		fn:   (*renderFD).getParam,
	},
	nrVirtgpuResourceCreate: {
		name:  "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE",
		cmd:   cmdVirtgpuResourceCreate,
		fn:    (*renderFD).resourceCreate,
		modes: modeVirgl,
	},
	nrVirtgpuResourceInfo: {
		name: "DRM_IOCTL_VIRTGPU_RESOURCE_INFO",
		cmd:  cmdVirtgpuResourceInfo,
		fn:   (*renderFD).resourceInfo,
	},
	nrVirtgpuTransferFromHost: {
		name:  "DRM_IOCTL_VIRTGPU_TRANSFER_FROM_HOST",
		cmd:   cmdVirtgpuTransferFromHost,
		fn:    (*renderFD).transferFromHost,
		modes: modeVirgl,
	},
	nrVirtgpuTransferToHost: {
		name:  "DRM_IOCTL_VIRTGPU_TRANSFER_TO_HOST",
		cmd:   cmdVirtgpuTransferToHost,
		fn:    (*renderFD).transferToHost,
		modes: modeVirgl,
	},
	nrVirtgpuWait: {
		name:  "DRM_IOCTL_VIRTGPU_WAIT",
		cmd:   cmdVirtgpuWait,
		fn:    (*renderFD).wait,
		modes: modeVirgl,
	},
	nrVirtgpuGetCaps: {
		name: "DRM_IOCTL_VIRTGPU_GET_CAPS",
		cmd:  cmdVirtgpuGetCaps,
		fn:   (*renderFD).getCaps,
	},
	nrVirtgpuResourceCreateBlob: {
		name:  "DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB",
		cmd:   cmdVirtgpuResourceCreateBlob,
		fn:    (*renderFD).createBlob,
		modes: modeVenus,
	},
	nrVirtgpuContextInit: {
		name: "DRM_IOCTL_VIRTGPU_CONTEXT_INIT",
		cmd:  cmdVirtgpuContextInit,
		fn:   (*renderFD).contextInit,
	},
}

var refusedIoctls = map[uint32]refusal{
	nrGetUnique:             {name: "DRM_IOCTL_GET_UNIQUE", err: linuxerr.EACCES},
	nrGetMagic:              {name: "DRM_IOCTL_GET_MAGIC", err: linuxerr.EACCES},
	nrGetClient:             {name: "DRM_IOCTL_GET_CLIENT", err: linuxerr.EACCES},
	nrGetStats:              {name: "DRM_IOCTL_GET_STATS", err: linuxerr.EACCES},
	nrSetVersion:            {name: "DRM_IOCTL_SET_VERSION", err: linuxerr.EACCES},
	nrGemFlink:              {name: "DRM_IOCTL_GEM_FLINK", err: linuxerr.EACCES},
	nrGemOpen:               {name: "DRM_IOCTL_GEM_OPEN", err: linuxerr.EACCES},
	nrSetClientCap:          {name: "DRM_IOCTL_SET_CLIENT_CAP", err: linuxerr.EACCES},
	nrSetUnique:             {name: "DRM_IOCTL_SET_UNIQUE", err: linuxerr.EACCES},
	nrAuthMagic:             {name: "DRM_IOCTL_AUTH_MAGIC", err: linuxerr.EACCES},
	nrBlock:                 {name: "DRM_IOCTL_BLOCK", err: linuxerr.EACCES},
	nrUnblock:               {name: "DRM_IOCTL_UNBLOCK", err: linuxerr.EACCES},
	nrSetMaster:             {name: "DRM_IOCTL_SET_MASTER", err: linuxerr.EACCES},
	nrDropMaster:            {name: "DRM_IOCTL_DROP_MASTER", err: linuxerr.EACCES},
	nrAddDraw:               {name: "DRM_IOCTL_ADD_DRAW", err: linuxerr.EACCES},
	nrRmDraw:                {name: "DRM_IOCTL_RM_DRAW", err: linuxerr.EACCES},
	nrFinish:                {name: "DRM_IOCTL_FINISH", err: linuxerr.EACCES},
	nrPrimeHandleToFD:       {name: "DRM_IOCTL_PRIME_HANDLE_TO_FD", err: linuxerr.EOPNOTSUPP},
	nrPrimeFDToHandle:       {name: "DRM_IOCTL_PRIME_FD_TO_HANDLE", err: linuxerr.EOPNOTSUPP},
	nrWaitVblank:            {name: "DRM_IOCTL_WAIT_VBLANK", err: linuxerr.EACCES},
	nrCrtcGetSequence:       {name: "DRM_IOCTL_CRTC_GET_SEQUENCE", err: linuxerr.EACCES},
	nrCrtcQueueSequence:     {name: "DRM_IOCTL_CRTC_QUEUE_SEQUENCE", err: linuxerr.EACCES},
	nrUpdateDraw:            {name: "DRM_IOCTL_UPDATE_DRAW", err: linuxerr.EACCES},
	nrModeGetresources:      {name: "DRM_IOCTL_MODE_GETRESOURCES", err: linuxerr.EACCES},
	nrModeGetcrtc:           {name: "DRM_IOCTL_MODE_GETCRTC", err: linuxerr.EACCES},
	nrModeSetcrtc:           {name: "DRM_IOCTL_MODE_SETCRTC", err: linuxerr.EACCES},
	nrModeCursor:            {name: "DRM_IOCTL_MODE_CURSOR", err: linuxerr.EACCES},
	nrModeGetgamma:          {name: "DRM_IOCTL_MODE_GETGAMMA", err: linuxerr.EACCES},
	nrModeSetgamma:          {name: "DRM_IOCTL_MODE_SETGAMMA", err: linuxerr.EACCES},
	nrModeGetencoder:        {name: "DRM_IOCTL_MODE_GETENCODER", err: linuxerr.EACCES},
	nrModeGetconnector:      {name: "DRM_IOCTL_MODE_GETCONNECTOR", err: linuxerr.EACCES},
	nrModeAttachmode:        {name: "DRM_IOCTL_MODE_ATTACHMODE", err: linuxerr.EACCES},
	nrModeDetachmode:        {name: "DRM_IOCTL_MODE_DETACHMODE", err: linuxerr.EACCES},
	nrModeGetproperty:       {name: "DRM_IOCTL_MODE_GETPROPERTY", err: linuxerr.EACCES},
	nrModeSetproperty:       {name: "DRM_IOCTL_MODE_SETPROPERTY", err: linuxerr.EACCES},
	nrModeGetpropblob:       {name: "DRM_IOCTL_MODE_GETPROPBLOB", err: linuxerr.EACCES},
	nrModeGetfb:             {name: "DRM_IOCTL_MODE_GETFB", err: linuxerr.EACCES},
	nrModeAddfb:             {name: "DRM_IOCTL_MODE_ADDFB", err: linuxerr.EACCES},
	nrModeRmfb:              {name: "DRM_IOCTL_MODE_RMFB", err: linuxerr.EACCES},
	nrModePageFlip:          {name: "DRM_IOCTL_MODE_PAGE_FLIP", err: linuxerr.EACCES},
	nrModeDirtyfb:           {name: "DRM_IOCTL_MODE_DIRTYFB", err: linuxerr.EACCES},
	nrModeCreateDumb:        {name: "DRM_IOCTL_MODE_CREATE_DUMB", err: linuxerr.EACCES},
	nrModeMapDumb:           {name: "DRM_IOCTL_MODE_MAP_DUMB", err: linuxerr.EACCES},
	nrModeDestroyDumb:       {name: "DRM_IOCTL_MODE_DESTROY_DUMB", err: linuxerr.EACCES},
	nrModeGetplaneresources: {name: "DRM_IOCTL_MODE_GETPLANERESOURCES", err: linuxerr.EACCES},
	nrModeGetplane:          {name: "DRM_IOCTL_MODE_GETPLANE", err: linuxerr.EACCES},
	nrModeSetplane:          {name: "DRM_IOCTL_MODE_SETPLANE", err: linuxerr.EACCES},
	nrModeAddfb2:            {name: "DRM_IOCTL_MODE_ADDFB2", err: linuxerr.EACCES},
	nrModeObjGetproperties:  {name: "DRM_IOCTL_MODE_OBJ_GETPROPERTIES", err: linuxerr.EACCES},
	nrModeObjSetproperty:    {name: "DRM_IOCTL_MODE_OBJ_SETPROPERTY", err: linuxerr.EACCES},
	nrModeCursor2:           {name: "DRM_IOCTL_MODE_CURSOR2", err: linuxerr.EACCES},
	nrModeAtomic:            {name: "DRM_IOCTL_MODE_ATOMIC", err: linuxerr.EACCES},
	nrModeCreatepropblob:    {name: "DRM_IOCTL_MODE_CREATEPROPBLOB", err: linuxerr.EACCES},
	nrModeDestroypropblob:   {name: "DRM_IOCTL_MODE_DESTROYPROPBLOB", err: linuxerr.EACCES},
	nrSyncobjCreate:         {name: "DRM_IOCTL_SYNCOBJ_CREATE", err: linuxerr.EOPNOTSUPP},
	nrSyncobjDestroy:        {name: "DRM_IOCTL_SYNCOBJ_DESTROY", err: linuxerr.EOPNOTSUPP},
	nrSyncobjHandleToFD:     {name: "DRM_IOCTL_SYNCOBJ_HANDLE_TO_FD", err: linuxerr.EOPNOTSUPP},
	nrSyncobjFDToHandle:     {name: "DRM_IOCTL_SYNCOBJ_FD_TO_HANDLE", err: linuxerr.EOPNOTSUPP},
	nrSyncobjWait:           {name: "DRM_IOCTL_SYNCOBJ_WAIT", err: linuxerr.EOPNOTSUPP},
	nrSyncobjReset:          {name: "DRM_IOCTL_SYNCOBJ_RESET", err: linuxerr.EOPNOTSUPP},
	nrSyncobjSignal:         {name: "DRM_IOCTL_SYNCOBJ_SIGNAL", err: linuxerr.EOPNOTSUPP},
	nrModeCreateLease:       {name: "DRM_IOCTL_MODE_CREATE_LEASE", err: linuxerr.EACCES},
	nrModeListLessees:       {name: "DRM_IOCTL_MODE_LIST_LESSEES", err: linuxerr.EACCES},
	nrModeGetLease:          {name: "DRM_IOCTL_MODE_GET_LEASE", err: linuxerr.EACCES},
	nrModeRevokeLease:       {name: "DRM_IOCTL_MODE_REVOKE_LEASE", err: linuxerr.EACCES},
	nrSyncobjTimelineWait:   {name: "DRM_IOCTL_SYNCOBJ_TIMELINE_WAIT", err: linuxerr.EOPNOTSUPP},
	nrSyncobjQuery:          {name: "DRM_IOCTL_SYNCOBJ_QUERY", err: linuxerr.EOPNOTSUPP},
	nrSyncobjTransfer:       {name: "DRM_IOCTL_SYNCOBJ_TRANSFER", err: linuxerr.EOPNOTSUPP},
	nrSyncobjTimelineSignal: {name: "DRM_IOCTL_SYNCOBJ_TIMELINE_SIGNAL", err: linuxerr.EOPNOTSUPP},
	nrModeGetfb2:            {name: "DRM_IOCTL_MODE_GETFB2", err: linuxerr.EACCES},
	nrSyncobjEventFD:        {name: "DRM_IOCTL_SYNCOBJ_EVENTFD", err: linuxerr.EOPNOTSUPP},
	nrModeClosefb:           {name: "DRM_IOCTL_MODE_CLOSEFB", err: linuxerr.EACCES},
}

// ioctls maps a DRM request number (_IOC_NR) to its entry. It is built once
// from servedIoctls and refusedIoctls and never changes.
var ioctls = buildIoctlTable()

func buildIoctlTable() map[uint32]ioctlEntry {
	return buildIoctlTableFrom(servedIoctls, refusedIoctls)
}

func buildIoctlTableFrom(served map[uint32]ioctlEntry, refused map[uint32]refusal) map[uint32]ioctlEntry {
	table := make(map[uint32]ioctlEntry, len(served)+len(refused))
	for nr, e := range served {
		if e.fn != nil && e.modes == 0 {
			e.modes = modeAll
		}
		table[nr] = e
	}
	for nr, r := range refused {
		if _, dup := table[nr]; dup {
			panic(fmt.Sprintf("virtgpu: ioctl nr %#x (%s) appears in both served and refused tables", nr, r.name))
		}
		table[nr] = ioctlEntry{
			name: r.name,
			err:  r.err,
		}
	}
	return table
}

const (
	iocIn       = uint32(linux.IOC_WRITE) << linux.IOC_DIRSHIFT
	iocOut      = uint32(linux.IOC_READ) << linux.IOC_DIRSHIFT
	stackArgMax = 128
)

// ioctl dispatches one DRM ioctl using Linux drm_ioctl direction and size
// semantics.
func (fd *renderFD) ioctl(ctx context.Context, uio usermem.IO, cmd uint32, argAddr hostarch.Addr) (uintptr, error) {
	typ := (cmd >> linux.IOC_TYPESHIFT) & 0xff
	if typ != drmIoctlBase {
		return 0, linuxerr.ENOTTY
	}
	nr := linux.IOC_NR(cmd)
	e, ok := ioctls[nr]
	if !ok {
		fd.logRefused(ctx, nr, "unknown", cmd, linuxerr.EINVAL)
		return 0, linuxerr.EINVAL
	}
	if e.fn == nil {
		fd.logRefused(ctx, nr, e.name, cmd, e.err)
		return 0, e.err
	}
	if e.modes&fd.dev.modes == 0 {
		fd.logRefused(ctx, nr, e.name, cmd, linuxerr.EINVAL)
		return 0, linuxerr.EINVAL
	}

	drvSize := linux.IOC_SIZE(e.cmd)
	inSize := linux.IOC_SIZE(cmd)
	outSize := inSize
	if cmd&e.cmd&iocIn == 0 {
		inSize = 0
	}
	if cmd&e.cmd&iocOut == 0 {
		outSize = 0
	}
	kSize := max(inSize, outSize, drvSize)

	var stackBuf [stackArgMax]byte
	var arg []byte
	if kSize <= stackArgMax {
		arg = stackBuf[:kSize]
	} else {
		arg = make([]byte, kSize)
	}

	if inSize > 0 {
		if _, err := uio.CopyIn(ctx, argAddr, arg[:inSize], usermem.IOOpts{}); err != nil {
			return 0, linuxerr.EFAULT
		}
	}
	err := e.fn(fd, ctx, uio, arg)
	if outSize > 0 {
		if _, copyErr := uio.CopyOut(ctx, argAddr, arg[:outSize], usermem.IOOpts{}); copyErr != nil {
			return 0, linuxerr.EFAULT
		}
	}
	return 0, err
}

// logRefused writes one debug line the first time this file sees a refused
// request number. Gate runs (GVX_DEBUG_LOG=2) collect these lines to find the
// requests that a guest needs.
func (fd *renderFD) logRefused(ctx context.Context, nr uint32, name string, cmd uint32, err error) {
	word := nr / 64
	bit := uint64(1) << (nr % 64)

	fd.refusedMu.Lock()
	already := fd.refused[word]&bit != 0
	fd.refused[word] |= bit
	fd.refusedMu.Unlock()

	if !already {
		ctx.Debugf("virtgpu: refused ioctl %s (nr %#x, cmd %#x): %v", name, nr, cmd, err)
	}
}
