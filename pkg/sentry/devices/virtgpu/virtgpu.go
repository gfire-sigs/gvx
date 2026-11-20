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

// Package virtgpu implements a virtio-gpu render node (/dev/dri/renderD128)
// whose commands run in a host renderer process.
package virtgpu

import (
	"errors"
	"fmt"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// Device number of the render node. pkg/gvx copies both values into
// sys.VirtGPUSysfs, so that sysfs and devtmpfs agree.
const (
	DRMMajor    = 226 // DRM_MAJOR, include/drm/drm_device.h
	RenderMinor = 128 // first render minor, drivers/gpu/drm/drm_drv.c
)

// renderNodePath is the devtmpfs path of the node.
const renderNodePath = "dri/renderD128"

// modeMask is a set of renderer modes.
type modeMask uint8

const (
	modeVenus modeMask = 1 << iota
	modeVirgl
	modeAll = modeVenus | modeVirgl
)

func maskOf(m gpuproto.Mode) modeMask {
	switch m {
	case gpuproto.ModeVenus:
		return modeVenus
	case gpuproto.ModeVirgl:
		return modeVirgl
	default:
		return 0
	}
}

var (
	// ErrNoVenusCapset is returned by Register when the renderer did not report
	// the venus capset in its handshake.
	ErrNoVenusCapset = errors.New("virtgpu: renderer has no venus capset")

	// Register returns ErrNoVirglCapset when a virgl renderer did not report
	// the virgl capsets in its handshake.
	ErrNoVirglCapset = errors.New("virtgpu: renderer has no virgl capsets")

	errNilRenderer = errors.New("virtgpu: nil renderer")
	errUnknownMode = errors.New("virtgpu: renderer reports an unknown mode")
)

// Device is the render node of one sandbox. It holds no process-wide state:
// every counter and table hangs off the Device that Register returns.
type Device struct {
	vfs      *vfs.VirtualFilesystem
	renderer Renderer

	// mode, modes, and capsets never change after Register.
	mode    gpuproto.Mode
	modes   modeMask
	capsets uint64 // bit n set: Device serves capset n (VIRTGPU_PARAM_SUPPORTED_CAPSET_IDs)

	// lastCtxID is the last context ID that allocCtxID returned.
	lastCtxID atomicbitops.Uint32

	// lastResID is the last resource ID that allocResID returned.
	lastResID atomicbitops.Uint32

	// lastFenceID is the last fence ID that submit allocated.
	lastFenceID atomicbitops.Uint64

	// lost is set once, when the renderer is lost. It is never cleared.
	lost atomicbitops.Bool

	mu sync.Mutex
	// contexts maps a context ID to its context, from before CTX_CREATE is
	// sent until after CTX_DESTROY is sent.
	// +checklocks:mu
	contexts map[uint32]*fileContext

	// limits holds the effective resource caps of this sandbox.
	limits Limits

	// budget counts live blobs and their reserved or mapped host bytes.
	budget blobBudget

	blobsMu sync.Mutex
	// blobs holds every blob whose view is mapped, for ReleaseBlobViews.
	// +checklocks:blobsMu
	blobs map[*blob]struct{}
}

var _ vfs.Device = (*Device)(nil)

func (d *Device) hasCapset(id uint32) bool {
	return id < 64 && d.capsets&(uint64(1)<<id) != 0
}

func isVirglCapset(id uint32) bool {
	return id == gpuproto.CapsetVirgl || id == gpuproto.CapsetVirgl2
}

// Register creates the render node of one sandbox, registers it with vfsObj,
// and installs the device as the event sink of r. Call it before the devtmpfs
// mount, so that /dev/dri/renderD128 and /dev/char/226:128 exist.
func Register(vfsObj *vfs.VirtualFilesystem, r Renderer, lim Limits) (*Device, error) {
	if r == nil {
		return nil, errNilRenderer
	}
	mode := r.Mode()
	modes := maskOf(mode)
	if modes == 0 {
		return nil, errUnknownMode
	}
	var capsets uint64
	for _, id := range mode.Capsets() {
		if _, ok := r.Capset(id, 0); !ok {
			if mode == gpuproto.ModeVenus {
				return nil, ErrNoVenusCapset
			}
			return nil, ErrNoVirglCapset
		}
		capsets |= uint64(1) << id
	}
	lim = lim.withDefaults()
	d := &Device{
		vfs:      vfsObj,
		renderer: r,
		mode:     mode,
		modes:    modes,
		capsets:  capsets,
		limits:   lim,
		budget:   blobBudget{limit: lim.BlobBytes},
		contexts: make(map[uint32]*fileContext),
		blobs:    map[*blob]struct{}{},
	}
	if err := vfsObj.RegisterDevice(vfs.CharDevice, DRMMajor, RenderMinor, d, &vfs.RegisterDeviceOptions{
		GroupName: "drm",
		Pathname:  renderNodePath,
		FilePerms: 0666,
	}); err != nil {
		return nil, fmt.Errorf("virtgpu: register %d:%d: %w", DRMMajor, RenderMinor, err)
	}
	r.SetEventSink(eventSink{d})
	return d, nil
}

// Open implements vfs.Device.Open. Any user can open the node (mode 0666),
// also after the renderer is lost; ioctls that need the renderer then fail
// with EIO.
func (d *Device) Open(ctx context.Context, mnt *vfs.Mount, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	fd := &renderFD{
		dev: d,
		gem: newGemTable(),
	}
	if err := fd.vfsfd.Init(fd, opts.Flags, auth.CredentialsFromContext(ctx), mnt, vfsd, &vfs.FileDescriptionOptions{
		UseDentryMetadata: true,
		SpecialFile:       true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// renderFD is one open DRM file of the render node: one GEM handle table and
// at most one renderer context.
type renderFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.DentryMetadataFileDescriptionImpl
	vfs.NoLockFD

	dev *Device

	// queue holds the waiters of poll and epoll. The device generates no DRM
	// events, so nothing notifies it with EventIn.
	queue waiter.Queue

	// initMu serializes CONTEXT_INIT and the implicit context creation of
	// ensureContext. Both hold it across the CreateContext call.
	initMu sync.Mutex

	// ctx stays nil until createContextLocked stores the context. It then
	// never changes.
	ctx atomic.Pointer[fileContext]

	gemMu sync.Mutex
	// +checklocks:gemMu
	gem gemTable

	refusedMu sync.Mutex
	// refused has one bit for each DRM request number that this file already
	// logged as refused.
	// +checklocks:refusedMu
	refused [4]uint64
	// refusedExecbuf has one bit for each EXECBUFFER field that this file
	// already logged as refused.
	// +checklocks:refusedMu
	refusedExecbuf uint8
}

var _ vfs.FileDescriptionImpl = (*renderFD)(nil)

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *renderFD) Release(ctx context.Context) {
	fd.gemMu.Lock()
	objs := fd.gem.takeAll()
	fd.gemMu.Unlock()

	c := fd.ctx.Load()
	for _, o := range objs {
		if c != nil {
			fd.dev.unrefResource(c.id, o.resID)
		}
		if o.blob != nil {
			o.blob.decOwner()
		} else if o.accounted != 0 {
			fd.dev.budget.release(o.accounted)
		}
	}
	if c != nil {
		fd.dev.destroyContext(c)
	}
}

// Ioctl implements vfs.FileDescriptionImpl.Ioctl.
func (fd *renderFD) Ioctl(ctx context.Context, uio usermem.IO, sysno uintptr, args arch.SyscallArguments) (uintptr, error) {
	return fd.ioctl(ctx, uio, args[1].Uint(), args[2].Pointer())
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *renderFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	return 0, linuxerr.ErrWouldBlock
}

// Readiness implements waiter.Waitable.Readiness.
func (fd *renderFD) Readiness(mask waiter.EventMask) waiter.EventMask {
	return 0
}

// EventRegister implements waiter.Waitable.EventRegister.
func (fd *renderFD) EventRegister(e *waiter.Entry) error {
	fd.queue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (fd *renderFD) EventUnregister(e *waiter.Entry) {
	fd.queue.EventUnregister(e)
}

// Epollable implements vfs.FileDescriptionImpl.Epollable.
func (fd *renderFD) Epollable() bool {
	return true
}
