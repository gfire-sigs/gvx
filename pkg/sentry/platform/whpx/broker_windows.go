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

package whpx

import (
	"errors"
	"fmt"
	"net/rpc"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// BrokerRequest carries operations on one partition. Source always belongs to the fixed worker process.
type BrokerRequest struct {
	Operation  string
	Index      uint32
	Processors uint32
	Source     uint64
	GPA        uint64
	Size       uint64
	Flags      uint32
	Names      []uint32
	Values     []byte
}

// BrokerReply contains register values, an exit context, or host capabilities.
type BrokerReply struct {
	Values            []byte
	HypervisorPresent bool
	ARM64Support      bool
	WindowsBuild      uint32
	WindowsUBR        uint32
	Processors        uint32
	Xsave             bool
}

// Broker owns a WHPX partition whose pages belong to one worker.
// The caller owns the process object and must keep it open until Close returns.
type Broker struct {
	mu       sync.RWMutex
	stateMu  sync.Mutex
	backend  *winBackend
	process  windows.Handle
	features hostFeatures
	vpCount  uint32
	created  [maxVPs]bool
	running  [maxVPs]atomic.Bool
	closed   atomic.Bool
}

// NewBroker binds all memory mappings to workerProcess. Requests cannot select another process.
func NewBroker(workerProcess uintptr) (*Broker, error) {
	if workerProcess == 0 {
		return nil, errors.New("whpx: worker process is required")
	}
	be, err := newBackend()
	if err != nil {
		return nil, err
	}
	win := be.(*winBackend)
	f, err := win.features()
	if err != nil {
		return nil, err
	}
	if err := checkHost(runtime.GOARCH == "arm64", f); err != nil {
		return nil, err
	}
	if err := procMapGpaRange2.Find(); err != nil {
		return nil, fmt.Errorf("%w: WHvMapGpaRange2: %v", ErrUnsupported, err)
	}
	return &Broker{backend: win, process: windows.Handle(workerProcess), features: f}, nil
}

// Call implements the bounded RPC service. It exposes no file, process, or socket creation operation.
func (b *Broker) Call(request BrokerRequest, reply *BrokerReply) error {
	if b.closed.Load() {
		return errClosed
	}
	if request.Operation == "Setup" || request.Operation == "Close" {
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.closed.Load() {
			return errClosed
		}
		if request.Operation == "Close" {
			b.stateMu.Lock()
			defer b.stateMu.Unlock()
			for _, created := range b.created {
				if created {
					return errors.New("whpx: processors remain in the partition")
				}
			}
			return b.backend.closePartition()
		}
		if b.backend.partition != 0 || request.Processors == 0 || request.Processors > maxVPs {
			return errors.New("whpx: invalid partition setup")
		}
		info, err := b.backend.createPartition(request.Processors)
		if err != nil {
			return err
		}
		b.vpCount = info.vpCount
		reply.Processors, reply.Xsave = info.vpCount, info.xsave
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed.Load() {
		return errClosed
	}
	if request.Operation == "Features" {
		reply.HypervisorPresent = b.features.hypervisorPresent
		reply.ARM64Support = b.features.arm64Support
		reply.WindowsBuild = b.features.windowsBuild
		reply.WindowsUBR = b.features.windowsUBR
		return nil
	}
	if b.backend.partition == 0 {
		return errors.New("whpx: partition has not started")
	}
	switch request.Operation {
	case "Map":
		if !validBrokerRange(request) || request.Source == 0 || request.Source%pageSize != 0 || request.Source+request.Size < request.Source || request.Flags == 0 || request.Flags&^uint32(7) != 0 {
			return errors.New("whpx: invalid worker memory mapping")
		}
		return call(procMapGpaRange2, "WHvMapGpaRange2", b.backend.partition, uintptr(b.process), uintptr(request.Source), uintptr(request.GPA), uintptr(request.Size), uintptr(request.Flags))
	case "Unmap":
		if !validBrokerRange(request) {
			return errors.New("whpx: invalid worker memory range")
		}
		return b.backend.unmapGPA(request.GPA, request.Size)
	}
	if request.Index >= b.vpCount {
		return errors.New("whpx: processor index exceeds the partition")
	}
	b.stateMu.Lock()
	if request.Operation == "CreateVP" {
		defer b.stateMu.Unlock()
		if b.created[request.Index] {
			return errors.New("whpx: processor already exists")
		}
		if err := b.backend.createVP(request.Index); err != nil {
			return err
		}
		b.created[request.Index] = true
		return nil
	}
	if !b.created[request.Index] {
		b.stateMu.Unlock()
		return errors.New("whpx: processor does not exist")
	}
	if request.Operation == "Cancel" {
		b.stateMu.Unlock()
		return b.backend.cancel(request.Index)
	}
	if b.running[request.Index].Load() {
		b.stateMu.Unlock()
		return errors.New("whpx: processor is running")
	}
	if request.Operation == "DeleteVP" {
		defer b.stateMu.Unlock()
		if err := b.backend.deleteVP(request.Index); err != nil {
			return err
		}
		b.created[request.Index] = false
		return nil
	}
	// Serialize register operations with Run for this processor.
	b.running[request.Index].Store(true)
	b.stateMu.Unlock()
	defer b.running[request.Index].Store(false)
	switch request.Operation {
	case "Run":
		reply.Values = alignedBuf(exitCtxBufSize, 16)
		return b.backend.run(request.Index, reply.Values)
	case "GetRegisters", "SetRegisters":
		if len(request.Names) == 0 || len(request.Names) > 512 {
			return errors.New("whpx: invalid register count")
		}
		rb := newRegBatch(len(request.Names))
		rb.n = len(request.Names)
		copy(rb.names, request.Names)
		if request.Operation == "GetRegisters" {
			if err := b.backend.getRegs(request.Index, rb); err != nil {
				return err
			}
			_, reply.Values = rb.view()
			return nil
		}
		if len(request.Values) != len(request.Names)*regValueSize {
			return errors.New("whpx: invalid register values")
		}
		copy(rb.raw, request.Values)
		return b.backend.setRegs(request.Index, rb)
	default:
		return errors.New("whpx: unknown broker operation")
	}
}

func validBrokerRange(request BrokerRequest) bool {
	return request.Size != 0 && request.Size%pageSize == 0 && request.GPA%pageSize == 0 && request.GPA >= gpaWindowBase && request.GPA < gpaWindowEnd && request.Size <= gpaWindowEnd-request.GPA
}

// Close stops processors before it releases the partition and its mappings.
func (b *Broker) Close() error {
	if b.closed.Swap(true) {
		return nil
	}
	var errs []error
	b.mu.RLock()
	b.stateMu.Lock()
	for index, created := range b.created {
		if created {
			errs = append(errs, b.backend.cancel(uint32(index)))
		}
	}
	b.stateMu.Unlock()
	b.mu.RUnlock()
	b.mu.Lock()
	defer b.mu.Unlock()
	for index, created := range b.created {
		if created {
			errs = append(errs, b.backend.deleteVP(uint32(index)))
			b.created[index] = false
		}
	}
	errs = append(errs, b.backend.closePartition())
	return errors.Join(errs...)
}

type brokerBackend struct {
	winBackend
	client *rpc.Client
}

// NewBrokered creates a platform through a broker registered as Hypervisor.
// The caller owns client and closes it after Platform.Close.
func NewBrokered(client *rpc.Client) (*Platform, error) {
	if client == nil {
		return nil, errors.New("whpx: broker client is required")
	}
	if err := checkPageSize(hostarch.PageSize); err != nil {
		return nil, err
	}
	return newPlatform(&brokerBackend{client: client}, Options{})
}

func (b *brokerBackend) invoke(request BrokerRequest) (reply BrokerReply, err error) {
	err = b.client.Call("Hypervisor.Call", request, &reply)
	return reply, err
}
func (b *brokerBackend) features() (hostFeatures, error) {
	r, err := b.invoke(BrokerRequest{Operation: "Features"})
	return hostFeatures{hypervisorPresent: r.HypervisorPresent, arm64Support: r.ARM64Support, windowsBuild: r.WindowsBuild, windowsUBR: r.WindowsUBR}, err
}
func (b *brokerBackend) createPartition(count uint32) (partitionInfo, error) {
	r, err := b.invoke(BrokerRequest{Operation: "Setup", Processors: count})
	return partitionInfo{vpCount: r.Processors, xsave: r.Xsave}, err
}
func (b *brokerBackend) closePartition() error {
	_, err := b.invoke(BrokerRequest{Operation: "Close"})
	return err
}
func (b *brokerBackend) mapGPA(source unsafe.Pointer, gpa, size uint64, flags uint32) error {
	_, err := b.invoke(BrokerRequest{Operation: "Map", Source: uint64(uintptr(source)), GPA: gpa, Size: size, Flags: flags})
	return err
}
func (b *brokerBackend) unmapGPA(gpa, size uint64) error {
	_, err := b.invoke(BrokerRequest{Operation: "Unmap", GPA: gpa, Size: size})
	return err
}
func (b *brokerBackend) createVP(index uint32) error {
	_, err := b.invoke(BrokerRequest{Operation: "CreateVP", Index: index})
	return err
}
func (b *brokerBackend) deleteVP(index uint32) error {
	_, err := b.invoke(BrokerRequest{Operation: "DeleteVP", Index: index})
	return err
}
func (b *brokerBackend) cancel(index uint32) error {
	_, err := b.invoke(BrokerRequest{Operation: "Cancel", Index: index})
	return err
}
func (b *brokerBackend) run(index uint32, exit []byte) error {
	r, err := b.invoke(BrokerRequest{Operation: "Run", Index: index})
	if err == nil && len(r.Values) != len(exit) {
		return errors.New("whpx: invalid broker exit context")
	}
	copy(exit, r.Values)
	return err
}
func (b *brokerBackend) getRegs(index uint32, rb *regBatch) error {
	names, values := rb.view()
	r, err := b.invoke(BrokerRequest{Operation: "GetRegisters", Index: index, Names: names})
	if err == nil && len(r.Values) != len(values) {
		return errors.New("whpx: invalid broker register result")
	}
	copy(values, r.Values)
	return err
}
func (b *brokerBackend) setRegs(index uint32, rb *regBatch) error {
	names, values := rb.view()
	_, err := b.invoke(BrokerRequest{Operation: "SetRegisters", Index: index, Names: names, Values: values})
	return err
}
