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
)

// readFP reads the floating-point and vector registers of the processor into
// image. The processor must not run.
func (v *vcpu) readFP(image []byte) error {
	if !v.p.arm64 {
		state, err := v.xsaveState()
		if err != nil {
			return err
		}
		return x86StandardFromCompacted(image, state, v.p.vec.xcr0, v.p.vec.layout)
	}
	b := v.regs
	b.reset()
	a64WantFP(b)
	if err := v.p.be.getRegs(v.index, b); err != nil {
		return err
	}
	return a64FPFromRegs(image, b, 0)
}

// writeFP loads image into the floating-point and vector registers of the
// processor. The processor must not run.
func (v *vcpu) writeFP(image []byte) error {
	if !v.p.arm64 {
		// The hypervisor state carries supervisor components and an XCOMP_BV
		// that the Sentry image lacks, so the write starts from the current
		// state of the processor.
		state, err := v.xsaveState()
		if err != nil {
			return err
		}
		if err := x86CompactedFromStandard(state, image, v.p.vec.xcr0, v.p.vec.layout); err != nil {
			return err
		}
		if err := v.p.be.setXsave(v.index, state); err != nil {
			v.xsaveCurrent = false
			return err
		}
		return nil
	}
	b := v.regs
	b.reset()
	if err := a64FPToRegs(b, image); err != nil {
		return err
	}
	return v.p.be.setRegs(v.index, b)
}

// xsaveAlign is the alignment of the XSAVE state buffer. QEMU passes a
// page-aligned buffer to the same calls.
const xsaveAlign = pageSize

// xsaveState returns the XSAVE state of the processor. The state call costs
// as much as a guest exit, so it reads the state only when the processor ran
// since the last read or write. A signal delivery pulls and then pushes the
// state without a run in between.
func (v *vcpu) xsaveState() ([]byte, error) {
	if v.xsaveCurrent {
		return v.xsave[:v.xsaveLen], nil
	}
	return v.fetchXsave()
}

// fetchXsave reads the XSAVE state of the processor into its scratch buffer.
// It grows the buffer once when the hypervisor asks for more space.
func (v *vcpu) fetchXsave() ([]byte, error) {
	for range 2 {
		n, err := v.p.be.getXsave(v.index, v.xsave)
		if errors.Is(err, errXsaveBufferSmall) && n > len(v.xsave) {
			v.xsave = alignedBuf(n, xsaveAlign)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("whpx: read XSAVE state of virtual processor %d: %w", v.index, err)
		}
		v.xsaveLen, v.xsaveCurrent = n, true
		return v.xsave[:n], nil
	}
	return nil, fmt.Errorf("whpx: XSAVE state of virtual processor %d grew between two reads", v.index)
}
