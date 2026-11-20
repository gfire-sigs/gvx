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

//go:build !darwin

package virtgpu

import (
	"fmt"
	"unsafe"

	"z.gfire.dev/gvx/pkg/fd"
)

// blobView is empty on hosts without a blob path. The device registers only
// on darwin (pkg/gvx refuses the GPU option elsewhere).
type blobView struct{}

func mapBlobView(*fd.HostHandle, uint64) (blobView, uint64, error) {
	return blobView{}, 0, fmt.Errorf("%w: no blob path on this host", errBlobSize)
}

func (blobView) mapped() bool { return false }

func (blobView) base() unsafe.Pointer { return nil }

func (blobView) unmap() error { return nil }
