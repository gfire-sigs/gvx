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

package overlay

// userMountUpperFSNames lists the filesystem type names that a guest overlay
// mount accepts for its upper layer.
//
// WHY: An upper layer must store whiteouts (character device 0:0) and the
// overlay xattrs. These filesystems do both:
//   - "tmpfs" and "9p" are the upstream choices.
//   - "ext4" is the name of the ext4lite volume filesystem. It keeps
//     device nodes and every xattr namespace in its image.
//   - "hostfs" keeps device nodes and trusted.* xattrs in the .gvx_meta
//     table beside the host files.
//
// This package cannot import ext4lite or hostfs, so the names are literals.
// The overlay upper tests in e2e fail when a filesystem changes its name.
var userMountUpperFSNames = map[string]bool{
	"tmpfs":  true,
	"9p":     true,
	"ext4":   true,
	"hostfs": true,
}

// isUserMountUpperFS reports whether a guest overlay mount may use a
// filesystem of this type name as its upper layer.
func isUserMountUpperFS(fsName string) bool {
	return userMountUpperFSNames[fsName]
}
