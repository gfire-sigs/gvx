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

package hostfs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadMeta reads the .gvx_meta file at path and returns its records by the
// workspace-relative path of the entry that each record describes. It reads the
// journal form and the JSON form of earlier releases, and it ignores a torn
// tail as hostfs does.
//
// A record keyed on a file identity has no path of its own. ReadMeta walks the
// host directory that holds the file and names each record by the path where it
// finds the file, so the result matches the tree as it stands, also after a
// rename that a host process made. A hard-linked file appears under each of
// its names. A record whose file no longer exists is missing from the result,
// and so is the record of the workspace root. A virtual symbolic link appears
// when its parent directory exists.
func ReadMeta(path string) (map[string]POSIXAttr, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("hostfs: read %s: %w", path, err)
	}
	img, err := parseMeta(raw)
	if err != nil {
		return nil, err
	}
	if img.paths != nil {
		return img.paths, nil
	}
	out := make(map[string]POSIXAttr, len(img.recs))
	byID := make(map[fileKey]*rec)
	kids := make(map[fileKey][]namedRec)
	for k, r := range img.recs {
		switch k.kind {
		case kindPath:
			out[k.path] = r.attr
		case kindPathName:
			out[joinRelPath(k.path, k.name)] = r.attr
		case kindInode:
			byID[k.id] = r
		case kindName:
			kids[k.id] = append(kids[k.id], namedRec{name: k.name, r: r})
		}
	}
	if len(byID) == 0 && len(kids) == 0 {
		return out, nil
	}
	r := treeReader{dir: filepath.Dir(path), out: out, byID: byID, kids: kids}
	if err := r.read(); err != nil {
		return nil, fmt.Errorf("hostfs: resolve the records of %s: %w", path, err)
	}
	return out, nil
}

// treeReader names the identity-keyed records of one table by walking the host
// directory.
type treeReader struct {
	dir  string
	out  map[string]POSIXAttr
	byID map[fileKey]*rec
	kids map[fileKey][]namedRec

	host    hostBackend
	codec   NameCodec
	rootDev uint64
}

// namedRec is a virtual symbolic link that a directory holds.
type namedRec struct {
	name string
	r    *rec
}

func (t *treeReader) read() error {
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	host, err := newHostRoot(root)
	if err != nil {
		return err
	}
	defer host.close()
	t.host = host
	t.codec = newNameCodec(platformCaps(host, true))
	info, err := host.lstat(".")
	if err != nil {
		return err
	}
	t.rootDev = info.fid.dev
	t.placeKids(info, ".")
	return t.walk(".", ".")
}

// stored returns the identity in the form that .gvx_meta stores.
func (t *treeReader) stored(k fileKey) fileKey {
	if k.dev == t.rootDev {
		k.dev = 0
	}
	return k
}

// placeKids adds the virtual symbolic links of the directory that info
// describes. guest is the guest path of the directory.
func (t *treeReader) placeKids(info hostInfo, guest string) {
	for _, kid := range t.kids[t.stored(info.fid)] {
		t.out[joinRelPath(guest, kid.name)] = kid.r.attr
	}
}

func (t *treeReader) walk(hostDir, guestDir string) error {
	entries, err := t.host.readDir(hostDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if (hostDir == "." && isReservedPath(e.name)) || isEphemeralName(e.name) {
			continue
		}
		if t.codec.active && strings.HasPrefix(e.name, codecPrefix) {
			if _, ok := t.codec.canonicalGuest(e.name); !ok {
				continue
			}
		}
		if e.kind != hostKindRegular && e.kind != hostKindDir {
			continue
		}
		hostRel := hostChild(hostDir, e.name)
		guest := joinRelPath(guestDir, t.codec.ToGuest(e.name))
		info, err := t.host.lstat(hostRel)
		if err != nil {
			continue
		}
		if r := t.byID[t.stored(info.fid)]; r != nil {
			t.out[guest] = r.attr
		}
		if info.kind != hostKindDir {
			continue
		}
		t.placeKids(info, guest)
		if err := t.walk(hostRel, guest); err != nil {
			return err
		}
	}
	return nil
}
