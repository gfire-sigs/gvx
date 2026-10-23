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

package oci

import (
	"archive/tar"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

// archiveMember locates a regular file inside an uncompressed tar archive.
type archiveMember struct {
	off  int64
	size int64
}

// archive is an uncompressed tar file with an index of its regular files.
type archive struct {
	ra      io.ReaderAt
	size    int64
	members map[string]archiveMember
	cache   *LayerCache
}

// posReader reads a ReaderAt sequentially and reports its position. The tar
// reader consumes only header blocks before Next returns, so the position
// after Next is the offset of the entry data.
type posReader struct {
	ra   io.ReaderAt
	size int64
	pos  int64
}

func (p *posReader) Read(b []byte) (int, error) {
	if p.pos >= p.size {
		return 0, io.EOF
	}
	if rest := p.size - p.pos; int64(len(b)) > rest {
		b = b[:rest]
	}
	n, err := p.ra.ReadAt(b, p.pos)
	p.pos += int64(n)
	if n > 0 && errors.Is(err, io.EOF) {
		err = nil
	}
	return n, err
}

func (p *posReader) Seek(offset int64, whence int) (int64, error) {
	var base int64
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		base = p.pos
	case io.SeekEnd:
		base = p.size
	default:
		return 0, errors.New("oci: invalid seek whence")
	}
	if base+offset < 0 {
		return 0, errors.New("oci: negative seek position")
	}
	p.pos = base + offset
	return p.pos, nil
}

// openArchive makes r available as an uncompressed ReaderAt. An uncompressed
// *os.File is used in place, from offset zero. Any other input is decompressed
// into a temporary file in the cache directory. The returned function releases
// the temporary file.
func (c *LayerCache) openArchive(r io.Reader) (*archive, func() error, error) {
	noCleanup := func() error { return nil }
	src := r
	if f, ok := r.(*os.File); ok {
		info, err := f.Stat()
		if err != nil {
			return nil, nil, fmt.Errorf("oci: stat archive: %w", err)
		}
		if info.Mode().IsRegular() {
			var head [magicPeekLen]byte
			n, err := f.ReadAt(head[:], 0)
			if err != nil && !errors.Is(err, io.EOF) {
				return nil, nil, fmt.Errorf("oci: read archive header: %w", err)
			}
			if detectCompression(head[:n]) == compressionNone {
				return &archive{ra: f, size: info.Size(), cache: c}, noCleanup, nil
			}
			src = io.NewSectionReader(f, 0, info.Size())
		}
	}

	dec, err := openDecompressed(src, c.limits)
	if err != nil {
		return nil, nil, err
	}
	defer dec.Close()
	tmp, err := os.CreateTemp(c.dir, tempPattern)
	if err != nil {
		return nil, nil, fmt.Errorf("oci: create temp archive file: %w", err)
	}
	cleanup := func() error {
		closeErr := tmp.Close()
		if err := os.Remove(tmp.Name()); err != nil {
			return fmt.Errorf("oci: remove temp archive file: %w", err)
		}
		return closeErr
	}
	n, err := io.Copy(tmp, newBoundedReader(dec, "decompressed archive size", c.limits.MaxImageBytes, nil))
	if err != nil {
		_ = cleanup()
		return nil, nil, fmt.Errorf("oci: spool archive: %w", err)
	}
	return &archive{ra: tmp, size: n, cache: c}, cleanup, nil
}

// index records the offset and size of every regular file of the archive.
func (a *archive) index() error {
	a.members = make(map[string]archiveMember)
	pr := &posReader{ra: a.ra, size: a.size}
	tr := tar.NewReader(pr)
	var entries int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("oci: read archive tar: %w", err)
		}
		if entries++; entries > a.cache.limits.MaxArchiveEntries {
			return &LimitError{What: "archive member count", Limit: a.cache.limits.MaxArchiveEntries}
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		name, err := cleanTarPath(hdr.Name)
		if err != nil {
			return err
		}
		if hdr.Size < 0 || pr.pos+hdr.Size > a.size {
			return fmt.Errorf("oci: archive member %q is truncated", hdr.Name)
		}
		a.members[name] = archiveMember{off: pr.pos, size: hdr.Size}
	}
}

func (a *archive) reader(name string) (*io.SectionReader, bool) {
	m, ok := a.members[name]
	if !ok {
		return nil, false
	}
	return io.NewSectionReader(a.ra, m.off, m.size), true
}

// readJSON reads a small member under the JSON size budget.
func (a *archive) readJSON(name string) ([]byte, error) {
	sr, ok := a.reader(name)
	if !ok {
		return nil, fmt.Errorf("oci: %q is missing from the archive", name)
	}
	return readAllBounded(sr, "size of "+name, a.cache.limits.MaxJSONBytes)
}

func blobMemberName(digest string) (string, error) {
	hexStr, err := parseDigest(digest)
	if err != nil {
		return "", err
	}
	return "blobs/sha256/" + hexStr, nil
}

// LoadArchiveTar compiles a multi-arch or single-arch image archive into
// cached <sha256>.erofs layers and opens their read-only handles. The archive
// is an OCI image layout, a `docker save` archive, or a plain root filesystem
// tarball, optionally gzip or zstd compressed. A *os.File is read from offset
// zero. The call verifies the manifest, config, and layers of an OCI layout
// against their digests, and the layers of a `docker save` archive against the
// diff IDs of their config.
func LoadArchiveTar(r io.Reader, cache *LayerCache, targetArch string) (*ResolvedImage, error) {
	if cache == nil {
		var err error
		cache, err = NewLayerCache("")
		if err != nil {
			return nil, err
		}
	}
	_, _, _, targetArch = normalizePullArgs("", "", "", targetArch)

	a, cleanup, err := cache.openArchive(r)
	if err != nil {
		return nil, err
	}
	img, loadErr := a.load(targetArch)
	if cleanupErr := cleanup(); loadErr == nil && cleanupErr != nil {
		_ = img.Close()
		return nil, cleanupErr
	}
	return img, loadErr
}

func (a *archive) load(targetArch string) (*ResolvedImage, error) {
	if err := a.index(); err != nil {
		return nil, err
	}

	if _, ok := a.members["index.json"]; ok {
		raw, err := a.readJSON("index.json")
		if err != nil {
			return nil, err
		}
		var idx ImageIndex
		if err := json.Unmarshal(raw, &idx); err == nil && len(idx.Manifests) > 0 {
			return a.loadOCILayout(raw, targetArch)
		}
		if _, ok := a.members["oci-layout"]; ok {
			return nil, errors.New("oci: archive has an oci-layout marker but index.json lists no manifests")
		}
	}
	if _, ok := a.members["manifest.json"]; ok {
		return a.loadDockerSave(targetArch)
	}
	return a.loadRootfs(targetArch)
}

// loadOCILayout resolves an OCI image layout, whose index.json is the entry point.
func (a *archive) loadOCILayout(indexJSON []byte, targetArch string) (*ResolvedImage, error) {
	res, err := resolveManifestChain(indexJSON, targetArch, func(d Descriptor) ([]byte, error) {
		name, err := blobMemberName(d.Digest)
		if err != nil {
			return nil, err
		}
		return a.readJSON(name)
	})
	if err != nil {
		return nil, err
	}
	cfgName, err := blobMemberName(res.Manifest.Config.Digest)
	if err != nil {
		return nil, err
	}
	cfgBytes, err := a.readJSON(cfgName)
	if err != nil {
		return nil, err
	}
	if err := verifyBody(res.Manifest.Config, cfgBytes); err != nil {
		return nil, fmt.Errorf("oci: config %s: %w", res.Manifest.Config.Digest, err)
	}
	cfg, err := parseImageConfig(cfgBytes, targetArch, len(res.Manifest.Layers))
	if err != nil {
		return nil, err
	}

	digests, err := a.compileOCILayers(res.Manifest.Layers)
	if err != nil {
		return nil, err
	}
	return a.cache.finishImage(targetArch, cfg, "", digests)
}

// compileOCILayers compiles the layer blobs of an OCI manifest from the archive
// into the cache and returns their cache keys. It skips a layer that the cache
// already holds.
func (a *archive) compileOCILayers(layers []Descriptor) ([]string, error) {
	image := newByteBudget("decompressed image size", a.cache.limits.MaxImageBytes)
	digests := make([]string, 0, len(layers))
	for _, l := range layers {
		if err := checkLayerDescriptor(l, a.cache.limits); err != nil {
			return nil, err
		}
		name, err := blobMemberName(l.Digest)
		if err != nil {
			return nil, err
		}
		hexStr, _ := parseDigest(l.Digest)
		if _, ok := a.cache.HasLayer(hexStr); !ok {
			sr, ok := a.reader(name)
			if !ok {
				return nil, fmt.Errorf("oci: layer blob %s is missing from the archive", l.Digest)
			}
			spec := layerSpec{key: hexStr, blobHex: hexStr, blobSize: l.Size, image: image}
			if _, _, err := a.cache.compileAndStore(spec, sr); err != nil {
				return nil, fmt.Errorf("oci: compile layer %s: %w", l.Digest, err)
			}
		}
		digests = append(digests, hexStr)
	}
	return digests, nil
}

// dockerSaveEntry is one image of a `docker save` manifest.json.
type dockerSaveEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// loadDockerSave resolves a `docker save` archive. It has no layer digests, so
// the config's diff IDs verify the layers.
func (a *archive) loadDockerSave(targetArch string) (*ResolvedImage, error) {
	entries, err := a.dockerSaveEntries()
	if err != nil {
		return nil, err
	}
	var firstErr error
	for _, e := range entries {
		img, skip, err := a.compileDockerSaveEntry(e, targetArch)
		if skip {
			// A multi-image archive can hold other architectures.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		return a.cache.finishImage(targetArch, img.cfg, "", img.digests)
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, errors.New("oci: manifest.json lists no images")
}

// dockerSaveEntries parses manifest.json.
func (a *archive) dockerSaveEntries() ([]dockerSaveEntry, error) {
	raw, err := a.readJSON("manifest.json")
	if err != nil {
		return nil, err
	}
	var entries []dockerSaveEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("oci: parse manifest.json: %w", err)
	}
	return entries, nil
}

// dockerSaveImage is one compiled image of a `docker save` archive.
type dockerSaveImage struct {
	cfgBytes []byte
	cfg      RuntimeConfig
	// diffIDs are the diff IDs of the config, one per layer.
	diffIDs []string
	// digests are the cache keys of the layers, which are the diff ID hex.
	digests []string
	// layerSizes are the sizes of the layer members in the archive.
	layerSizes []int64
}

// compileDockerSaveEntry compiles the layers of one manifest.json entry. skip
// is true, with the cause in err, when the entry is for another architecture.
func (a *archive) compileDockerSaveEntry(e dockerSaveEntry, targetArch string) (img *dockerSaveImage, skip bool, err error) {
	cfgName, err := cleanTarPath(e.Config)
	if err != nil {
		return nil, false, err
	}
	cfgBytes, err := a.readJSON(cfgName)
	if err != nil {
		return nil, false, err
	}
	cfg, err := parseImageConfig(cfgBytes, targetArch, len(e.Layers))
	if err != nil {
		return nil, true, err
	}
	var parsed imageConfigFile
	if err := json.Unmarshal(cfgBytes, &parsed); err != nil {
		return nil, false, fmt.Errorf("oci: unmarshal image config JSON: %w", err)
	}
	if len(parsed.RootFS.DiffIDs) != len(e.Layers) {
		return nil, false, fmt.Errorf("oci: image config lists %d diff IDs for %d layers", len(parsed.RootFS.DiffIDs), len(e.Layers))
	}

	image := newByteBudget("decompressed image size", a.cache.limits.MaxImageBytes)
	out := &dockerSaveImage{cfgBytes: cfgBytes, cfg: cfg, diffIDs: parsed.RootFS.DiffIDs}
	for i, layer := range e.Layers {
		diffHex, err := parseDigest(parsed.RootFS.DiffIDs[i])
		if err != nil {
			return nil, false, err
		}
		name, err := cleanTarPath(layer)
		if err != nil {
			return nil, false, err
		}
		if _, ok := a.cache.HasLayer(diffHex); !ok {
			sr, ok := a.reader(name)
			if !ok {
				return nil, false, fmt.Errorf("oci: layer %q is missing from the archive", layer)
			}
			spec := layerSpec{key: diffHex, blobSize: -1, diffID: diffHex, image: image}
			if _, _, err := a.cache.compileAndStore(spec, sr); err != nil {
				return nil, false, fmt.Errorf("oci: compile layer %q: %w", layer, err)
			}
		}
		out.digests = append(out.digests, diffHex)
		out.layerSizes = append(out.layerSizes, a.members[name].size)
	}
	return out, false, nil
}

// loadRootfs compiles an archive that is itself a root filesystem tarball.
func (a *archive) loadRootfs(targetArch string) (*ResolvedImage, error) {
	image := newByteBudget("decompressed image size", a.cache.limits.MaxImageBytes)
	_, stats, err := a.cache.compileAndStore(layerSpec{blobSize: -1, image: image}, io.NewSectionReader(a.ra, 0, a.size))
	if err != nil {
		return nil, err
	}
	return a.cache.finishImage(targetArch, RuntimeConfig{WorkingDir: "/"}, "", []string{stats.SHA256Hex})
}
