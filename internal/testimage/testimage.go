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

// Package testimage builds OCI layer tarballs and serves them from an
// in-process registry, so tests exercise the image pipeline without network
// access.
package testimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// File is one entry of a layer tarball.
type File struct {
	// Name is the tar entry name, for example "etc/passwd".
	Name string
	// Data is the regular file content.
	Data []byte
	// Mode is the permission bits. Zero selects 0644 for files and 0755 for
	// directories.
	Mode int64
	// Type is the tar type flag. Zero selects a regular file.
	Type byte
	// Linkname is the symlink or hardlink target.
	Linkname string
}

// Tar returns an uncompressed layer tarball with the entries in the given
// order. The order matters for whiteout semantics.
func Tar(files ...File) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, f := range files {
		typeflag := f.Type
		if typeflag == 0 {
			typeflag = tar.TypeReg
		}
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
			if typeflag == tar.TypeDir {
				mode = 0o755
			}
		}
		hdr := &tar.Header{
			Name:     f.Name,
			Mode:     mode,
			Typeflag: typeflag,
			Linkname: f.Linkname,
		}
		if typeflag == tar.TypeReg {
			hdr.Size = int64(len(f.Data))
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, fmt.Errorf("write tar header %q: %w", f.Name, err)
		}
		if typeflag == tar.TypeReg {
			if _, err := tw.Write(f.Data); err != nil {
				return nil, fmt.Errorf("write tar body %q: %w", f.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, fmt.Errorf("close tar: %w", err)
	}
	return buf.Bytes(), nil
}

// Image describes one single-architecture image of a test registry.
type Image struct {
	// Arch is the Linux architecture: "amd64" or "arm64".
	Arch string
	// Layers holds uncompressed layer tarballs from the lowest layer up.
	Layers [][]byte
	// Entrypoint, Cmd, Env, and WorkingDir fill the image config.
	Entrypoint []string
	Cmd        []string
	Env        []string
	WorkingDir string
}

type blob struct {
	data      []byte
	mediaType string
}

type registry struct {
	repo      string
	blobs     map[string]blob // key: "sha256:<hex>"
	manifests map[string]blob // key: tag or digest
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *platform `json:"platform,omitempty"`
}

type platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
}

func (r *registry) addBlob(data []byte, mediaType string) descriptor {
	d := digestOf(data)
	r.blobs[d] = blob{data: data, mediaType: mediaType}
	return descriptor{MediaType: mediaType, Digest: d, Size: int64(len(data))}
}

func (r *registry) addManifest(key string, data []byte, mediaType string) descriptor {
	d := digestOf(data)
	r.manifests[d] = blob{data: data, mediaType: mediaType}
	if key != "" {
		r.manifests[key] = blob{data: data, mediaType: mediaType}
	}
	return descriptor{MediaType: mediaType, Digest: d, Size: int64(len(data))}
}

// Registry is a running in-process registry.
type Registry struct {
	// URL is the registry base URL, for example "http://127.0.0.1:41234".
	URL string
	srv *httptest.Server
}

// Close stops the server. Later requests fail with a connection error.
// Close is safe to call more than once.
func (r *Registry) Close() {
	r.srv.Close()
}

// NewRegistry starts an in-process OCI registry that serves repo:tag as an
// image index with one manifest per entry of images, and returns its base
// URL. The server closes when the test ends.
func NewRegistry(tb testing.TB, repo, tag string, images ...Image) string {
	tb.Helper()
	return NewRegistryServer(tb, repo, tag, images...).URL
}

// NewRegistryServer is like NewRegistry but returns the server, so a test
// can stop it early.
func NewRegistryServer(tb testing.TB, repo, tag string, images ...Image) *Registry {
	tb.Helper()
	return newRegistryServer(tb, nil, repo, tag, images...)
}

// NewTLSRegistryServer is like NewRegistryServer but serves HTTPS with cert.
// The URL of the result starts with "https://".
func NewTLSRegistryServer(tb testing.TB, cert tls.Certificate, repo, tag string, images ...Image) *Registry {
	tb.Helper()
	return newRegistryServer(tb, &cert, repo, tag, images...)
}

func newRegistryServer(tb testing.TB, cert *tls.Certificate, repo, tag string, images ...Image) *Registry {
	tb.Helper()
	r := &registry{
		repo:      repo,
		blobs:     make(map[string]blob),
		manifests: make(map[string]blob),
	}
	index := struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Manifests     []descriptor `json:"manifests"`
	}{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json"}

	for _, img := range images {
		manifestDesc, err := r.addImage(img)
		if err != nil {
			tb.Fatalf("testimage: build image for %s: %v", img.Arch, err)
		}
		index.Manifests = append(index.Manifests, manifestDesc)
	}
	indexBytes, err := json.Marshal(index)
	if err != nil {
		tb.Fatalf("testimage: marshal index: %v", err)
	}
	r.addManifest(tag, indexBytes, index.MediaType)

	srv := httptest.NewUnstartedServer(r)
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	tb.Cleanup(srv.Close)
	return &Registry{URL: srv.URL, srv: srv}
}

func (r *registry) addImage(img Image) (descriptor, error) {
	var diffIDs []string
	var layerDescs []descriptor
	for i, rawTar := range img.Layers {
		var gz bytes.Buffer
		zw := gzip.NewWriter(&gz)
		if _, err := zw.Write(rawTar); err != nil {
			return descriptor{}, fmt.Errorf("compress layer %d: %w", i, err)
		}
		if err := zw.Close(); err != nil {
			return descriptor{}, fmt.Errorf("close layer %d: %w", i, err)
		}
		layerDescs = append(layerDescs, r.addBlob(gz.Bytes(), "application/vnd.oci.image.layer.v1.tar+gzip"))
		diffIDs = append(diffIDs, digestOf(rawTar))
	}

	type runtimeConfig struct {
		Entrypoint []string `json:"Entrypoint,omitempty"`
		Cmd        []string `json:"Cmd,omitempty"`
		Env        []string `json:"Env,omitempty"`
		WorkingDir string   `json:"WorkingDir,omitempty"`
	}
	cfg := struct {
		Architecture string        `json:"architecture"`
		OS           string        `json:"os"`
		Config       runtimeConfig `json:"config"`
		RootFS       struct {
			Type    string   `json:"type"`
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}{
		Architecture: img.Arch,
		OS:           "linux",
		Config: runtimeConfig{
			Entrypoint: img.Entrypoint,
			Cmd:        img.Cmd,
			Env:        img.Env,
			WorkingDir: img.WorkingDir,
		},
	}
	cfg.RootFS.Type = "layers"
	cfg.RootFS.DiffIDs = diffIDs
	cfgBytes, err := json.Marshal(cfg)
	if err != nil {
		return descriptor{}, fmt.Errorf("marshal config: %w", err)
	}
	cfgDesc := r.addBlob(cfgBytes, "application/vnd.oci.image.config.v1+json")

	manifest := struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Config        descriptor   `json:"config"`
		Layers        []descriptor `json:"layers"`
	}{
		SchemaVersion: 2,
		MediaType:     "application/vnd.oci.image.manifest.v1+json",
		Config:        cfgDesc,
		Layers:        layerDescs,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	desc := r.addManifest("", manifestBytes, manifest.MediaType)
	desc.Platform = &platform{Architecture: img.Arch, OS: "linux"}
	return desc, nil
}

// ServeHTTP implements the read side of the OCI distribution API.
func (r *registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if req.URL.Path == "/v2/" || req.URL.Path == "/v2" {
		w.WriteHeader(http.StatusOK)
		return
	}
	rest, ok := strings.CutPrefix(req.URL.Path, "/v2/"+r.repo+"/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	var item blob
	var found bool
	switch {
	case strings.HasPrefix(rest, "manifests/"):
		item, found = r.manifests[strings.TrimPrefix(rest, "manifests/")]
	case strings.HasPrefix(rest, "blobs/"):
		item, found = r.blobs[strings.TrimPrefix(rest, "blobs/")]
	}
	if !found {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", item.mediaType)
	w.Header().Set("Docker-Content-Digest", digestOf(item.data))
	w.Header().Set("Content-Length", strconv.Itoa(len(item.data)))
	w.WriteHeader(http.StatusOK)
	if req.Method == http.MethodGet {
		_, _ = w.Write(item.data)
	}
}
