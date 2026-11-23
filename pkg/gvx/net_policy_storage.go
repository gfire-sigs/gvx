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

package gvx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"golang.org/x/text/unicode/norm"

	"z.gfire.dev/gvx/internal/hoststorage"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
)

type policyStoragePath struct {
	path     string
	dir      *os.File
	owned    bool
	tail     []string
	isDir    bool
	ancestry []hoststorage.StorageIdentity
	file     hoststorage.StorageIdentity
}

type policyStorage struct {
	private []policyStoragePath
	output  int
	files   []hoststorage.StorageIdentity
}

func unsafePolicyStorage(err error) error {
	return fmt.Errorf("%w: %w: %w", ErrInvalidConfig, netPolicyError("invalid_policy", "unsafe network policy storage"), err)
}

// locatePolicyStorage holds the existing parent of an uncreated path. It does
// not make directories or open the contents of a file.
func locatePolicyStorage(path string, isDir bool) (policyStoragePath, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return policyStoragePath{}, err
	}
	dirPath := abs
	var tail []string
	if !isDir {
		dirPath = filepath.Dir(abs)
		tail = append(tail, filepath.Base(abs))
	}
	dirPath = resolveSymlinkPrefix(dirPath)
	p := policyStoragePath{path: filepath.Join(dirPath, filepath.Join(tail...)), isDir: isDir, owned: true}
	for {
		p.dir, err = os.Open(dirPath)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(dirPath) == dirPath {
			return policyStoragePath{}, err
		}
		tail = append(tail, filepath.Base(dirPath))
		dirPath = filepath.Dir(dirPath)
	}
	info, err := p.dir.Stat()
	if err == nil && !info.IsDir() {
		err = fmt.Errorf("%q is not a directory", dirPath)
	}
	if err != nil {
		return policyStoragePath{}, errors.Join(err, p.dir.Close())
	}
	slices.Reverse(tail)
	p.tail = tail
	p.ancestry, err = hoststorage.StorageAncestry(p.dir)
	if err != nil {
		return policyStoragePath{}, errors.Join(err, p.dir.Close())
	}
	return p, nil
}

func (p *policyStoragePath) createDir(tail []string, perm os.FileMode) (*os.File, error) {
	dir := p.dir
	for _, name := range tail {
		child, err := hoststorage.OpenStorageDir(dir, name, true, perm)
		if dir != p.dir {
			err = errors.Join(err, dir.Close())
		}
		if err != nil {
			if child != nil {
				_ = child.Close()
			}
			return nil, err
		}
		dir = child
	}
	return dir, nil
}

func (p *policyStoragePath) close() error {
	if p.owned {
		p.owned = false
		return p.dir.Close()
	}
	return nil
}

func (s *policyStorage) close() error {
	var errs []error
	for i := range s.private {
		errs = append(errs, s.private[i].close())
	}
	return errors.Join(errs...)
}

func capturePolicyStorage(opts *NetPolicyOptions, input *bundleRoot, output, unixPath string) (*policyStorage, error) {
	s := &policyStorage{output: -1}
	if err := s.capture(opts, input, output, unixPath); err != nil {
		return nil, errors.Join(err, s.close())
	}
	return s, nil
}

func (s *policyStorage) capture(opts *NetPolicyOptions, input *bundleRoot, output, unixPath string) error {
	controls := append([]string(nil), opts.ControlPaths...)
	if unixPath != "" {
		controls = append(controls, unixPath)
	}
	for i, path := range controls {
		p, err := locatePolicyStorage(path, false)
		if err != nil {
			return err
		}
		s.private = append(s.private, p)
		if i < len(opts.ControlPaths) && len(p.tail) == 1 {
			id, err := hoststorage.StatStorageFile(p.dir, p.tail[0])
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			if err == nil {
				s.private[len(s.private)-1].file = id
				s.files = append(s.files, id)
			}
		}
	}
	for _, f := range opts.ControlFiles {
		if f == nil {
			return os.ErrInvalid
		}
		id, err := hoststorage.VerifyStorageFile(f)
		if err != nil {
			return err
		}
		if !slices.ContainsFunc(s.files, func(named hoststorage.StorageIdentity) bool {
			return named.SameMount(id) && named.SameFile(id)
		}) {
			return fmt.Errorf("control file %q does not match an approved control path", f.Name())
		}
	}
	if input != nil {
		path, err := filepath.Abs(input.path)
		if err != nil {
			return err
		}
		p, err := openedPolicyStorage(resolveSymlinkPrefix(path), input.dir, nil)
		if err != nil {
			return err
		}
		s.private = append(s.private, p)
	}
	if output != "" {
		p, err := locatePolicyStorage(output, true)
		if err != nil {
			return err
		}
		s.output = len(s.private)
		s.private = append(s.private, p)
	}
	return nil
}

func openedPolicyStorage(path string, dir, file *os.File) (policyStoragePath, error) {
	p := policyStoragePath{path: path, dir: dir, isDir: file == nil}
	var err error
	p.ancestry, err = hoststorage.StorageAncestry(dir)
	if err != nil {
		return policyStoragePath{}, err
	}
	if file != nil {
		p.file, err = hoststorage.VerifyStorageFile(file)
		if err != nil {
			return policyStoragePath{}, err
		}
		if !p.ancestry[0].SameMount(p.file) {
			return policyStoragePath{}, fmt.Errorf("%q crosses a mount boundary", path)
		}
	}
	return p, nil
}

func containsStoragePath(dir, other string) bool {
	if runtime.GOOS == "darwin" {
		dir, other = foldedStoragePath(dir), foldedStoragePath(other)
	}
	rel, err := filepath.Rel(dir, other)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func foldedStoragePath(path string) string {
	return strings.ToLower(norm.NFC.String(path))
}

func (p *policyStoragePath) contains(other *policyStoragePath) bool {
	if !p.isDir {
		if runtime.GOOS == "darwin" {
			return foldedStoragePath(p.path) == foldedStoragePath(other.path)
		}
		return p.path == other.path
	}
	if containsStoragePath(p.path, other.path) {
		return true
	}
	if len(p.tail) != 0 {
		return false
	}
	return slices.ContainsFunc(other.ancestry, p.ancestry[0].SameFile)
}

func (s *policyStorage) validate(p *policyStoragePath) error {
	for i := range s.private {
		private := s.private[i]
		ancestry, err := hoststorage.StorageAncestry(private.dir)
		if err != nil {
			return err
		}
		private.ancestry = ancestry
		left, right := p.ancestry[0], private.ancestry[0]
		if !left.SameMount(right) && !hoststorage.StorageVolumesDisjoint(p.dir, private.dir, left, right) {
			return fmt.Errorf("cannot prove mount %q is separate from private path %q", p.path, private.path)
		}
		if p.contains(&private) || private.contains(p) || (p.file.Links != 0 && private.file.Links != 0 && p.file.SameFile(private.file)) {
			return fmt.Errorf("%q overlaps private path %q", p.path, private.path)
		}
	}
	return s.validateFile(p.file)
}

func (s *policyStorage) validateFile(id hoststorage.StorageIdentity) error {
	if id.Links != 0 && slices.ContainsFunc(s.files, id.SameFile) {
		return errors.New("mounted file aliases private storage")
	}
	return nil
}

func (s *policyStorage) pinCheckpointOutput() error {
	if s.output < 0 {
		return nil
	}
	p := &s.private[s.output]
	if len(p.tail) != 0 {
		dir, err := p.createDir(p.tail, 0o700)
		if err != nil {
			return err
		}
		ancestry, err := hoststorage.StorageAncestry(dir)
		if err != nil {
			return errors.Join(err, dir.Close())
		}
		old := p.dir
		p.dir, p.ancestry, p.tail = dir, ancestry, nil
		if err := old.Close(); err != nil {
			return err
		}
	}
	for _, name := range [...]string{checkpointManifestFileName, checkpointStateFileName, checkpointPagesMetaFileName, checkpointPagesFileName} {
		id, err := hoststorage.StatStorageFile(p.dir, name)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		s.files = append(s.files, id)
	}
	return nil
}

func (s *Sandbox) openCheckpointOutput() (*checkpointBundleFiles, error) {
	if s.policyStorage == nil {
		return openCheckpointBundleFiles(s.cfg.CheckpointDir, nil)
	}
	p := &s.policyStorage.private[s.policyStorage.output]
	p.owned = false // The checkpoint bundle now owns this descriptor.
	b := &bundleRoot{path: p.path, dir: p.dir}
	files, err := openCheckpointBundleFiles(p.path, b)
	if err != nil {
		return nil, unsafePolicyStorage(err)
	}
	s.policyStorage.files = append(s.policyStorage.files, b.identities...)
	return files, nil
}

func (s *Sandbox) openIsolatedHostMount(m Mount, restore bool, shared map[workspaceKey]*hostfs.Workspace) (string, bool, *hostfs.Workspace, error) {
	if runtime.GOOS == "android" {
		return "", false, nil, hoststorage.ErrUnsupported
	}
	path := m.HostPath
	perm := os.FileMode(0o755)
	if m.Kind == MountVolume {
		root, err := s.cfg.volumeRoot()
		if err != nil {
			return "", false, nil, err
		}
		path = filepath.Join(root, m.VolumeName)
		perm = 0o700
	}

	kind, err := classifyHostPath(path)
	if err != nil {
		return "", false, nil, err
	}
	isFile := kind == hostPathFile
	if isFile {
		if m.Kind == MountVolume || (m.GuestPath == workspaceGuestPath && s.cfg.WorkspacePath != "") {
			return "", false, nil, fmt.Errorf("source %q must be a directory", path)
		}
		if path, err = filepath.EvalSymlinks(path); err != nil {
			return "", false, nil, err
		}
	}
	p, err := locatePolicyStorage(path, !isFile)
	if err != nil {
		return "", false, nil, err
	}
	defer p.close()
	if err := s.policyStorage.validate(&p); err != nil {
		return "", false, nil, err
	}
	key := workspaceKey{path: p.path, file: isFile, readOnly: m.ReadOnly}
	if ws := shared[key]; ws != nil {
		return p.path, isFile, ws, nil
	}
	dir := p.dir
	if !isFile && len(p.tail) != 0 {
		if m.Kind != MountVolume && !m.CreateHostPathIfMissing {
			return "", false, nil, os.ErrNotExist
		}
		dir, err = p.createDir(p.tail, perm)
		if err != nil {
			return "", false, nil, err
		}
		defer dir.Close()
	}
	expected, err := hoststorage.IdentifyStorage(dir)
	if err != nil {
		return "", false, nil, err
	}
	if isFile {
		if len(p.tail) != 1 {
			return "", false, nil, os.ErrNotExist
		}
		p.file, err = hoststorage.StatStorageFile(dir, p.tail[0])
		if err != nil {
			return "", false, nil, err
		}
	}
	ws, err := hostfs.OpenIsolatedWorkspace(p.path, m.ReadOnly, restore, func(dir, file *os.File) error {
		actual, err := openedPolicyStorage(p.path, dir, file)
		if err != nil {
			return err
		}
		if !expected.SameFile(actual.ancestry[0]) || !expected.SameMount(actual.ancestry[0]) ||
			isFile != (file != nil) || (isFile && !p.file.SameFile(actual.file)) {
			return fmt.Errorf("source %q changed while opening the mount", p.path)
		}
		return s.policyStorage.validate(&actual)
	}, s.policyStorage.validateFile)
	if err != nil {
		return "", false, nil, err
	}
	shared[key] = ws
	s.workspaces = append(s.workspaces, ws)
	return p.path, isFile, ws, nil
}

func (s *Sandbox) openIsolatedVolumeImage(m Mount, path string, flags int) (*os.File, error) {
	p, err := locatePolicyStorage(path, false)
	if err != nil {
		return nil, unsafePolicyStorage(err)
	}
	defer p.close()
	if err := s.policyStorage.validate(&p); err != nil {
		return nil, unsafePolicyStorage(err)
	}
	dir := p.dir
	if parents := p.tail[:len(p.tail)-1]; len(parents) != 0 {
		if m.ImagePath != "" || flags&os.O_CREATE == 0 {
			return nil, os.ErrNotExist
		}
		dir, err = p.createDir(parents, 0o700)
		if err != nil {
			return nil, unsafePolicyStorage(err)
		}
		defer dir.Close()
	}
	f, err := hoststorage.OpenStorageFile(dir, p.tail[len(p.tail)-1], flags, 0o600)
	if err != nil {
		return nil, unsafePolicyStorage(err)
	}
	actual, err := openedPolicyStorage(p.path, dir, f)
	if err == nil {
		err = s.policyStorage.validate(&actual)
	}
	if err != nil {
		return nil, unsafePolicyStorage(errors.Join(err, f.Close()))
	}
	return f, nil
}
