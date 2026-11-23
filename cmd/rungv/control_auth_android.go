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

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/internal/androidcache"
)

var appControlCache *os.File

func init() {
	if len(os.Args) < 2 || os.Args[1] != androidcache.LaunchFlag {
		return
	}
	var err error
	appControlCache, err = adoptAndroidCache(os.Args[2:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "rungv: %v\n", err)
		os.Exit(1)
	}
	os.Args = append(os.Args[:1], os.Args[4:]...)
}

func adoptAndroidCache(args []string) (*os.File, error) {
	if len(args) < 2 {
		return nil, errors.New("missing Android cache descriptor or path")
	}
	fd, err := strconv.Atoi(args[0])
	if err != nil {
		return nil, fmt.Errorf("parse Android cache descriptor: %w", err)
	}
	if err := androidcache.Verify(fd, args[1]); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return nil, fmt.Errorf("protect Android cache descriptor: %w", err)
	}
	return os.NewFile(uintptr(fd), args[1]), nil
}

func appControlTokenDir() (string, error) {
	if appControlCache != nil {
		return filepath.Join(appControlCache.Name(), "gvx", "control"), nil
	}
	if androidcache.AppUID() {
		return "", errors.New("Android app control requires a cache descriptor from Gvx.start")
	}
	return "", nil
}

func openAppControlTokenTarget(path string, create bool) (controlTokenTarget, func() error, error) {
	if appControlCache == nil {
		return nil, nil, nil
	}
	if filepath.Dir(path) != filepath.Join(appControlCache.Name(), "gvx", "control") {
		return nil, nil, errors.New("unexpected Android control token directory")
	}
	gvx, err := openAppControlDir(int(appControlCache.Fd()), "gvx", create, false)
	runtime.KeepAlive(appControlCache)
	if err != nil {
		return nil, nil, err
	}
	dir, err := openAppControlDir(gvx, "control", create, true)
	if err := errors.Join(err, unix.Close(gvx)); err != nil {
		if dir >= 0 {
			err = errors.Join(err, unix.Close(dir))
		}
		return nil, nil, err
	}
	target := appControlTokenTarget{dir: dir, path: path, name: filepath.Base(path)}
	return target, func() error { return unix.Close(dir) }, nil
}

func openAppControlDir(parent int, name string, create, private bool) (int, error) {
	if create {
		if err := unix.Mkdirat(parent, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, err
		}
	}
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	var dir unix.Stat_t
	if err := unix.Fstat(fd, &dir); err != nil {
		return -1, errors.Join(err, unix.Close(fd))
	}
	if dir.Uid != uint32(os.Geteuid()) || dir.Mode&0o022 != 0 || (private && dir.Mode&0o777 != 0o700) {
		return -1, errors.Join(fmt.Errorf("unsafe Android control directory %q", name), unix.Close(fd))
	}
	return fd, nil
}

type appControlTokenTarget struct {
	dir  int
	path string
	name string
}

func (t appControlTokenTarget) verifyRegular() error {
	var st unix.Stat_t
	if err := unix.Fstatat(t.dir, t.name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("control token path %q is not a regular file", t.path)
	}
	return nil
}

func (t appControlTokenTarget) open() (*os.File, error) {
	return t.openFile(unix.O_RDONLY)
}

func (t appControlTokenTarget) create() (*os.File, error) {
	return t.openFile(unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL)
}

func (t appControlTokenTarget) openFile(flags int) (*os.File, error) {
	fd, err := unix.Openat(t.dir, t.name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: t.path, Err: err}
	}
	f := os.NewFile(uintptr(fd), t.path)
	if err := validateControlInput(f, true); err != nil {
		if flags&unix.O_EXCL != 0 {
			err = errors.Join(err, t.removeIfSame(f))
		}
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func (t appControlTokenTarget) remove() error {
	return unix.Unlinkat(t.dir, t.name, 0)
}

func (t appControlTokenTarget) removeIfSame(f *os.File) error {
	var current, created unix.Stat_t
	if err := unix.Fstatat(t.dir, t.name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	err := unix.Fstat(int(f.Fd()), &created)
	runtime.KeepAlive(f)
	if err != nil || current.Dev != created.Dev || current.Ino != created.Ino {
		return err
	}
	return t.remove()
}
