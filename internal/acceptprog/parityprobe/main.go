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

//go:build linux

// Command parityprobe checks the guest kernel features that gvx shares with
// runsc. Each check prints "PASS name" or "FAIL name: reason". The probe runs
// as root in a guest without an image.
//
// Usage:
//
//	parityprobe checks     run every check, then print DONE
//	parityprobe euid       copy the probe as a set-user-ID file, run the copy
//	                       as user 1000, and print the user IDs of the copy
//	parityprobe ids        print the real and effective user IDs
//	parityprobe overlay-upper DIR   mount an overlay with its upper layer in DIR,
//	                       write whiteouts and opaque directories, and verify
//	                       the view after a new mount
//	parityprobe overlay-write DIR [hold]   write that state; with hold, sync it,
//	                       print SYNCED, and sleep
//	parityprobe overlay-verify DIR   verify the state that overlay-write left
//	parityprobe sleep      sleep for one minute
//	parityprobe poweroff   call reboot(2) with LINUX_REBOOT_CMD_POWER_OFF
//	parityprobe restart    call reboot(2) with LINUX_REBOOT_CMD_RESTART
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	netlinkKobjectUevent = 15
	cmdPowerOff          = 0x4321fedc
	cmdRestart           = 0x01234567
	rebootMagic1         = 0xfee1dead
	rebootMagic2         = 672274793
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: parityprobe checks|euid|ids|poweroff|restart")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "checks":
		runChecks()
	case "euid":
		if err := runSetUID(); err != nil {
			fmt.Println("FAIL euid:", err)
			os.Exit(1)
		}
	case "overlay-upper", "overlay-write", "overlay-verify":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: parityprobe", os.Args[1], "DIR [hold]")
			os.Exit(2)
		}
		hold := len(os.Args) > 3 && os.Args[3] == "hold"
		if !runOverlayUpper(os.Args[1], os.Args[2], hold) {
			os.Exit(1)
		}
	case "ids":
		fmt.Printf("uid=%d euid=%d\n", os.Getuid(), os.Geteuid())
	case "sleep":
		time.Sleep(time.Minute)
	case "poweroff":
		reboot(cmdPowerOff)
	case "restart":
		reboot(cmdRestart)
	default:
		fmt.Fprintln(os.Stderr, "unknown mode", os.Args[1])
		os.Exit(2)
	}
}

// reboot calls reboot(2) while a child process sleeps. The sandbox must stop
// both. The probe then waits, so only the kernel can end it.
func reboot(cmd uintptr) {
	child := exec.Command("/proc/self/exe", "sleep")
	if err := child.Start(); err != nil {
		fmt.Println("FAIL reboot: start child:", err)
		os.Exit(1)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_REBOOT, rebootMagic1, rebootMagic2, cmd); errno != 0 {
		fmt.Println("FAIL reboot:", errno)
		os.Exit(1)
	}
	time.Sleep(time.Minute)
	fmt.Println("FAIL reboot: the sandbox did not stop")
	os.Exit(1)
}

func runChecks() {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"tmpfs-percent-size", checkTmpfsPercent},
		{"cgroup2-mounted", func() error { return checkMounted("/sys/fs/cgroup", "cgroup2") }},
		{"mqueue-mounted", func() error { return checkMounted("/dev/mqueue", "mqueue") }},
		{"mq-open", checkMQOpen},
		{"dev-fuse", func() error { return checkCharDevice("/dev/fuse") }},
		{"dev-net-tun", func() error { return checkCharDevice("/dev/net/tun") }},
		{"uevent-socket", checkUeventSocket},
		{"loopback-named", checkLoopbackNamed},
		{"new-netns-has-lo", checkNewNetns},
		{"pivot-root", checkPivotRoot},
		{"keyring-link", checkKeyringLink},
		{"overlay-dentry-cache", checkOverlayDentries},
		{"mnt-ns-setns", checkMountNamespaceSetns},
	}
	for _, c := range checks {
		if err := c.fn(); err != nil {
			fmt.Printf("FAIL %s: %v\n", c.name, err)
			continue
		}
		fmt.Printf("PASS %s\n", c.name)
	}
	fmt.Println("DONE")
}

// memTotalBytes reads MemTotal from /proc/meminfo.
func memTotalBytes() (uint64, error) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.ParseUint(fields[1], 10, 64)
			return kb << 10, err
		}
	}
	return 0, errors.New("no MemTotal line")
}

// checkTmpfsPercent mounts a tmpfs with size=25%. Linux resolves the
// percentage against the RAM that MemTotal reports.
func checkTmpfsPercent() error {
	total, err := memTotalBytes()
	if err != nil {
		return err
	}
	dir := "/tmp/pct"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, "size=25%"); err != nil {
		return fmt.Errorf("mount size=25%%: %w", err)
	}
	defer syscall.Unmount(dir, 0)
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return err
	}
	size := st.Blocks * uint64(st.Bsize)
	want := total / 4
	if diff := int64(size) - int64(want); diff > int64(want/100) || -diff > int64(want/100) {
		return fmt.Errorf("size %d, want 25%% of MemTotal %d (%d)", size, total, want)
	}
	return nil
}

func checkMounted(target, fsType string) error {
	// /proc/self would show the mounts of the thread group leader. See
	// checkMountNamespaceSetns.
	data, err := os.ReadFile("/proc/thread-self/mounts")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[1] == target && f[2] == fsType {
			return nil
		}
	}
	return fmt.Errorf("no %s mount at %s in:\n%s", fsType, target, data)
}

func checkMQOpen() error {
	name := []byte("parityprobe\x00")
	fd, _, errno := syscall.Syscall6(syscall.SYS_MQ_OPEN, uintptr(unsafe.Pointer(&name[0])), uintptr(syscall.O_CREAT|syscall.O_RDWR), 0o600, 0, 0, 0)
	if errno != 0 {
		return fmt.Errorf("mq_open: %w", errno)
	}
	syscall.Close(int(fd))
	if _, _, errno := syscall.Syscall(syscall.SYS_MQ_UNLINK, uintptr(unsafe.Pointer(&name[0])), 0, 0); errno != 0 {
		return fmt.Errorf("mq_unlink: %w", errno)
	}
	return nil
}

func checkCharDevice(path string) error {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFCHR {
		return fmt.Errorf("mode %#o is not a character device", st.Mode)
	}
	return nil
}

// checkUeventSocket opens and binds a NETLINK_KOBJECT_UEVENT socket, as
// systemd-logind does at start. As in runsc, the socket joins no multicast
// group, because the kernel sends no device events.
func checkUeventSocket() error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, netlinkKobjectUevent)
	if err != nil {
		return err
	}
	defer syscall.Close(fd)
	return syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK})
}

func interfaceNames() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, i := range ifs {
		names = append(names, fmt.Sprintf("%d:%s", i.Index, i.Name))
	}
	return names, nil
}

func checkLoopbackNamed() error {
	names, err := interfaceNames()
	if err != nil {
		return err
	}
	for _, n := range names {
		if n == "1:lo" {
			return nil
		}
	}
	return fmt.Errorf("interfaces %v lack 1:lo", names)
}

// inNewThreadNamespace runs fn on a locked thread after unshare(flags). The
// thread never returns to the Go scheduler, because its namespaces differ.
func inNewThreadNamespace(flags uintptr, fn func() error) error {
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if _, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, flags, 0, 0); errno != 0 {
			done <- fmt.Errorf("unshare(%#x): %w", flags, errno)
			return
		}
		done <- fn()
	}()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		return errors.New("no answer after 10s")
	}
}

func checkNewNetns() error {
	return inNewThreadNamespace(syscall.CLONE_NEWNET, func() error {
		names, err := interfaceNames()
		if err != nil {
			return err
		}
		if len(names) != 1 || names[0] != "1:lo" {
			return fmt.Errorf("interfaces %v, want [1:lo]", names)
		}
		return nil
	})
}

// checkPivotRoot makes a tmpfs the root of a new mount namespace, as runc
// does for a container.
func checkPivotRoot() error {
	return inNewThreadNamespace(syscall.CLONE_NEWNS|syscall.CLONE_FS, func() error {
		dir := "/tmp/newroot"
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		if err := syscall.Mount("tmpfs", dir, "tmpfs", 0, ""); err != nil {
			return fmt.Errorf("mount tmpfs: %w", err)
		}
		if err := os.Mkdir(dir+"/old", 0o755); err != nil {
			return err
		}
		if err := syscall.Chdir(dir); err != nil {
			return err
		}
		if err := syscall.PivotRoot(".", "old"); err != nil {
			return fmt.Errorf("pivot_root: %w", err)
		}
		if _, err := os.Stat("/old/proc"); err != nil {
			return fmt.Errorf("old root not under /old: %w", err)
		}
		return nil
	})
}

// checkOverlayDentries renames, deletes, and recreates files on the overlay
// root after lookups have cached their dentries. It also creates more files
// than the overlay keeps unused dentries for. A stale dentry would show a
// file at its old name or hide a new one.
func checkOverlayDentries() error {
	const app = "/bin/app"
	for range 3 {
		if _, err := os.Stat(app); err != nil {
			return err
		}
	}
	if err := os.Rename(app, app+"2"); err != nil {
		return fmt.Errorf("rename lower file: %w", err)
	}
	if _, err := os.Stat(app); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat %s after rename: %v, want ENOENT", app, err)
	}
	if err := os.Rename(app+"2", app); err != nil {
		return err
	}
	if _, err := os.Stat(app); err != nil {
		return fmt.Errorf("stat %s after rename back: %w", app, err)
	}

	base := "/tmp/dcache"
	if err := os.MkdirAll(base+"/a/b", 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(base+"/a/b/f", []byte("x"), 0o644); err != nil {
		return err
	}
	if _, err := os.Stat(base + "/a/b/f"); err != nil {
		return err
	}
	if err := os.Rename(base+"/a", base+"/z"); err != nil {
		return err
	}
	if _, err := os.Stat(base + "/a/b/f"); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat old path after directory rename: %v, want ENOENT", err)
	}
	if data, err := os.ReadFile(base + "/z/b/f"); err != nil || string(data) != "x" {
		return fmt.Errorf("read new path after directory rename: %q, %v", data, err)
	}

	const n = 5000
	for i := range n {
		if err := os.WriteFile(fmt.Sprintf("%s/f%d", base, i), nil, 0o644); err != nil {
			return err
		}
	}
	for i := range n {
		if _, err := os.Stat(fmt.Sprintf("%s/f%d", base, i)); err != nil {
			return err
		}
	}
	for i := range n {
		if err := os.Remove(fmt.Sprintf("%s/f%d", base, i)); err != nil {
			return err
		}
	}
	for i := range n {
		if _, err := os.Stat(fmt.Sprintf("%s/f%d", base, i)); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat f%d after unlink: %v, want ENOENT", i, err)
		}
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != "z" {
		return fmt.Errorf("entries of %s = %d, want only z", base, len(entries))
	}
	return os.RemoveAll(base)
}

// checkMountNamespaceSetns reads the mount namespace link of the process and
// enters that namespace with setns(2) from a new mount namespace, as runc
// exec does for docker exec. runc reports a namespace as unsupported when its
// /proc/self/ns link cannot be read.
//
// The probe reads the namespace of its own thread through /proc/thread-self.
// /proc/self names the thread group leader. When a goroutine that changed its
// namespaces exits on the main thread, the Go runtime parks that thread for
// good, so the leader can stay in the private namespace of an earlier check.
func checkMountNamespaceSetns() error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	link, err := os.Readlink("/proc/thread-self/ns/mnt")
	if err != nil {
		return fmt.Errorf("readlink /proc/thread-self/ns/mnt: %w", err)
	}
	if !strings.HasPrefix(link, "mnt:[") {
		return fmt.Errorf("/proc/thread-self/ns/mnt = %q, want mnt:[N]", link)
	}
	fd, err := syscall.Open("/proc/thread-self/ns/mnt", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open /proc/thread-self/ns/mnt: %w", err)
	}
	defer syscall.Close(fd)
	return inNewThreadNamespace(syscall.CLONE_NEWNS|syscall.CLONE_FS, func() error {
		inner, err := os.Readlink("/proc/thread-self/ns/mnt")
		if err != nil {
			return fmt.Errorf("readlink in the new namespace: %w", err)
		}
		if inner == link {
			return fmt.Errorf("unshare(CLONE_NEWNS) kept the namespace %s", link)
		}
		if _, _, errno := syscall.RawSyscall(sysSetns, uintptr(fd), syscall.CLONE_NEWNS, 0); errno != 0 {
			return fmt.Errorf("setns(CLONE_NEWNS): %w", errno)
		}
		back, err := os.Readlink("/proc/thread-self/ns/mnt")
		if err != nil {
			return fmt.Errorf("readlink after setns: %w", err)
		}
		if back != link {
			return fmt.Errorf("namespace after setns = %s, want %s", back, link)
		}
		return nil
	})
}

// checkKeyringLink joins a new session keyring and links the user keyring into
// it, as systemd does before it starts a mount unit.
func checkKeyringLink() error {
	const (
		keyctlJoinSessionKeyring = 1
		keyctlLink               = 8
		keySpecUserKeyring       = -4
		keySpecSessionKeyring    = -3
	)
	if _, _, errno := syscall.Syscall(syscall.SYS_KEYCTL, keyctlJoinSessionKeyring, 0, 0); errno != 0 {
		return fmt.Errorf("join session keyring: %w", errno)
	}
	user, session := keySpecUserKeyring, keySpecSessionKeyring
	if _, _, errno := syscall.Syscall(syscall.SYS_KEYCTL, keyctlLink, uintptr(user), uintptr(session)); errno != 0 {
		return fmt.Errorf("link the user keyring: %w", errno)
	}
	return nil
}

// runSetUID copies the probe to a set-user-ID file that root owns, and runs
// the copy as user 1000.
func runSetUID() error {
	src, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer src.Close()
	const copyPath = "/tmp/parityprobe-suid"
	dst, err := os.OpenFile(copyPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		dst.Close()
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	if err := syscall.Chmod(copyPath, 0o4755); err != nil {
		return err
	}
	cmd := exec.Command(copyPath, "ids")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
