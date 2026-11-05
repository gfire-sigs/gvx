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

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The checks of /dev/kmsg and syslog(2) follow Documentation/ABI/testing/dev-kmsg
// and kernel/printk/printk.c of Linux. The guest has no other writer than the
// probe, so a check finds its own records by their text.

// The commands of syslog(2).
const (
	syslogRead       = 2
	syslogReadAll    = 3
	syslogReadClear  = 4
	syslogClear      = 5
	syslogConsoleOff = 6
	syslogConsoleOn  = 7
	syslogConsoleLvl = 8
	syslogSizeUnread = 9
	syslogSizeBuffer = 10
)

const (
	kmsgPath          = "/dev/kmsg"
	devkmsgSysctl     = "/proc/sys/kernel/printk_devkmsg"
	dmesgRestrictFile = "/proc/sys/kernel/dmesg_restrict"
	printkSysctl      = "/proc/sys/kernel/printk"
)

// kmsgRecord is one record that a read of /dev/kmsg returned.
type kmsgRecord struct {
	prio int
	seq  uint64
	usec uint64
	text string
}

var kmsgLine = regexp.MustCompile(`^(\d+),(\d+),(\d+),([-cf]);(.*)\n$`)

func parseKmsgRecord(line string) (kmsgRecord, error) {
	m := kmsgLine.FindStringSubmatch(line)
	if m == nil {
		return kmsgRecord{}, fmt.Errorf("read %q, want prio,seq,usec,flag;text", line)
	}
	prio, _ := strconv.Atoi(m[1])
	seq, _ := strconv.ParseUint(m[2], 10, 64)
	usec, _ := strconv.ParseUint(m[3], 10, 64)
	return kmsgRecord{prio: prio, seq: seq, usec: usec, text: m[5]}, nil
}

// readKmsgRecord reads one record from fd.
func readKmsgRecord(fd int) (kmsgRecord, error) {
	buf := make([]byte, 8192)
	n, err := unix.Read(fd, buf)
	if err != nil {
		return kmsgRecord{}, err
	}
	return parseKmsgRecord(string(buf[:n]))
}

// drainKmsg reads fd, which must not block, until EAGAIN and returns the
// records.
func drainKmsg(fd int) ([]kmsgRecord, error) {
	var out []kmsgRecord
	for {
		rec, err := readKmsgRecord(fd)
		if errors.Is(err, syscall.EAGAIN) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, rec)
	}
}

// withReader opens /dev/kmsg for reading without blocking, moves it after the
// last record, and runs fn.
func withReader(fn func(fd int) error) error {
	fd, err := unix.Open(kmsgPath, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, err := unix.Seek(fd, 0, unix.SEEK_END); err != nil {
		return err
	}
	return fn(fd)
}

// writeKmsg writes text to /dev/kmsg through a new descriptor. Each descriptor
// has its own rate limit.
func writeKmsg(text string) error {
	fd, err := unix.Open(kmsgPath, unix.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	n, err := unix.Write(fd, []byte(text))
	if err != nil {
		return err
	}
	if n != len(text) {
		return fmt.Errorf("write of %d bytes returned %d", len(text), n)
	}
	return nil
}

// withDevkmsgMode sets kernel.printk_devkmsg for the call of fn and restores the
// default afterwards.
func withDevkmsgMode(mode string, fn func() error) error {
	if err := writeValue(devkmsgSysctl, mode); err != nil {
		return err
	}
	defer writeValue(devkmsgSysctl, "ratelimit")
	return fn()
}

// klogctl calls syslog(2) with a buffer of size bytes and returns what it
// filled.
func klogctl(cmd, size int) ([]byte, error) {
	buf := make([]byte, size)
	n, err := unix.Klogctl(cmd, buf)
	if err != nil {
		return nil, err
	}
	return buf[:min(n, len(buf))], nil
}

func kmsgChecks() []check {
	return append(kmsgBootChecks(), append(kmsgInterfaceChecks(), append(kmsgSemanticsChecks(), syslogChecks()...)...)...)
}

// kmsgBootChecks run first, before a check overwrites the ring.
func kmsgBootChecks() []check {
	return []check{
		{"kmsg-boot-messages-are-in-the-ring", func() error {
			text, err := klogctl(syslogReadAll, 1<<20)
			if err != nil {
				return err
			}
			if !strings.Contains(string(text), "Starting gVisor...") || !strings.Contains(string(text), "Ready!") {
				return fmt.Errorf("the log lacks the boot messages:\n%.300s", text)
			}
			return nil
		}},
		{"kmsg-first-record-has-sequence-0", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			rec, err := readKmsgRecord(fd)
			if err != nil {
				return err
			}
			if rec.seq != 0 || rec.text != "Starting gVisor..." || rec.prio != 6 {
				return fmt.Errorf("first record = %+v, want sequence 0, priority 6, text Starting gVisor...", rec)
			}
			return nil
		}},
	}
}

func kmsgInterfaceChecks() []check {
	return []check{
		{"kmsg-is-char-device-1-11", func() error {
			var st unix.Stat_t
			if err := unix.Stat(kmsgPath, &st); err != nil {
				return err
			}
			if st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != 1 || unix.Minor(uint64(st.Rdev)) != 11 {
				return fmt.Errorf("mode %#o rdev %d:%d, want a character device 1:11", st.Mode, unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev)))
			}
			return nil
		}},
		{"kmsg-open-read-write", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDWR, 0)
			if err != nil {
				return err
			}
			return unix.Close(fd)
		}},
		{"kmsg-seek-end-returns-0", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			off, err := unix.Seek(fd, 0, unix.SEEK_END)
			if err != nil || off != 0 {
				return fmt.Errorf("lseek(SEEK_END) = %d, %v, want 0", off, err)
			}
			return nil
		}},
		{"kmsg-seek-set-and-data-return-0", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			for name, whence := range map[string]int{"SEEK_SET": unix.SEEK_SET, "SEEK_DATA": unix.SEEK_DATA} {
				if off, err := unix.Seek(fd, 0, whence); err != nil || off != 0 {
					return fmt.Errorf("lseek(%s) = %d, %v, want 0", name, off, err)
				}
			}
			return nil
		}},
		{"kmsg-seek-with-offset-fails-with-espipe", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			for _, whence := range []int{unix.SEEK_SET, unix.SEEK_DATA, unix.SEEK_END} {
				if off, err := unix.Seek(fd, 1, whence); !errors.Is(err, syscall.ESPIPE) {
					return fmt.Errorf("lseek(1, whence %d) = %d, %v, want ESPIPE", whence, off, err)
				}
			}
			return nil
		}},
		{"kmsg-seek-with-invalid-whence-fails-with-einval", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			for _, whence := range []int{unix.SEEK_CUR, unix.SEEK_HOLE, 99} {
				if off, err := unix.Seek(fd, 0, whence); !errors.Is(err, syscall.EINVAL) {
					return fmt.Errorf("lseek(0, whence %d) = %d, %v, want EINVAL", whence, off, err)
				}
			}
			return nil
		}},
		{"kmsg-nonblocking-read-returns-eagain", func() error {
			return withReader(func(fd int) error {
				buf := make([]byte, 8192)
				n, err := unix.Read(fd, buf)
				return wantErrno(fmt.Sprintf("read at the end = %d", n), err, syscall.EAGAIN)
			})
		}},
		{"kmsg-write-returns-length", func() error {
			return writeKmsg("<6>x")
		}},
		{"kmsg-write-of-more-than-1024-bytes-fails-with-einval", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_WRONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			_, err = unix.Write(fd, make([]byte, 1025))
			return wantErrno("write of 1025 bytes", err, syscall.EINVAL)
		}},
		{"kmsg-pread-fails-with-espipe", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			_, err = unix.Pread(fd, make([]byte, 8192), 0)
			return wantErrno("pread", err, syscall.ESPIPE)
		}},
	}
}

func kmsgSemanticsChecks() []check {
	return []check{
		{"kmsg-write-splits-lines-into-records-with-the-prefix", func() error {
			return withReader(func(fd int) error {
				if err := writeKmsg("<30>probe-one\nprobe-two\n"); err != nil {
					return err
				}
				a, err := readKmsgRecord(fd)
				if err != nil {
					return err
				}
				b, err := readKmsgRecord(fd)
				if err != nil {
					return err
				}
				if a.text != "probe-one" || b.text != "probe-two" || a.prio != 30 || b.prio != 30 {
					return fmt.Errorf("records = %+v, %+v, want probe-one and probe-two with priority 30", a, b)
				}
				if b.seq != a.seq+1 || b.usec < a.usec || a.usec == 0 {
					return fmt.Errorf("sequence %d, %d and time %d, %d are not consecutive", a.seq, b.seq, a.usec, b.usec)
				}
				if _, err := readKmsgRecord(fd); !errors.Is(err, syscall.EAGAIN) {
					return fmt.Errorf("a third read gave %v, want EAGAIN", err)
				}
				return nil
			})
		}},
		{"kmsg-write-without-prefix-has-user-facility-and-level-4", func() error {
			return withReader(func(fd int) error {
				if err := writeKmsg("probe-plain"); err != nil {
					return err
				}
				rec, err := readKmsgRecord(fd)
				if err != nil {
					return err
				}
				if rec.text != "probe-plain" || rec.prio != 1<<3|4 {
					return fmt.Errorf("record = %+v, want priority 12", rec)
				}
				return nil
			})
		}},
		{"kmsg-read-into-a-small-buffer-fails-with-einval", func() error {
			return withReader(func(fd int) error {
				if err := writeKmsg("probe-small-buffer"); err != nil {
					return err
				}
				if _, err := unix.Read(fd, make([]byte, 8)); !errors.Is(err, syscall.EINVAL) {
					return fmt.Errorf("read into 8 bytes: %v, want EINVAL", err)
				}
				rec, err := readKmsgRecord(fd)
				if err != nil || rec.text != "probe-small-buffer" {
					return fmt.Errorf("the read after EINVAL = %+v, %v, want the same record", rec, err)
				}
				return nil
			})
		}},
		{"kmsg-each-open-file-has-its-own-position", func() error {
			return withReader(func(a int) error {
				return withReader(func(b int) error {
					if err := writeKmsg("probe-two-readers"); err != nil {
						return err
					}
					for _, fd := range []int{a, b} {
						rec, err := readKmsgRecord(fd)
						if err != nil || rec.text != "probe-two-readers" {
							return fmt.Errorf("reader %d read %+v, %v", fd, rec, err)
						}
					}
					return nil
				})
			})
		}},
		{"kmsg-blocking-read-waits-for-a-record", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			if _, err := unix.Seek(fd, 0, unix.SEEK_END); err != nil {
				return err
			}
			const delay = 300 * time.Millisecond
			go func() {
				time.Sleep(delay)
				writeKmsg("probe-wakeup")
			}()
			start := time.Now()
			rec, err := readKmsgRecord(fd)
			if err != nil {
				return err
			}
			if rec.text != "probe-wakeup" || time.Since(start) < delay/2 {
				return fmt.Errorf("read %+v after %v, want probe-wakeup after about %v", rec, time.Since(start), delay)
			}
			return nil
		}},
		{"kmsg-poll-reports-a-record-and-is-never-writable", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDWR|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			if _, err := unix.Seek(fd, 0, unix.SEEK_END); err != nil {
				return err
			}
			fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLOUT}}
			n, err := unix.Poll(fds, 50)
			if err != nil || n != 0 {
				return fmt.Errorf("poll at the end = %d events %#x, %v, want none", n, fds[0].Revents, err)
			}
			if err := writeKmsg("probe-poll"); err != nil {
				return err
			}
			n, err = unix.Poll(fds, 1000)
			if err != nil || n != 1 || fds[0].Revents&unix.POLLIN == 0 || fds[0].Revents&(unix.POLLOUT|unix.POLLERR) != 0 {
				return fmt.Errorf("poll with a record = %d events %#x, %v, want POLLIN only", n, fds[0].Revents, err)
			}
			return nil
		}},
		{"kmsg-ratelimit-allows-ten-writes-for-each-open-file", func() error {
			return withReader(func(fd int) error {
				w, err := unix.Open(kmsgPath, unix.O_WRONLY, 0)
				if err != nil {
					return err
				}
				defer unix.Close(w)
				for i := 0; i < 15; i++ {
					if n, err := unix.Write(w, []byte(fmt.Sprintf("probe-rl-%d", i))); err != nil || n != len(fmt.Sprintf("probe-rl-%d", i)) {
						return fmt.Errorf("write %d = %d, %v: a dropped write must still succeed", i, n, err)
					}
				}
				if err := writeKmsg("probe-rl-other"); err != nil {
					return err
				}
				recs, err := drainKmsg(fd)
				if err != nil {
					return err
				}
				count := 0
				for _, r := range recs {
					if strings.HasPrefix(r.text, "probe-rl-") {
						count++
					}
				}
				if count != 11 {
					return fmt.Errorf("%d records, want 10 from the first file and 1 from the second", count)
				}
				return nil
			})
		}},
		{"kmsg-printk-devkmsg-off-drops-writes-and-on-keeps-all", func() error {
			if err := withDevkmsgMode("off", func() error {
				return withReader(func(fd int) error {
					if err := writeKmsg("probe-off"); err != nil {
						return err
					}
					recs, err := drainKmsg(fd)
					if err != nil || len(recs) != 0 {
						return fmt.Errorf("mode off: records %+v, %v, want none", recs, err)
					}
					return nil
				})
			}); err != nil {
				return err
			}
			return withDevkmsgMode("on", func() error {
				return withReader(func(fd int) error {
					w, err := unix.Open(kmsgPath, unix.O_WRONLY, 0)
					if err != nil {
						return err
					}
					defer unix.Close(w)
					for i := 0; i < 30; i++ {
						if _, err := unix.Write(w, []byte("probe-on")); err != nil {
							return err
						}
					}
					recs, err := drainKmsg(fd)
					if err != nil || len(recs) != 30 {
						return fmt.Errorf("mode on: %d records, %v, want 30", len(recs), err)
					}
					return nil
				})
			})
		}},
		{"kmsg-sysctls-show-and-set-the-values", func() error {
			for path, want := range map[string]string{devkmsgSysctl: "ratelimit", dmesgRestrictFile: "0", printkSysctl: "7 4 1 7"} {
				if err := expectValue(path, want); err != nil {
					return err
				}
			}
			for _, mode := range []string{"on", "off", "ratelimit"} {
				if err := writeValue(devkmsgSysctl, mode+"\n"); err != nil {
					return fmt.Errorf("write %s: %w", mode, err)
				}
				if err := expectValue(devkmsgSysctl, mode); err != nil {
					return err
				}
			}
			if err := wantErrno("write bogus mode", writeValue(devkmsgSysctl, "bogus"), syscall.EINVAL); err != nil {
				return err
			}
			if err := wantErrno("write dmesg_restrict 2", writeValue(dmesgRestrictFile, "2"), syscall.EINVAL); err != nil {
				return err
			}
			if err := writeValue(printkSysctl, "5 3 1 7"); err != nil {
				return err
			}
			if err := expectValue(printkSysctl, "5 3 1 7"); err != nil {
				return err
			}
			return writeValue(printkSysctl, "7 4 1 7")
		}},
		{"kmsg-overwrite-returns-epipe-once-then-continues", func() error {
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			return withDevkmsgMode("on", func() error {
				w, err := unix.Open(kmsgPath, unix.O_WRONLY, 0)
				if err != nil {
					return err
				}
				defer unix.Close(w)
				// The ring has one descriptor for each 32 bytes of its size, so
				// 5000 short records overwrite the 4096 records of the default ring.
				for i := 0; i < 5000; i++ {
					if _, err := unix.Write(w, []byte("probe-fill")); err != nil {
						return err
					}
				}
				fds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN | unix.POLLPRI}}
				if n, err := unix.Poll(fds, 1000); err != nil || n != 1 || fds[0].Revents&(unix.POLLERR|unix.POLLPRI) != unix.POLLERR|unix.POLLPRI {
					return fmt.Errorf("poll after the overwrite = %d events %#x, %v, want POLLERR and POLLPRI", n, fds[0].Revents, err)
				}
				buf := make([]byte, 8192)
				if n, err := unix.Read(fd, buf); !errors.Is(err, syscall.EPIPE) {
					return fmt.Errorf("first read after the overwrite = %d, %v, want EPIPE", n, err)
				}
				rec, err := readKmsgRecord(fd)
				if err != nil {
					return fmt.Errorf("second read after the overwrite: %w", err)
				}
				if rec.seq == 0 {
					return fmt.Errorf("the read after EPIPE returned sequence 0, want the oldest record that remains")
				}
				return nil
			})
		}},
		{"kmsg-seek-data-follows-syslog-clear", func() error {
			if err := writeKmsg("probe-before-clear"); err != nil {
				return err
			}
			if _, err := klogctl(syslogClear, 0); err != nil {
				return err
			}
			if err := writeKmsg("probe-after-clear"); err != nil {
				return err
			}
			fd, err := unix.Open(kmsgPath, unix.O_RDONLY|unix.O_NONBLOCK, 0)
			if err != nil {
				return err
			}
			defer unix.Close(fd)
			if _, err := unix.Seek(fd, 0, unix.SEEK_DATA); err != nil {
				return err
			}
			rec, err := readKmsgRecord(fd)
			if err != nil || rec.text != "probe-after-clear" {
				return fmt.Errorf("first record after SEEK_DATA = %+v, %v, want probe-after-clear", rec, err)
			}
			return nil
		}},
		{"kmsg-dmesg-restrict-needs-cap-syslog-to-read", kmsgRestrictCheck},
	}
}

// kmsgUnprivileged is the child of kmsgRestrictCheck. It runs as an ordinary
// user and prints what each call returned.
func kmsgUnprivileged() {
	result := func(err error) string {
		switch {
		case err == nil:
			return "ok"
		case errors.Is(err, syscall.EPERM):
			return "EPERM"
		case errors.Is(err, syscall.EACCES):
			return "EACCES"
		default:
			return err.Error()
		}
	}
	var parts []string
	fd, err := unix.Open(kmsgPath, unix.O_RDONLY, 0)
	if err == nil {
		unix.Close(fd)
	}
	parts = append(parts, "open-ro="+result(err))
	fd, err = unix.Open(kmsgPath, unix.O_WRONLY, 0)
	if err == nil {
		unix.Close(fd)
	}
	parts = append(parts, "open-wo="+result(err))
	_, err = klogctl(syslogSizeBuffer, 0)
	parts = append(parts, "size-buffer="+result(err))
	_, err = klogctl(syslogReadAll, 4096)
	parts = append(parts, "read-all="+result(err))
	_, err = klogctl(syslogClear, 0)
	parts = append(parts, "clear="+result(err))
	fmt.Println(strings.Join(parts, " "))
}

// kmsgRestrictCheck runs kmsgUnprivileged as user 1000 with kernel.dmesg_restrict
// at 0 and at 1. The device has the mode 0644, as in Linux, so the file mode
// alone stops a write by an ordinary user, and a read needs no capability while
// the sysctl is 0.
func kmsgRestrictCheck() error {
	run := func() (string, error) {
		cmd := exec.Command("/proc/self/exe", "kmsg-unpriv")
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 1000, Gid: 1000}}
		out, err := cmd.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	defer writeValue(dmesgRestrictFile, "0")
	for _, tc := range []struct{ restrict, want string }{
		{"0", "open-ro=ok open-wo=EACCES size-buffer=ok read-all=ok clear=EPERM"},
		{"1", "open-ro=EPERM open-wo=EACCES size-buffer=EPERM read-all=EPERM clear=EPERM"},
	} {
		if err := writeValue(dmesgRestrictFile, tc.restrict); err != nil {
			return err
		}
		if err := expectValue(dmesgRestrictFile, tc.restrict); err != nil {
			return err
		}
		got, err := run()
		if err != nil {
			return fmt.Errorf("dmesg_restrict=%s: %w: %s", tc.restrict, err, got)
		}
		if got != tc.want {
			return fmt.Errorf("dmesg_restrict=%s: an ordinary user got %q, want %q", tc.restrict, got, tc.want)
		}
	}
	return nil
}

func syslogChecks() []check {
	textForm := regexp.MustCompile(`(?m)^<(\d+)>\[ *(\d+)\.(\d{6})\] (.*)$`)
	return []check{
		{"syslog-size-buffer-is-the-ring-size", func() error {
			n, err := unix.Klogctl(syslogSizeBuffer, nil)
			if err != nil || n != 1<<17 {
				return fmt.Errorf("SIZE_BUFFER = %d, %v, want 131072", n, err)
			}
			return nil
		}},
		{"syslog-read-all-returns-the-text-form", func() error {
			if err := writeKmsg("<30>probe-text-form"); err != nil {
				return err
			}
			text, err := klogctl(syslogReadAll, 1<<20)
			if err != nil {
				return err
			}
			for _, m := range textForm.FindAllStringSubmatch(string(text), -1) {
				if m[4] == "probe-text-form" {
					if m[1] != "30" {
						return fmt.Errorf("the record has priority %s, want 30", m[1])
					}
					return nil
				}
			}
			return fmt.Errorf("READ_ALL has no record in the form <prio>[ sec.usec] text:\n%.300s", text[max(0, len(text)-300):])
		}},
		{"syslog-read-all-returns-only-whole-records-that-fit", func() error {
			all, err := klogctl(syslogReadAll, 1<<20)
			if err != nil {
				return err
			}
			part, err := klogctl(syslogReadAll, 200)
			if err != nil {
				return err
			}
			if len(part) == 0 || len(part) > 200 || !strings.HasSuffix(string(part), "\n") || !strings.HasSuffix(string(all), string(part)) {
				return fmt.Errorf("READ_ALL(200) = %q, want the last whole records of the log", part)
			}
			return nil
		}},
		{"syslog-read-all-with-a-null-buffer-fails-with-einval", func() error {
			_, _, errno := unix.Syscall(unix.SYS_SYSLOG, syslogReadAll, 0, 16)
			return wantErrno("READ_ALL with a null buffer", errnoOrNil(errno), syscall.EINVAL)
		}},
		{"syslog-unknown-command-fails-with-einval", func() error {
			_, err := unix.Klogctl(11, nil)
			return wantErrno("command 11", err, syscall.EINVAL)
		}},
		{"syslog-read-clear-returns-the-log-and-clears-it", func() error {
			if err := writeKmsg("probe-read-clear"); err != nil {
				return err
			}
			text, err := klogctl(syslogReadClear, 1<<20)
			if err != nil {
				return err
			}
			if !strings.Contains(string(text), "probe-read-clear") {
				return fmt.Errorf("READ_CLEAR did not return the record")
			}
			after, err := klogctl(syslogReadAll, 1<<20)
			if err != nil || len(after) != 0 {
				return fmt.Errorf("READ_ALL after READ_CLEAR = %q, %v, want nothing", after, err)
			}
			return nil
		}},
		{"syslog-clear-hides-the-records-from-read-all", func() error {
			if err := writeKmsg("probe-hidden"); err != nil {
				return err
			}
			if _, err := klogctl(syslogClear, 0); err != nil {
				return err
			}
			after, err := klogctl(syslogReadAll, 1<<20)
			if err != nil || len(after) != 0 {
				return fmt.Errorf("READ_ALL after CLEAR = %q, %v, want nothing", after, err)
			}
			if err := writeKmsg("probe-visible"); err != nil {
				return err
			}
			after, err = klogctl(syslogReadAll, 1<<20)
			if err != nil || !strings.Contains(string(after), "probe-visible") || strings.Contains(string(after), "probe-hidden") {
				return fmt.Errorf("READ_ALL = %q, %v, want only probe-visible", after, err)
			}
			return nil
		}},
		{"syslog-read-consumes-and-size-unread-counts", func() error {
			n, err := unix.Klogctl(syslogSizeUnread, nil)
			if err != nil {
				return err
			}
			// Consume what is unread, without blocking on the last call.
			for n > 0 {
				text, err := klogctl(syslogRead, n)
				if err != nil {
					return err
				}
				n -= len(text)
			}
			if left, err := unix.Klogctl(syslogSizeUnread, nil); err != nil || left != 0 {
				return fmt.Errorf("SIZE_UNREAD after the read = %d, %v, want 0", left, err)
			}
			if err := writeKmsg("probe-unread"); err != nil {
				return err
			}
			unread, err := unix.Klogctl(syslogSizeUnread, nil)
			if err != nil || unread == 0 {
				return fmt.Errorf("SIZE_UNREAD after a write = %d, %v, want more than 0", unread, err)
			}
			text, err := klogctl(syslogRead, 1<<16)
			if err != nil || len(text) != unread || !strings.Contains(string(text), "probe-unread") {
				return fmt.Errorf("READ = %q, %v, want %d bytes with probe-unread", text, err, unread)
			}
			return nil
		}},
		{"syslog-read-blocks-until-a-record-arrives", func() error {
			const delay = 300 * time.Millisecond
			go func() {
				time.Sleep(delay)
				writeKmsg("probe-syslog-wakeup")
			}()
			start := time.Now()
			text, err := klogctl(syslogRead, 4096)
			if err != nil || !strings.Contains(string(text), "probe-syslog-wakeup") || time.Since(start) < delay/2 {
				return fmt.Errorf("READ = %q, %v after %v, want probe-syslog-wakeup after about %v", text, err, time.Since(start), delay)
			}
			return nil
		}},
		{"syslog-console-commands-set-console-loglevel", func() error {
			level := func() (string, error) {
				v, err := readValue(printkSysctl)
				if err != nil {
					return "", err
				}
				return strings.Fields(v)[0], nil
			}
			setLevel := func(n int) error {
				_, _, errno := unix.Syscall(unix.SYS_SYSLOG, syslogConsoleLvl, 0, uintptr(n))
				return errnoOrNil(errno)
			}
			for _, n := range []int{0, 9} {
				if err := wantErrno(fmt.Sprintf("CONSOLE_LEVEL %d", n), setLevel(n), syscall.EINVAL); err != nil {
					return err
				}
			}
			for _, tc := range []struct {
				name string
				do   func() error
				want string
			}{
				{"CONSOLE_LEVEL 3", func() error { return setLevel(3) }, "3"},
				{"CONSOLE_OFF", func() error { _, err := unix.Klogctl(syslogConsoleOff, nil); return err }, "1"},
				{"CONSOLE_ON", func() error { _, err := unix.Klogctl(syslogConsoleOn, nil); return err }, "7"},
				{"CONSOLE_LEVEL 8", func() error { return setLevel(8) }, "8"},
			} {
				if err := tc.do(); err != nil {
					return fmt.Errorf("%s: %w", tc.name, err)
				}
				if got, err := level(); err != nil || got != tc.want {
					return fmt.Errorf("after %s the console loglevel is %q, %v, want %s", tc.name, got, err, tc.want)
				}
			}
			return writeValue(printkSysctl, "7 4 1 7")
		}},
	}
}

func errnoOrNil(errno syscall.Errno) error {
	if errno == 0 {
		return nil
	}
	return errno
}

// kmsgSizeChecks checks the ring size that a sandbox with kernel.log_buf_len
// reports.
func kmsgSizeChecks(want int) []check {
	return []check{
		{"syslog-size-buffer-follows-the-tunable", func() error {
			n, err := unix.Klogctl(syslogSizeBuffer, nil)
			if err != nil || n != want {
				return fmt.Errorf("SIZE_BUFFER = %d, %v, want %d", n, err, want)
			}
			return nil
		}},
	}
}
