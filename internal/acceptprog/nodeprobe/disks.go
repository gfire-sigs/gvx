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
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// numStatFields is the number of counters on a line of /proc/diskstats after
// the device numbers and the name. Linux 5.5 and later print 17.
const numStatFields = 17

// Positions of the counters that the checks use, in the order of
// Documentation/admin-guide/iostats.rst.
const (
	fieldReads          = 0
	fieldSectorsRead    = 2
	fieldReadMillis     = 3
	fieldWrites         = 4
	fieldSectorsWritten = 6
	fieldWriteMillis    = 7
	fieldInFlight       = 8
	fieldIOMillis       = 9
	fieldWeightedMillis = 10
	fieldFlushes        = 15
)

// diskLine is one line of /proc/diskstats.
type diskLine struct {
	major, minor uint64
	name         string
	fields       [numStatFields]uint64
}

// virtioName is the name of a disk that the kernel gives to a virtio block
// device.
var virtioName = regexp.MustCompile(`^vd[a-z]+$`)

// readDiskstats parses /proc/diskstats and requires 20 columns on every line.
func readDiskstats() (map[string]diskLine, error) {
	data, err := os.ReadFile("/proc/diskstats")
	if err != nil {
		return nil, err
	}
	lines := make(map[string]diskLine)
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3+numStatFields {
			return nil, fmt.Errorf("diskstats line %q has %d columns, want %d", line, len(f), 3+numStatFields)
		}
		var d diskLine
		var err error
		if d.major, err = strconv.ParseUint(f[0], 10, 64); err != nil {
			return nil, err
		}
		if d.minor, err = strconv.ParseUint(f[1], 10, 64); err != nil {
			return nil, err
		}
		d.name = f[2]
		for i := range d.fields {
			if d.fields[i], err = strconv.ParseUint(f[3+i], 10, 64); err != nil {
				return nil, fmt.Errorf("diskstats line %q: %w", line, err)
			}
		}
		lines[d.name] = d
	}
	return lines, nil
}

// deviceOf returns the device numbers of the file system of path, as stat
// reports them.
func deviceOf(path string) (major, minor uint64, err error) {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return 0, 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return uint64(unix.Major(uint64(st.Dev))), uint64(unix.Minor(uint64(st.Dev))), nil
}

// diskOf returns the disk of the file system of path: the line of
// /proc/diskstats with the device numbers that stat reports for path.
func diskOf(path string) (diskLine, error) {
	major, minor, err := deviceOf(path)
	if err != nil {
		return diskLine{}, err
	}
	lines, err := readDiskstats()
	if err != nil {
		return diskLine{}, err
	}
	for _, d := range lines {
		if d.major == major && d.minor == minor {
			return d, nil
		}
	}
	return diskLine{}, fmt.Errorf("%s has the device %d:%d, and /proc/diskstats has no disk with it: %v", path, major, minor, lines)
}

// mountOf returns the major:minor and the source of the mount at mountpoint in
// /proc/self/mountinfo.
func mountOf(mountpoint string) (device, source string, err error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", "", err
	}
	for line := range strings.SplitSeq(strings.TrimSpace(string(data)), "\n") {
		f := strings.Fields(line)
		sep := -1
		for i, w := range f {
			if w == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) < sep+3 || f[4] != mountpoint {
			continue
		}
		device, source = f[2], f[sep+2]
	}
	if device == "" {
		return "", "", fmt.Errorf("/proc/self/mountinfo has no mount at %s:\n%s", mountpoint, data)
	}
	return device, source, nil
}

// sysDiskFile returns the text of /sys/block/<name>/<file> without the final newline.
func sysDiskFile(name, file string) (string, error) {
	data, err := os.ReadFile(filepath.Join("/sys/block", name, file))
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(string(data), "\n"), nil
}

// sysDiskStat returns the 17 counters of /sys/block/<name>/stat.
func sysDiskStat(name string) ([numStatFields]uint64, error) {
	var out [numStatFields]uint64
	text, err := sysDiskFile(name, "stat")
	if err != nil {
		return out, err
	}
	f := strings.Fields(text)
	if len(f) != numStatFields {
		return out, fmt.Errorf("/sys/block/%s/stat has %d fields, want %d: %q", name, len(f), numStatFields, text)
	}
	for i := range out {
		if out[i], err = strconv.ParseUint(f[i], 10, 64); err != nil {
			return out, err
		}
	}
	return out, nil
}

// partitionLine returns the blocks of the disk with the numbers in
// /proc/partitions.
func partitionLine(major, minor uint64, name string) (blocks uint64, err error) {
	data, err := os.ReadFile("/proc/partitions")
	if err != nil {
		return 0, err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) == 4 && f[0] == strconv.FormatUint(major, 10) && f[1] == strconv.FormatUint(minor, 10) && f[3] == name {
			return strconv.ParseUint(f[2], 10, 64)
		}
	}
	return 0, fmt.Errorf("/proc/partitions has no line for %s %d:%d:\n%s", name, major, minor, data)
}

// writeSynced writes mib MiB to path in 1 MiB chunks and flushes the file.
func writeSynced(path string, mib int) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	chunk := bytes.Repeat([]byte{'d'}, 1<<20)
	for range mib {
		if _, err := f.Write(chunk); err != nil {
			f.Close()
			return err
		}
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// socketAndPipeTraffic moves size bytes through an AF_UNIX socket pair, through
// a pipe, and through a TCP connection to addr. It reads from the TCP server at
// addr until the server closes the connection.
func socketAndPipeTraffic(size int, addr string) error {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	a, b := os.NewFile(uintptr(pair[0]), "socket-a"), os.NewFile(uintptr(pair[1]), "socket-b")
	defer a.Close()
	defer b.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		return err
	}
	defer pr.Close()
	defer pw.Close()

	for _, link := range []struct {
		name string
		w    io.WriteCloser
		r    io.Reader
	}{{"socketpair", a, b}, {"pipe", pw, pr}} {
		errc := make(chan error, 1)
		go func() {
			_, err := io.Copy(link.w, io.LimitReader(zeroReader{}, int64(size)))
			link.w.Close()
			errc <- err
		}()
		n, err := io.Copy(io.Discard, link.r)
		if err != nil {
			return fmt.Errorf("%s: %w", link.name, err)
		}
		if werr := <-errc; werr != nil && !isClosedPipe(werr) {
			return fmt.Errorf("%s: %w", link.name, werr)
		}
		if n != int64(size) {
			return fmt.Errorf("%s moved %d bytes, want %d", link.name, n, size)
		}
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := conn.Write([]byte("go\n")); err != nil {
		return err
	}
	if n, err := io.Copy(io.Discard, conn); err != nil || n == 0 {
		return fmt.Errorf("the server at %s sent %d bytes: %v", addr, n, err)
	}
	return nil
}

// zeroReader reads zero bytes without end.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func isClosedPipe(err error) bool {
	return err == syscall.EPIPE || err == io.ErrClosedPipe
}

// disksChecks checks that /proc/diskstats, /proc/partitions, /sys/block, and
// the device numbers of stat and mountinfo describe the same disks, and that
// the counters follow real block I/O: a file on the volume at dir moves them,
// and socket, pipe, and tmpfs traffic does not. The server at addr answers a
// line with some data.
func disksChecks(dir, addr string) []check {
	const writeMiB = 64
	const sectorsPerMiB = 1 << 20 / 512
	var before, after diskLine
	return []check{
		{"disk-numbers-agree-across-the-interfaces", func() error {
			if err := os.WriteFile(filepath.Join(dir, "probe"), []byte("x"), 0o644); err != nil {
				return err
			}
			d, err := diskOf(dir)
			if err != nil {
				return err
			}
			if !virtioName.MatchString(d.name) {
				return fmt.Errorf("the disk of %s is named %q, want a name such as vdb", dir, d.name)
			}
			number := fmt.Sprintf("%d:%d", d.major, d.minor)
			for _, p := range []string{
				filepath.Join("/sys/block", d.name, "dev"),
				filepath.Join("/sys/class/block", d.name, "dev"),
				filepath.Join("/sys/dev/block", number, "dev"),
			} {
				if got, err := os.ReadFile(p); err != nil || strings.TrimSpace(string(got)) != number {
					return fmt.Errorf("%s = %q, %v, want %s", p, got, err, number)
				}
			}
			if dev, err := deviceOfFile(filepath.Join(dir, "probe")); err != nil || dev != number {
				return fmt.Errorf("st_dev of a file on %s = %q, %v, want %s", dir, dev, err, number)
			}
			mountDev, source, err := mountOf(dir)
			if err != nil {
				return err
			}
			if mountDev != number || source != "/dev/"+d.name {
				return fmt.Errorf("mountinfo says %s %s for %s, want %s /dev/%s", mountDev, source, dir, number, d.name)
			}
			size, err := sysDiskFile(d.name, "size")
			if err != nil {
				return err
			}
			sectors, err := strconv.ParseUint(size, 10, 64)
			if err != nil || sectors == 0 {
				return fmt.Errorf("/sys/block/%s/size = %q, %v, want a positive number", d.name, size, err)
			}
			blocks, err := partitionLine(d.major, d.minor, d.name)
			if err != nil {
				return err
			}
			if blocks != sectors/2 {
				return fmt.Errorf("/proc/partitions shows %d blocks, /sys/block/%s/size shows %d sectors", blocks, d.name, sectors)
			}
			entries, err := os.ReadDir("/sys/block")
			if err != nil {
				return err
			}
			listed := false
			for _, e := range entries {
				listed = listed || e.Name() == d.name
			}
			if !listed {
				return fmt.Errorf("/sys/block lists %v, want %s", entries, d.name)
			}
			return nil
		}},
		{"root-disk-is-a-read-only-image", func() error {
			d, err := diskOf("/")
			if err != nil {
				return err
			}
			if d.name != "vda" {
				return fmt.Errorf("the disk of / is %s, want vda", d.name)
			}
			if got, err := sysDiskFile(d.name, "ro"); err != nil || got != "1" {
				return fmt.Errorf("/sys/block/%s/ro = %q, %v, want 1", d.name, got, err)
			}
			mountDev, _, err := mountOf("/")
			if err != nil {
				return err
			}
			if want := fmt.Sprintf("%d:%d", d.major, d.minor); mountDev != want {
				return fmt.Errorf("mountinfo shows %s for /, want %s", mountDev, want)
			}
			// The first read of the image moves the read counters. The image sits
			// behind the page cache of the host, so a second read of the same
			// pages moves them by almost nothing. The pages that the loader and
			// the runtime map in the meantime can add a few sectors.
			if _, err := os.ReadFile("/bin/app"); err != nil {
				return err
			}
			first, err := diskOf("/")
			if err != nil {
				return err
			}
			if first.fields[fieldSectorsRead] <= d.fields[fieldSectorsRead] {
				return fmt.Errorf("reading /bin/app left the sectors read of %s at %d", d.name, first.fields[fieldSectorsRead])
			}
			if _, err := os.ReadFile("/bin/app"); err != nil {
				return err
			}
			second, err := diskOf("/")
			if err != nil {
				return err
			}
			const rereadTolerance = 256
			if grew := second.fields[fieldSectorsRead] - first.fields[fieldSectorsRead]; grew > rereadTolerance {
				return fmt.Errorf("a second read of /bin/app moved the sectors read of %s by %d, want at most %d", d.name, grew, rereadTolerance)
			}
			// A write to the root, which is memory above the image, moves no
			// counter of the disk.
			if err := os.WriteFile("/tmp/rootwrite", bytes.Repeat([]byte{'t'}, 8<<20), 0o644); err != nil {
				return err
			}
			os.Remove("/tmp/rootwrite")
			rootAfter, err := diskOf("/")
			if err != nil {
				return err
			}
			if got := rootAfter.fields[fieldSectorsWritten]; got != 0 {
				return fmt.Errorf("writes to the root file system moved the sectors written of %s to %d, want 0", d.name, got)
			}
			return nil
		}},
		{"write-sectors-grow-with-fsync", func() error {
			var err error
			if before, err = diskOf(dir); err != nil {
				return err
			}
			if err := writeSynced(filepath.Join(dir, "big"), writeMiB); err != nil {
				return err
			}
			if after, err = diskOf(dir); err != nil {
				return err
			}
			grew := after.fields[fieldSectorsWritten] - before.fields[fieldSectorsWritten]
			if want := uint64(writeMiB * sectorsPerMiB); grew < want {
				return fmt.Errorf("sectors written of %s grew by %d after %d MiB with fsync, want at least %d", after.name, grew, writeMiB, want)
			}
			if after.fields[fieldWrites] <= before.fields[fieldWrites] {
				return fmt.Errorf("writes completed stayed at %d", after.fields[fieldWrites])
			}
			if after.fields[fieldFlushes] <= before.fields[fieldFlushes] {
				return fmt.Errorf("flushes completed stayed at %d after fsync", after.fields[fieldFlushes])
			}
			if after.fields[fieldWriteMillis] == 0 || after.fields[fieldIOMillis] == 0 {
				return fmt.Errorf("a %d MiB write took %d ms of write time and %d ms of I/O time, want both above 0", writeMiB, after.fields[fieldWriteMillis], after.fields[fieldIOMillis])
			}
			if after.fields[fieldWeightedMillis] < after.fields[fieldIOMillis] {
				return fmt.Errorf("weighted time %d ms is below the I/O time %d ms", after.fields[fieldWeightedMillis], after.fields[fieldIOMillis])
			}
			sys, err := sysDiskStat(after.name)
			if err != nil {
				return err
			}
			if sys[fieldSectorsWritten] < after.fields[fieldSectorsWritten] {
				return fmt.Errorf("/sys/block/%s/stat shows %d sectors written, /proc/diskstats showed %d earlier", after.name, sys[fieldSectorsWritten], after.fields[fieldSectorsWritten])
			}
			return nil
		}},
		{"read-sectors-grow-with-file-reads", func() error {
			start, err := diskOf(dir)
			if err != nil {
				return err
			}
			f, err := os.Open(filepath.Join(dir, "big"))
			if err != nil {
				return err
			}
			defer f.Close()
			n, err := io.Copy(io.Discard, f)
			if err != nil {
				return err
			}
			if n != writeMiB<<20 {
				return fmt.Errorf("read %d bytes, want %d", n, writeMiB<<20)
			}
			end, err := diskOf(dir)
			if err != nil {
				return err
			}
			if grew, want := end.fields[fieldSectorsRead]-start.fields[fieldSectorsRead], uint64(writeMiB*sectorsPerMiB); grew < want {
				return fmt.Errorf("sectors read of %s grew by %d after a read of %d MiB, want at least %d", end.name, grew, writeMiB, want)
			}
			if end.fields[fieldReads] <= start.fields[fieldReads] || end.fields[fieldReadMillis] < start.fields[fieldReadMillis] {
				return fmt.Errorf("reads completed %d to %d, read time %d to %d ms", start.fields[fieldReads], end.fields[fieldReads], start.fields[fieldReadMillis], end.fields[fieldReadMillis])
			}
			return nil
		}},
		{"no-request-stays-in-flight", func() error {
			// The flusher of the volume can have a request open at any moment, so
			// the count has to reach 0 and not be 0 at a given time.
			var d diskLine
			var err error
			for range 50 {
				if d, err = diskOf(dir); err != nil {
					return err
				}
				if d.fields[fieldInFlight] == 0 {
					return nil
				}
				time.Sleep(100 * time.Millisecond)
			}
			return fmt.Errorf("%d requests of %s stayed in flight for 5 seconds", d.fields[fieldInFlight], d.name)
		}},
		{"socket-and-pipe-traffic-does-not-count", func() error {
			const traffic = 32 << 20
			start, err := readDiskstats()
			if err != nil {
				return err
			}
			if err := socketAndPipeTraffic(traffic, addr); err != nil {
				return err
			}
			end, err := readDiskstats()
			if err != nil {
				return err
			}
			// The traffic is 64 MiB or more, which is 131072 sectors. A few
			// sectors of metadata from the flusher of the volume can show up.
			const tolerance = 4096
			for name, s := range start {
				e, ok := end[name]
				if !ok {
					return fmt.Errorf("the disk %s vanished", name)
				}
				for _, i := range []int{fieldSectorsRead, fieldSectorsWritten} {
					if e.fields[i] < s.fields[i] || e.fields[i]-s.fields[i] > tolerance {
						return fmt.Errorf("%s field %d went from %d to %d during socket and pipe traffic, want a change of at most %d", name, i+1, s.fields[i], e.fields[i], tolerance)
					}
				}
			}
			return nil
		}},
	}
}

// deviceOfFile returns the device of path as "major:minor".
func deviceOfFile(path string) (string, error) {
	major, minor, err := deviceOf(path)
	return fmt.Sprintf("%d:%d", major, minor), err
}
