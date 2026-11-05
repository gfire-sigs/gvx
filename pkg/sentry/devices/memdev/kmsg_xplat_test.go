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

package memdev

import (
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// newKmsgFD returns a descriptor on a new log, positioned at the oldest record.
func newKmsgFD(bufLen int) (*kmsgFD, *kernel.KernelLog) {
	l := kernel.NewKernelLog(bufLen, func() time.Duration { return 7 * time.Second })
	return &kmsgFD{log: l, seq: l.FirstSeq()}, l
}

func (fd *kmsgFD) readInto(size int) (string, error) {
	buf := make([]byte, size)
	n, err := fd.Read(context.Background(), usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	return string(buf[:n]), err
}

func (fd *kmsgFD) writeString(s string) (int64, error) {
	return fd.Write(context.Background(), usermem.BytesIOSequence([]byte(s)), vfs.WriteOptions{})
}

func TestKmsgReadReturnsOneRecordInTheDocumentedFormat(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	l.Printk(kernel.LogInfo, "first")
	l.Printk(kernel.LogErr, "sec\tond")
	for i, want := range []string{"6,0,7000000,-;first\n", "3,1,7000000,-;sec\\x09ond\n"} {
		got, err := fd.readInto(8192)
		if err != nil || got != want {
			t.Errorf("read %d = %q, %v, want %q", i, got, err, want)
		}
	}
	if got, err := fd.readInto(8192); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) || got != "" {
		t.Errorf("read at the end = %q, %v, want ErrWouldBlock", got, err)
	}
}

func TestKmsgReadWithASmallBufferFailsAndKeepsThePosition(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	l.Printk(kernel.LogInfo, "0123456789")
	line := "6,0,7000000,-;0123456789\n"
	if _, err := fd.readInto(len(line) - 1); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("read into a small buffer: err = %v, want EINVAL", err)
	}
	if got, err := fd.readInto(len(line)); err != nil || got != line {
		t.Errorf("read after EINVAL = %q, %v, want %q", got, err, line)
	}
}

func TestKmsgReadReportsEPIPEOnceWhenTheRecordWasOverwritten(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogMinBufLen)
	l.Printk(kernel.LogInfo, "kept until the ring wraps")
	text := strings.Repeat("x", 1000)
	for i := 0; i < 10; i++ {
		l.Printk(kernel.LogInfo, text)
	}
	if _, err := fd.readInto(8192); !linuxerr.Equals(linuxerr.EPIPE, err) {
		t.Fatalf("first read after the overwrite: err = %v, want EPIPE", err)
	}
	got, err := fd.readInto(8192)
	if err != nil || !strings.HasPrefix(got, "6,7,") {
		t.Errorf("second read = %.20q, %v, want the oldest record, sequence 7", got, err)
	}
}

func TestKmsgEachDescriptorHasItsOwnPosition(t *testing.T) {
	a, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	b := &kmsgFD{log: l, seq: l.FirstSeq()}
	l.Printk(kernel.LogInfo, "one")
	l.Printk(kernel.LogInfo, "two")
	if _, err := a.readInto(8192); err != nil {
		t.Fatal(err)
	}
	if got, _ := b.readInto(8192); !strings.HasSuffix(got, ";one\n") {
		t.Errorf("second descriptor read %q, want the first record", got)
	}
	if got, _ := a.readInto(8192); !strings.HasSuffix(got, ";two\n") {
		t.Errorf("first descriptor read %q, want the second record", got)
	}
}

func TestKmsgSeek(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	l.Printk(kernel.LogInfo, "a")
	l.Printk(kernel.LogInfo, "b")
	l.Clear()
	l.Printk(kernel.LogInfo, "c")

	seek := func(whence int32) {
		t.Helper()
		if off, err := fd.Seek(context.Background(), 0, whence); err != nil || off != 0 {
			t.Fatalf("Seek(0, %d) = %d, %v, want 0", whence, off, err)
		}
	}
	next := func() string {
		got, err := fd.readInto(8192)
		if err != nil {
			return err.Error()
		}
		return got[strings.Index(got, ";")+1 : len(got)-1]
	}
	seek(linux.SEEK_SET)
	if got := next(); got != "a" {
		t.Errorf("after SEEK_SET the read gives %q, want a", got)
	}
	seek(linux.SEEK_DATA)
	if got := next(); got != "c" {
		t.Errorf("after SEEK_DATA the read gives %q, want c, the record after the clear", got)
	}
	seek(linux.SEEK_END)
	if got := next(); got != linuxerr.ErrWouldBlock.Error() {
		t.Errorf("after SEEK_END the read gives %q, want would block", got)
	}
	l.Printk(kernel.LogInfo, "d")
	if got := next(); got != "d" {
		t.Errorf("a record after SEEK_END reads as %q, want d", got)
	}
}

func TestKmsgSeekErrors(t *testing.T) {
	fd, _ := newKmsgFD(kernel.KernelLogDefaultBufLen)
	for _, whence := range []int32{linux.SEEK_SET, linux.SEEK_DATA, linux.SEEK_END} {
		if _, err := fd.Seek(context.Background(), 1, whence); !linuxerr.Equals(linuxerr.ESPIPE, err) {
			t.Errorf("Seek(1, %d) error = %v, want ESPIPE", whence, err)
		}
	}
	for _, whence := range []int32{linux.SEEK_CUR, linux.SEEK_HOLE, 99} {
		if _, err := fd.Seek(context.Background(), 0, whence); !linuxerr.Equals(linuxerr.EINVAL, err) {
			t.Errorf("Seek(0, %d) error = %v, want EINVAL", whence, err)
		}
	}
}

func TestKmsgReadinessFollowsTheRecordAtThePosition(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogMinBufLen)
	all := waiter.ReadableEvents | waiter.WritableEvents | waiter.EventErr | waiter.EventPri
	if got := fd.Readiness(all); got != 0 {
		t.Errorf("Readiness of an empty log = %#x, want 0", got)
	}
	l.Printk(kernel.LogInfo, "x")
	if got := fd.Readiness(all); got != waiter.ReadableEvents {
		t.Errorf("Readiness with a record = %#x, want %#x", got, waiter.ReadableEvents)
	}
	text := strings.Repeat("y", 1000)
	for i := 0; i < 10; i++ {
		l.Printk(kernel.LogInfo, text)
	}
	if got, want := fd.Readiness(all), waiter.ReadableEvents|waiter.EventErr|waiter.EventPri; got != want {
		t.Errorf("Readiness after an overwrite = %#x, want %#x", got, want)
	}
	if got := fd.Readiness(waiter.WritableEvents); got != 0 {
		t.Errorf("Readiness(writable) = %#x, want 0 as in Linux", got)
	}
}

func TestKmsgNewRecordWakesAWaiter(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := fd.EventRegister(&e); err != nil {
		t.Fatal(err)
	}
	defer fd.EventUnregister(&e)
	l.Printk(kernel.LogInfo, "x")
	select {
	case <-ch:
	default:
		t.Error("a new record did not wake the waiter")
	}
}

func TestKmsgWriteMakesRecordsOfTheUserFacility(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	n, err := fd.writeString("<30>kubelet: started\nsecond line\n")
	if err != nil || n != int64(len("<30>kubelet: started\nsecond line\n")) {
		t.Fatalf("write = %d, %v", n, err)
	}
	r0, _ := l.Lookup(0)
	r1, _ := l.Lookup(1)
	if r0.Text != "kubelet: started" || r0.Priority() != 3<<3|6 || r1.Text != "second line" || r1.Priority() != 3<<3|6 {
		t.Errorf("records = %+v, %+v", r0, r1)
	}
}

func TestKmsgWriteOfMoreThan1024BytesFails(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	if _, err := fd.writeString(strings.Repeat("x", 1025)); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("write of 1025 bytes: err = %v, want EINVAL", err)
	}
	if l.NextSeq() != 0 {
		t.Errorf("a failed write made a record")
	}
}

func TestKmsgWriteRateLimitCountsPerDescriptor(t *testing.T) {
	a, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	b := &kmsgFD{log: l, seq: l.FirstSeq()}
	for i := 0; i < 15; i++ {
		if n, err := a.writeString("x"); err != nil || n != 1 {
			t.Fatalf("write %d = %d, %v, want 1: a dropped write still succeeds", i, n, err)
		}
	}
	if _, err := b.writeString("y"); err != nil {
		t.Fatal(err)
	}
	if got := l.NextSeq(); got != 11 {
		t.Errorf("records = %d, want 10 from the first descriptor and 1 from the second", got)
	}
}

func TestKmsgWriteHonorsTheModeOff(t *testing.T) {
	fd, l := newKmsgFD(kernel.KernelLogDefaultBufLen)
	l.SetDevkmsgMode(kernel.DevkmsgOff)
	if n, err := fd.writeString("x"); err != nil || n != 1 {
		t.Fatalf("write = %d, %v, want 1", n, err)
	}
	if l.NextSeq() != 0 {
		t.Errorf("a write in the mode off made a record")
	}
}

func TestKmsgPositionalIOFailsWithESPIPE(t *testing.T) {
	fd, _ := newKmsgFD(kernel.KernelLogDefaultBufLen)
	if _, err := fd.PRead(context.Background(), usermem.BytesIOSequence(make([]byte, 8)), 0, vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.ESPIPE, err) {
		t.Errorf("PRead error = %v, want ESPIPE", err)
	}
	if _, err := fd.PWrite(context.Background(), usermem.BytesIOSequence([]byte("x")), 0, vfs.WriteOptions{}); !linuxerr.Equals(linuxerr.ESPIPE, err) {
		t.Errorf("PWrite error = %v, want ESPIPE", err)
	}
}
