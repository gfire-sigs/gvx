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

package kernel

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"weak"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/waiter"
)

// This file implements the kernel log ring of the guest that printk populates
// in Linux. /dev/kmsg, syslog(2), dmesg, the OOM killer of the memory
// controller, and the iptables LOG target share this ring. Each record stores
// a sequence number, a facility, a level, a timestamp since boot, and one line
// of text. The ring evicts the oldest records when capacity runs out.

// Severity levels from include/linux/kern_levels.h.
const (
	LogEmerg = iota
	LogAlert
	LogCrit
	LogErr
	LogWarning
	LogNotice
	LogInfo
	LogDebug
)

// Record facilities. Kernel writers pass LogFacilityKern; /dev/kmsg writes
// default to LogFacilityUser when the prefix specifies no facility.
const (
	LogFacilityKern = 0
	LogFacilityUser = 1
)

const (
	// LogDefaultLevel selects default_message_loglevel in Emit.
	LogDefaultLevel = -1

	// KernelLogDefaultBufLen matches Linux CONFIG_LOG_BUF_SHIFT=17 (128 KiB).
	KernelLogDefaultBufLen = 1 << 17
	// KernelLogMinBufLen matches Linux CONFIG_LOG_BUF_SHIFT=12 (4 KiB).
	KernelLogMinBufLen = 1 << 12
	// KernelLogMaxBufLen matches Linux LOG_BUF_LEN_MAX.
	KernelLogMaxBufLen = 1 << 31

	// KernelLogMessageMax matches Linux PRINTK_MESSAGE_MAX for /dev/kmsg reads.
	KernelLogMessageMax = 2048

	// KernelLogRecordMax matches Linux PRINTKRB_RECORD_MAX for record text and
	// /dev/kmsg writes.
	KernelLogRecordMax = 1024

	// logAvgRecordBits matches Linux PRB_AVGBITS (one descriptor per 32 bytes).
	logAvgRecordBits = 5

	// logBlockOverhead matches the 8-byte record ID header in Linux.
	logBlockOverhead = 8

	// Default /proc/sys/kernel/printk values when Linux boots without "quiet".
	defaultConsoleLogLevel = 7
	defaultMessageLogLevel = 4
	minimumConsoleLogLevel = 1
)

// KernelLogRecord holds one entry in the kernel log ring.
//
// +stateify savable
type KernelLogRecord struct {
	// Seq is the monotonic sequence number starting at 0.
	Seq uint64
	// Time is the elapsed monotonic time since boot when the record entered.
	Time time.Duration
	// Facility and Level hold the syslog facility and severity level.
	Facility uint8
	Level    uint8
	// Text holds one line without a trailing newline.
	Text string
}

// Priority returns (Facility << 3) | Level as syslog and /dev/kmsg format it.
func (r KernelLogRecord) Priority() int {
	return int(r.Facility)<<3 | int(r.Level)
}

// blockSize returns the aligned byte footprint of the record in the data ring.
func (r KernelLogRecord) blockSize() int {
	return (len(r.Text) + logBlockOverhead + 7) &^ 7
}

// AppendKmsg appends the record in /dev/kmsg read format
// ("prio,seq,usec,-;text\n"). It escapes bytes below 0x20, bytes above 0x7e,
// and backslashes as \xNN, capping total length at KernelLogMessageMax without
// splitting an escape sequence.
func (r KernelLogRecord) AppendKmsg(dst []byte) []byte {
	start := len(dst)
	dst = strconv.AppendInt(dst, int64(r.Priority()), 10)
	dst = append(dst, ',')
	dst = strconv.AppendUint(dst, r.Seq, 10)
	dst = append(dst, ',')
	dst = strconv.AppendInt(dst, int64(r.Time/time.Microsecond), 10)
	dst = append(dst, ",-;"...)
	const hex = "0123456789abcdef"
	for i := range len(r.Text) {
		c := r.Text[i]
		escaped := c < ' ' || c >= 127 || c == '\\'
		width := 1
		if escaped {
			width = 4
		}
		// Reserve one byte for the trailing newline.
		if len(dst)-start+width > KernelLogMessageMax-1 {
			break
		}
		if escaped {
			dst = append(dst, '\\', 'x', hex[c>>4], hex[c&15])
			continue
		}
		dst = append(dst, c)
	}
	return append(dst, '\n')
}

// AppendSyslog appends the record in syslog(2) format ("<prio>[ sec.usec] text\n").
func (r KernelLogRecord) AppendSyslog(dst []byte) []byte {
	dst = fmt.Appendf(dst, "<%d>[%5d.%06d] ", r.Priority(), int64(r.Time/time.Second), int64(r.Time%time.Second/time.Microsecond))
	dst = append(dst, r.Text...)
	return append(dst, '\n')
}

// syslogLen computes len(r.AppendSyslog(nil)) without allocating.
func (r KernelLogRecord) syslogLen() int {
	digits := func(n int64) int {
		d := 1
		for ; n >= 10; n /= 10 {
			d++
		}
		return d
	}
	return 1 + digits(int64(r.Priority())) + 2 + max(5, digits(int64(r.Time/time.Second))) + 1 + 6 + 2 + len(r.Text) + 1
}

// KernelLog owns the kernel log ring of one Kernel instance. All exported
// methods are safe for concurrent callers.
//
// +stateify savable
type KernelLog struct {
	// now returns elapsed time since boot. Rebound on restore via AttachKernelLog.
	now func() time.Duration `state:"nosave"`

	// bufLen is the data ring capacity in bytes (power of two). Immutable.
	bufLen int
	// maxRecords bounds live descriptors in the ring. Immutable.
	maxRecords int

	// devkmsg and dmesgRestrict store the corresponding sysctl settings.
	devkmsg       atomic.Int32 `state:".(int32)"`
	dmesgRestrict atomic.Bool  `state:".(bool)"`

	// queue wakes /dev/kmsg and syslog(2) readers when Emit appends records.
	queue waiter.Queue

	mu sync.Mutex `state:"nosave"`

	// +checklocks:mu
	records []KernelLogRecord
	// +checklocks:mu
	first int
	// +checklocks:mu
	used int
	// +checklocks:mu
	nextSeq uint64
	// +checklocks:mu
	clearSeq uint64
	// +checklocks:mu
	syslogSeq uint64
	// +checklocks:mu
	syslogPartial int
	// +checklocks:mu
	levels [4]int
	// +checklocks:mu
	savedConsole int
}

// saveDevkmsg is invoked by stateify.
func (l *KernelLog) saveDevkmsg() int32 {
	return l.devkmsg.Load()
}

// loadDevkmsg is invoked by stateify.
func (l *KernelLog) loadDevkmsg(_ context.Context, v int32) {
	l.devkmsg.Store(v)
}

// saveDmesgRestrict is invoked by stateify.
func (l *KernelLog) saveDmesgRestrict() bool {
	return l.dmesgRestrict.Load()
}

// loadDmesgRestrict is invoked by stateify.
func (l *KernelLog) loadDmesgRestrict(_ context.Context, v bool) {
	l.dmesgRestrict.Store(v)
}

// afterLoad is invoked by stateify.
func (l *KernelLog) afterLoad(ctx context.Context) {
	if ctx == nil {
		return
	}
	if k, ok := ctx.Value(CtxKernel).(*Kernel); ok && k != nil {
		k.AttachKernelLog(l)
	}
}

// noSavedConsole marks an empty savedConsole slot, matching Linux LOGLEVEL_DEFAULT.
const noSavedConsole = -1

// NewKernelLog allocates an empty kernel log ring. It rounds bufLen up to a
// power of two and clamps it within [KernelLogMinBufLen, KernelLogMaxBufLen].
// now returns elapsed monotonic time since boot.
func NewKernelLog(bufLen int, now func() time.Duration) *KernelLog {
	size := KernelLogMinBufLen
	for size < bufLen && size < KernelLogMaxBufLen {
		size <<= 1
	}
	return &KernelLog{
		now:          now,
		bufLen:       size,
		maxRecords:   size >> logAvgRecordBits,
		levels:       [4]int{defaultConsoleLogLevel, defaultMessageLogLevel, minimumConsoleLogLevel, defaultConsoleLogLevel},
		savedConsole: noSavedConsole,
	}
}

// BufLen returns the ring capacity in bytes.
func (l *KernelLog) BufLen() int {
	return l.bufLen
}

// Emit splits text on newlines (ignoring one trailing newline), truncates lines
// to KernelLogRecordMax bytes, and appends one record per line. A negative
// level selects default_message_loglevel.
func (l *KernelLog) Emit(facility, level int, text string) {
	text = strings.TrimSuffix(text, "\n")
	l.mu.Lock()
	// Sample the clock under mu so sequence order matches timestamp order.
	var now time.Duration
	if l.now != nil {
		now = l.now()
	}
	if level < 0 {
		level = l.levels[1]
	}
	for {
		line, rest, more := strings.Cut(text, "\n")
		l.appendLocked(KernelLogRecord{
			Time:     now,
			Facility: uint8(facility),
			Level:    uint8(level & 7),
			Text:     line[:min(len(line), KernelLogRecordMax)],
		})
		if !more {
			break
		}
		text = rest
	}
	l.mu.Unlock()
	l.queue.Notify(waiter.ReadableEvents | waiter.EventErr | waiter.EventPri)
}

// Printk appends text under LogFacilityKern.
func (l *KernelLog) Printk(level int, text string) {
	l.Emit(LogFacilityKern, level, text)
}

// Printkf formats and appends text under LogFacilityKern.
func (l *KernelLog) Printkf(level int, format string, args ...any) {
	l.Printk(level, fmt.Sprintf(format, args...))
}

// appendLocked appends r and evicts the oldest records until capacity permits.
//
// +checklocks:l.mu
func (l *KernelLog) appendLocked(r KernelLogRecord) {
	r.Seq = l.nextSeq
	l.nextSeq++
	for l.first < len(l.records) && (l.used+r.blockSize() > l.bufLen || len(l.records)-l.first >= l.maxRecords) {
		l.used -= l.records[l.first].blockSize()
		l.records[l.first] = KernelLogRecord{}
		l.first++
	}
	if l.first > 64 && l.first*2 >= len(l.records) {
		l.records = append(l.records[:0], l.records[l.first:]...)
		l.first = 0
	}
	l.records = append(l.records, r)
	l.used += r.blockSize()
}

// firstSeqLocked returns the oldest sequence number, or nextSeq when empty.
//
// +checklocks:l.mu
func (l *KernelLog) firstSeqLocked() uint64 {
	if l.first == len(l.records) {
		return l.nextSeq
	}
	return l.records[l.first].Seq
}

// FirstSeq returns the oldest live sequence number, or NextSeq when empty.
func (l *KernelLog) FirstSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.firstSeqLocked()
}

// NextSeq returns the sequence number assigned to the next appended record.
func (l *KernelLog) NextSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.nextSeq
}

// ClearSeq returns the sequence number immediately after the last Clear call.
func (l *KernelLog) ClearSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.clearSeq
}

// Lookup returns the first live record with sequence number >= seq. When the
// ring has evicted seq, rec.Seq exceeds seq. ok is false when seq >= NextSeq.
func (l *KernelLog) Lookup(seq uint64) (rec KernelLogRecord, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.lookupLocked(seq)
}

// +checklocks:l.mu
func (l *KernelLog) lookupLocked(seq uint64) (KernelLogRecord, bool) {
	if l.first == len(l.records) || seq >= l.nextSeq {
		return KernelLogRecord{}, false
	}
	first := l.records[l.first].Seq
	if seq < first {
		seq = first
	}
	return l.records[l.first+int(seq-first)], true
}

// Clear advances clearSeq for SYSLOG_ACTION_CLEAR without evicting records.
func (l *KernelLog) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clearSeq = l.nextSeq
}

// EventRegister implements waiter.Waitable.EventRegister.
func (l *KernelLog) EventRegister(e *waiter.Entry) error {
	l.queue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (l *KernelLog) EventUnregister(e *waiter.Entry) {
	l.queue.EventUnregister(e)
}

// DevkmsgMode returns the current kernel.printk_devkmsg setting.
func (l *KernelLog) DevkmsgMode() DevkmsgMode {
	return DevkmsgMode(l.devkmsg.Load())
}

// SetDevkmsgMode updates the kernel.printk_devkmsg setting.
func (l *KernelLog) SetDevkmsgMode(m DevkmsgMode) {
	l.devkmsg.Store(int32(m))
}

// DmesgRestrict returns the current kernel.dmesg_restrict setting.
func (l *KernelLog) DmesgRestrict() bool {
	return l.dmesgRestrict.Load()
}

// SetDmesgRestrict updates the kernel.dmesg_restrict setting.
func (l *KernelLog) SetDmesgRestrict(restrict bool) {
	l.dmesgRestrict.Store(restrict)
}

// Levels returns the four /proc/sys/kernel/printk integers: console_loglevel,
// default_message_loglevel, minimum_console_loglevel, default_console_loglevel.
func (l *KernelLog) Levels() [4]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.levels
}

// SetLevels updates the four /proc/sys/kernel/printk integers.
func (l *KernelLog) SetLevels(levels [4]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.levels = levels
}

// SetConsoleLevel implements SYSLOG_ACTION_CONSOLE_LEVEL for levels 1..8,
// clamping below minimum_console_loglevel and clearing any saved console level.
func (l *KernelLog) SetConsoleLevel(level int) bool {
	if level < 1 || level > 8 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.levels[0] = max(level, l.levels[2])
	l.savedConsole = noSavedConsole
	return true
}

// ConsoleOff implements SYSLOG_ACTION_CONSOLE_OFF.
func (l *KernelLog) ConsoleOff() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.savedConsole == noSavedConsole {
		l.savedConsole = l.levels[0]
	}
	l.levels[0] = l.levels[2]
}

// ConsoleOn implements SYSLOG_ACTION_CONSOLE_ON.
func (l *KernelLog) ConsoleOn() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.savedConsole != noSavedConsole {
		l.levels[0] = l.savedConsole
		l.savedConsole = noSavedConsole
	}
}

// ReadAll implements SYSLOG_ACTION_READ_ALL and SYSLOG_ACTION_READ_CLEAR. It
// collects whole records since clearSeq that fit in size bytes and formats them
// outside mu.
func (l *KernelLog) ReadAll(size int, clear bool) []byte {
	l.mu.Lock()
	start := max(l.clearSeq, l.firstSeqLocked())
	var newestFirst []KernelLogRecord
	total := 0
	for seq := l.nextSeq; seq > start; seq-- {
		rec, _ := l.lookupLocked(seq - 1)
		n := rec.syslogLen()
		if total+n > size {
			break
		}
		total += n
		newestFirst = append(newestFirst, rec)
	}
	if clear {
		l.clearSeq = l.nextSeq
	}
	l.mu.Unlock()
	out := make([]byte, 0, total)
	for i := len(newestFirst) - 1; i >= 0; i-- {
		out = newestFirst[i].AppendSyslog(out)
	}
	return out
}

// skipGoneLocked advances syslogSeq when ring eviction drops unread records.
//
// +checklocks:l.mu
func (l *KernelLog) skipGoneLocked() {
	if first := l.firstSeqLocked(); l.syslogSeq < first {
		l.syslogSeq = first
		l.syslogPartial = 0
	}
}

// syslogSegment describes a slice of one formatted syslog record.
type syslogSegment struct {
	rec        KernelLogRecord
	skip, take int
}

// Read implements SYSLOG_ACTION_READ. It consumes up to size formatted bytes
// from syslogSeq and returns nil when no unread record exists.
func (l *KernelLog) Read(size int) []byte {
	l.mu.Lock()
	var segments []syslogSegment
	got := 0
	for size > got {
		l.skipGoneLocked()
		rec, ok := l.lookupLocked(l.syslogSeq)
		if !ok {
			break
		}
		n := rec.syslogLen() - l.syslogPartial
		room := size - got
		if n <= room {
			segments = append(segments, syslogSegment{rec, l.syslogPartial, n})
			got += n
			l.syslogSeq = rec.Seq + 1
			l.syslogPartial = 0
			continue
		}
		if got == 0 {
			segments = append(segments, syslogSegment{rec, l.syslogPartial, room})
			got = room
			l.syslogPartial += room
		}
		break
	}
	l.mu.Unlock()
	out := make([]byte, 0, got)
	for _, seg := range segments {
		out = append(out, seg.rec.AppendSyslog(nil)[seg.skip:seg.skip+seg.take]...)
	}
	return out
}

// UnreadSize implements SYSLOG_ACTION_SIZE_UNREAD.
func (l *KernelLog) UnreadSize() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.skipGoneLocked()
	total := 0
	for seq := l.syslogSeq; seq < l.nextSeq; seq++ {
		rec, _ := l.lookupLocked(seq)
		total += rec.syslogLen()
	}
	return total - l.syslogPartial
}

// CanReadKernelLog reports whether creds hold CAP_SYSLOG or CAP_SYS_ADMIN in
// the root user namespace of k, as Linux requires under dmesg_restrict.
func CanReadKernelLog(creds *auth.Credentials, k *Kernel) bool {
	root := k.RootUserNamespace()
	return creds.HasCapabilityIn(linux.CAP_SYSLOG, root) || creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, root)
}

// kernelLogEntry stores the configured ring size and lazy ring for one Kernel.
type kernelLogEntry struct {
	bufLen int
	log    *KernelLog
}

// kernelLogRegistry maps each live Kernel to its KernelLog by weak pointer.
// Unreferenced Kernel instances drop their ring buffers without adding fields
// to Kernel or syslog.
type kernelLogRegistry struct {
	mu sync.Mutex
	// +checklocks:mu
	entries map[weak.Pointer[Kernel]]*kernelLogEntry
}

var kernelLogs kernelLogRegistry

func cleanupKernelLog(key weak.Pointer[Kernel]) {
	kernelLogs.mu.Lock()
	defer kernelLogs.mu.Unlock()
	delete(kernelLogs.entries, key)
}

// +checklocks:kernelLogs.mu
func kernelLogEntryFor(k *Kernel) (*kernelLogEntry, weak.Pointer[Kernel]) {
	key := weak.Make(k)
	if entry, ok := kernelLogs.entries[key]; ok {
		return entry, key
	}
	if kernelLogs.entries == nil {
		kernelLogs.entries = make(map[weak.Pointer[Kernel]]*kernelLogEntry)
	}
	entry := &kernelLogEntry{}
	kernelLogs.entries[key] = entry
	runtime.AddCleanup(k, cleanupKernelLog, key)
	return entry, key
}

// kernelUptimeFunc binds only the weak Kernel pointer so the stored KernelLog
// never retains k strongly through its clock callback.
func kernelUptimeFunc(key weak.Pointer[Kernel]) func() time.Duration {
	return func() time.Duration {
		k := key.Value()
		if k == nil {
			return 0
		}
		return k.uptime()
	}
}

// SetKernelLogBufLen sets the byte capacity of the kernel log ring for k before
// its first KernelLog call. It returns false once the ring exists.
func (k *Kernel) SetKernelLogBufLen(bufLen int) bool {
	kernelLogs.mu.Lock()
	defer kernelLogs.mu.Unlock()
	entry, _ := kernelLogEntryFor(k)
	if entry.log != nil {
		return false
	}
	entry.bufLen = bufLen
	return true
}

// KernelLogBufLen returns the configured ring byte capacity for k, or 0 before
// SetKernelLogBufLen or KernelLog runs on k.
func (k *Kernel) KernelLogBufLen() int {
	if k == nil {
		return 0
	}
	kernelLogs.mu.Lock()
	defer kernelLogs.mu.Unlock()
	if entry, ok := kernelLogs.entries[weak.Make(k)]; ok {
		if entry.log != nil {
			return entry.log.bufLen
		}
		return entry.bufLen
	}
	return 0
}

// LookupKernelLog returns the allocated kernel log ring of k, or nil before
// first access.
func (k *Kernel) LookupKernelLog() *KernelLog {
	kernelLogs.mu.Lock()
	defer kernelLogs.mu.Unlock()
	if entry, ok := kernelLogs.entries[weak.Make(k)]; ok {
		return entry.log
	}
	return nil
}

// AttachKernelLog binds l as the kernel log ring of k after restore.
func (k *Kernel) AttachKernelLog(l *KernelLog) {
	if l == nil {
		return
	}
	kernelLogs.mu.Lock()
	entry, key := kernelLogEntryFor(k)
	entry.bufLen = l.bufLen
	entry.log = l
	kernelLogs.mu.Unlock()
	l.mu.Lock()
	l.now = kernelUptimeFunc(key)
	l.mu.Unlock()
}

// KernelLog returns the kernel log ring of k, allocating it on first access.
func (k *Kernel) KernelLog() *KernelLog {
	kernelLogs.mu.Lock()
	defer kernelLogs.mu.Unlock()
	entry, key := kernelLogEntryFor(k)
	if entry.log == nil {
		bufLen := entry.bufLen
		if bufLen == 0 {
			bufLen = KernelLogDefaultBufLen
		}
		entry.log = NewKernelLog(bufLen, kernelUptimeFunc(key))
	}
	return entry.log
}

// uptime returns elapsed monotonic time since boot, or zero before timekeeper
// initialization completes.
func (k *Kernel) uptime() time.Duration {
	if k.timekeeper == nil || k.timekeeper.monotonicClock == nil {
		return 0
	}
	return time.Duration(k.timekeeper.monotonicClock.Now().Nanoseconds())
}
