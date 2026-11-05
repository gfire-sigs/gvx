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
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/waiter"
)

// This file implements the kernel log of the guest: the ring buffer that
// printk fills in Linux. /dev/kmsg, syslog(2), dmesg, the OOM killer of the
// memory controller, and the iptables LOG target use it. The ring follows
// kernel/printk/printk.c and printk_ringbuffer.c of Linux: a record has a
// sequence number, a facility, a level, a time in nanoseconds since boot, and
// a text of one line. The oldest records leave when the ring is full.

// The levels of a record, from include/linux/kern_levels.h.
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

// The facilities that a record can have. The kernel uses LogFacilityKern. A
// write to /dev/kmsg gets LogFacilityUser when it names no other facility.
const (
	LogFacilityKern = 0
	LogFacilityUser = 1
)

const (
	// LogDefaultLevel selects default_message_loglevel when a writer gives
	// Emit a level.
	LogDefaultLevel = -1

	// KernelLogDefaultBufLen is the size of the ring in Linux with
	// CONFIG_LOG_BUF_SHIFT=17.
	KernelLogDefaultBufLen = 1 << 17
	// KernelLogMinBufLen is the smallest ring, CONFIG_LOG_BUF_SHIFT=12.
	KernelLogMinBufLen = 1 << 12
	// KernelLogMaxBufLen is LOG_BUF_LEN_MAX of Linux.
	KernelLogMaxBufLen = 1 << 31

	// KernelLogMessageMax is the longest read of /dev/kmsg, PRINTK_MESSAGE_MAX
	// of Linux. A longer record loses the end of its text.
	KernelLogMessageMax = 2048

	// KernelLogRecordMax is the longest text of a record and the longest
	// write to /dev/kmsg, PRINTKRB_RECORD_MAX of Linux.
	KernelLogRecordMax = 1024

	// logAvgRecordBits is PRB_AVGBITS of Linux. The ring holds one
	// descriptor for each 32 bytes of its size.
	logAvgRecordBits = 5

	// logBlockOverhead is the size of the ID that Linux stores in front of
	// the text of a record.
	logBlockOverhead = 8

	// The values of the four integers of /proc/sys/kernel/printk in Linux
	// for a kernel without the option "quiet": the console level starts at the
	// default console level.
	defaultConsoleLogLevel = 7
	defaultMessageLogLevel = 4
	minimumConsoleLogLevel = 1
)

// The rate limit of a /dev/kmsg descriptor: DEFAULT_RATELIMIT_INTERVAL and
// DEFAULT_RATELIMIT_BURST of Linux.
const (
	logRateInterval = 5 * time.Second
	logRateBurst    = 10
)

// DevkmsgMode is the value of /proc/sys/kernel/printk_devkmsg.
type DevkmsgMode int32

// The modes of kernel.printk_devkmsg.
const (
	// DevkmsgRatelimit limits a /dev/kmsg descriptor to 10 writes in 5 seconds.
	// It is the default.
	DevkmsgRatelimit DevkmsgMode = iota
	// DevkmsgOn accepts every write.
	DevkmsgOn
	// DevkmsgOff drops every write and reports success.
	DevkmsgOff
)

// String returns the text that /proc/sys/kernel/printk_devkmsg shows.
func (m DevkmsgMode) String() string {
	switch m {
	case DevkmsgOn:
		return "on"
	case DevkmsgOff:
		return "off"
	default:
		return "ratelimit"
	}
}

// ParseDevkmsgMode returns the mode that text names. The text is "on", "off",
// or "ratelimit", with an optional trailing newline.
func ParseDevkmsgMode(text string) (DevkmsgMode, bool) {
	switch strings.TrimSuffix(text, "\n") {
	case "on":
		return DevkmsgOn, true
	case "off":
		return DevkmsgOff, true
	case "ratelimit":
		return DevkmsgRatelimit, true
	}
	return 0, false
}

// KernelLogRecord is one record of the kernel log.
type KernelLogRecord struct {
	// Seq is the sequence number. The first record has number 0.
	Seq uint64
	// Time is the time since boot at which the record entered the log.
	Time time.Duration
	// Facility and Level are the syslog facility and level.
	Facility uint8
	Level    uint8
	// Text is one line without a newline.
	Text string
}

// Priority returns the value that syslog and /dev/kmsg show: the facility
// shifted by three bits, ORed with the level.
func (r KernelLogRecord) Priority() int {
	return int(r.Facility)<<3 | int(r.Level)
}

// blockSize returns the bytes of the data ring that the record uses.
func (r KernelLogRecord) blockSize() int {
	return (len(r.Text) + logBlockOverhead + 7) &^ 7
}

// AppendKmsg appends the record in the format of a read of /dev/kmsg:
// "prio,seq,usec,flag;text\n". The text escapes each byte below 0x20, each
// byte above 0x7e, and the backslash as \xNN. Documentation/ABI/testing/dev-kmsg
// of Linux describes the format. The record is at most KernelLogMessageMax
// bytes, with its newline. An escape that does not fit is not cut: the record
// ends before it.
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
		// Keep one byte for the newline.
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

// AppendSyslog appends the record in the text form of syslog(2):
// "<prio>[ sec.usec] text\n".
func (r KernelLogRecord) AppendSyslog(dst []byte) []byte {
	dst = fmt.Appendf(dst, "<%d>[%5d.%06d] ", r.Priority(), int64(r.Time/time.Second), int64(r.Time%time.Second/time.Microsecond))
	dst = append(dst, r.Text...)
	return append(dst, '\n')
}

// syslogLen returns len(AppendSyslog) without the format.
func (r KernelLogRecord) syslogLen() int {
	digits := func(n int64) int {
		d := 1
		for ; n >= 10; n /= 10 {
			d++
		}
		return d
	}
	// "<prio>[", the seconds with a width of 5, ".", 6 digits, "] ", the text,
	// and the newline.
	return 1 + digits(int64(r.Priority())) + 2 + max(5, digits(int64(r.Time/time.Second))) + 1 + 6 + 2 + len(r.Text) + 1
}

// KernelLog is the kernel log ring of one kernel. All methods are safe for
// concurrent use.
type KernelLog struct {
	// now returns the time since boot. Immutable.
	now func() time.Duration

	// bufLen is the size of the data ring in bytes, a power of two. Immutable.
	bufLen int
	// maxRecords is the number of descriptors of the ring. Immutable.
	maxRecords int

	// devkmsg and dmesgRestrict are the two sysctl values that govern access.
	devkmsg       atomic.Int32
	dmesgRestrict atomic.Bool

	// queue holds the waiters that want a record. Each new record notifies it.
	queue waiter.Queue

	mu sync.Mutex

	// records holds the live records, the oldest at index first. The records
	// have consecutive sequence numbers.
	records []KernelLogRecord
	first   int
	// used is the sum of blockSize over the live records.
	used int
	// nextSeq is the sequence number of the next record.
	nextSeq uint64
	// clearSeq is the sequence number after the last record that
	// SYSLOG_ACTION_CLEAR cleared.
	clearSeq uint64
	// syslogSeq and syslogPartial are the read position of
	// SYSLOG_ACTION_READ: the next record, and the bytes of it that a
	// previous read already returned.
	syslogSeq     uint64
	syslogPartial int
	// levels holds console_loglevel, default_message_loglevel,
	// minimum_console_loglevel, and default_console_loglevel, in the order of
	// /proc/sys/kernel/printk.
	levels [4]int
	// savedConsole is the console level that SYSLOG_ACTION_CONSOLE_OFF
	// replaced, or noSavedConsole.
	savedConsole int
}

// noSavedConsole is LOGLEVEL_DEFAULT of Linux in the field savedConsole.
const noSavedConsole = -1

// NewKernelLog returns an empty kernel log. bufLen is the size of the ring in
// bytes. As in Linux, the log rounds it up to a power of two, and a value
// outside KernelLogMinBufLen and KernelLogMaxBufLen moves to the nearest
// limit. now returns the time since boot.
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

// BufLen returns the size of the ring in bytes.
func (l *KernelLog) BufLen() int {
	return l.bufLen
}

// Emit appends the text with the facility and the level. A text with newlines
// becomes one record for each line, and one final newline does not start a new
// line. A line longer than KernelLogRecordMax loses its end. A negative level
// selects default_message_loglevel.
func (l *KernelLog) Emit(facility, level int, text string) {
	text = strings.TrimSuffix(text, "\n")
	l.mu.Lock()
	// Read the clock under the lock, so that a later sequence number never
	// has an earlier time.
	now := l.now()
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

// Printk appends text as a record of the kernel facility.
func (l *KernelLog) Printk(level int, text string) {
	l.Emit(LogFacilityKern, level, text)
}

// Printkf is Printk with a format.
func (l *KernelLog) Printkf(level int, format string, args ...any) {
	l.Printk(level, fmt.Sprintf(format, args...))
}

// appendLocked adds a record and drops the oldest records that do not fit.
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
	// Drop the slots of dropped records when they are half of the slice.
	if l.first > 64 && l.first*2 >= len(l.records) {
		l.records = append(l.records[:0], l.records[l.first:]...)
		l.first = 0
	}
	l.records = append(l.records, r)
	l.used += r.blockSize()
}

// firstSeqLocked returns the sequence number of the oldest record, or the next
// sequence number when the log is empty.
//
// +checklocks:l.mu
func (l *KernelLog) firstSeqLocked() uint64 {
	if l.first == len(l.records) {
		return l.nextSeq
	}
	return l.records[l.first].Seq
}

// FirstSeq returns the sequence number of the oldest record. It returns
// NextSeq when the log has no record.
func (l *KernelLog) FirstSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.firstSeqLocked()
}

// NextSeq returns the sequence number that the next record gets.
func (l *KernelLog) NextSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.nextSeq
}

// ClearSeq returns the sequence number after the last cleared record.
func (l *KernelLog) ClearSeq() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.clearSeq
}

// Lookup returns the first record with a sequence number of at least seq. The
// result differs from seq in its Seq field when the record seq left the ring.
// ok is false when no such record exists yet.
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

// Clear implements SYSLOG_ACTION_CLEAR. It does not remove a record. It moves
// the start of SYSLOG_ACTION_READ_ALL and of SEEK_DATA.
func (l *KernelLog) Clear() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.clearSeq = l.nextSeq
}

// EventRegister implements waiter.Waitable.EventRegister. The queue fires for
// each new record.
func (l *KernelLog) EventRegister(e *waiter.Entry) error {
	l.queue.EventRegister(e)
	return nil
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (l *KernelLog) EventUnregister(e *waiter.Entry) {
	l.queue.EventUnregister(e)
}

// DevkmsgMode returns the value of kernel.printk_devkmsg.
func (l *KernelLog) DevkmsgMode() DevkmsgMode {
	return DevkmsgMode(l.devkmsg.Load())
}

// SetDevkmsgMode sets kernel.printk_devkmsg.
func (l *KernelLog) SetDevkmsgMode(m DevkmsgMode) {
	l.devkmsg.Store(int32(m))
}

// DmesgRestrict returns the value of kernel.dmesg_restrict.
func (l *KernelLog) DmesgRestrict() bool {
	return l.dmesgRestrict.Load()
}

// SetDmesgRestrict sets kernel.dmesg_restrict.
func (l *KernelLog) SetDmesgRestrict(restrict bool) {
	l.dmesgRestrict.Store(restrict)
}

// Levels returns console_loglevel, default_message_loglevel,
// minimum_console_loglevel, and default_console_loglevel, the four integers of
// /proc/sys/kernel/printk.
func (l *KernelLog) Levels() [4]int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.levels
}

// SetLevels sets the four integers of /proc/sys/kernel/printk.
func (l *KernelLog) SetLevels(levels [4]int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.levels = levels
}

// SetConsoleLevel implements SYSLOG_ACTION_CONSOLE_LEVEL. level is a value from
// 1 to 8. A level below minimum_console_loglevel becomes that minimum. The call
// also drops the level that CONSOLE_OFF saved. It returns false for a level
// outside 1 to 8.
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

// ConsoleOff implements SYSLOG_ACTION_CONSOLE_OFF. It saves the console level
// unless a previous call saved one, and sets the minimum level.
func (l *KernelLog) ConsoleOff() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.savedConsole == noSavedConsole {
		l.savedConsole = l.levels[0]
	}
	l.levels[0] = l.levels[2]
}

// ConsoleOn implements SYSLOG_ACTION_CONSOLE_ON. It restores the level that
// CONSOLE_OFF saved, and does nothing when no level is saved.
func (l *KernelLog) ConsoleOn() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.savedConsole != noSavedConsole {
		l.levels[0] = l.savedConsole
		l.savedConsole = noSavedConsole
	}
}

// ReadAll implements SYSLOG_ACTION_READ_ALL and SYSLOG_ACTION_READ_CLEAR. It
// returns the newest records since the last clear, in the text form of
// syslog(2), whole records only, and at most size bytes. With clear set, it
// then clears the log. The call walks back from the newest record and stops at
// size, and it formats the records after it releases the lock, so its cost
// under the lock does not grow with the ring.
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

// skipGoneLocked moves the read position of SYSLOG_ACTION_READ to the oldest
// record when the ring dropped the record at the position.
//
// +checklocks:l.mu
func (l *KernelLog) skipGoneLocked() {
	if first := l.firstSeqLocked(); l.syslogSeq < first {
		l.syslogSeq = first
		l.syslogPartial = 0
	}
}

// syslogSegment is the part of one record that a Read returns.
type syslogSegment struct {
	rec        KernelLogRecord
	skip, take int
}

// Read implements SYSLOG_ACTION_READ. It returns up to size bytes of the
// records after the read position, in the text form of syslog(2), and moves the
// position. It returns a partial record when the next record does not fit and
// no byte was returned before. It returns nil when no record is unread. The
// call moves the position under the lock and formats after it.
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

// UnreadSize implements SYSLOG_ACTION_SIZE_UNREAD. It returns the bytes that
// SYSLOG_ACTION_READ can still return.
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

// LogRateLimit is the rate limit of one /dev/kmsg descriptor. It allows 10
// writes in each period of 5 seconds, as ___ratelimit of Linux does. The zero
// value allows the first writes.
type LogRateLimit struct {
	mu      sync.Mutex
	begin   time.Duration
	started bool
	printed int
	missed  int
}

// Allow reports whether a write at the time since boot may pass. A period
// starts at the first write and ends after 5 seconds. The limit counts the writes
// that it drops, and it does not reset that count at the end of a period, as
// Linux does with RATELIMIT_MSG_ON_RELEASE. Missed returns the count.
func (r *LogRateLimit) Allow(now time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		r.started = true
		r.begin = now
	}
	if now-r.begin > logRateInterval {
		r.begin = now
		r.printed = 0
	}
	if r.printed < logRateBurst {
		r.printed++
		return true
	}
	r.missed++
	return false
}

// Missed returns the number of writes that the limit dropped.
func (r *LogRateLimit) Missed() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.missed
}

// WriteDevkmsg implements a write of data to /dev/kmsg, as devkmsg_write of
// Linux does. It returns EINVAL for more than KernelLogRecordMax bytes. In the
// mode "off" it drops the data, and in the mode "ratelimit" it drops the data
// that passes the limit rl of the descriptor. Both drops succeed.
//
// The data may start with "<N>", where N is the facility shifted by three bits,
// ORed with the level. Without the prefix, the level is
// default_message_loglevel. Without a facility, the facility is LogFacilityUser.
func (l *KernelLog) WriteDevkmsg(rl *LogRateLimit, data []byte) error {
	if len(data) > KernelLogRecordMax {
		return linuxerr.EINVAL
	}
	switch l.DevkmsgMode() {
	case DevkmsgOff:
		return nil
	case DevkmsgRatelimit:
		if !rl.Allow(l.now()) {
			return nil
		}
	}
	facility, level, text := LogFacilityUser, LogDefaultLevel, string(data)
	if rest, ok := strings.CutPrefix(text, "<"); ok {
		end := 0
		var prefix uint64
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			prefix = prefix*10 + uint64(rest[end]-'0')
			end++
		}
		if end < len(rest) && rest[end] == '>' {
			prefix = uint64(uint32(prefix))
			level = int(prefix & 7)
			if f := int(prefix >> 3 & 0xff); f != 0 {
				facility = f
			}
			text = rest[end+1:]
		}
	}
	l.Emit(facility, level, text)
	return nil
}

// ReleaseDevkmsg runs when a /dev/kmsg descriptor closes. As ratelimit_state_exit
// of Linux does, it records "comm: N output lines suppressed due to
// ratelimiting" when the limit rl dropped N writes. comm names the closing
// process.
func (l *KernelLog) ReleaseDevkmsg(rl *LogRateLimit, comm string) {
	if n := rl.Missed(); n > 0 {
		l.Printkf(LogWarning, "%s: %d output lines suppressed due to ratelimiting", comm, n)
	}
}

// CanReadKernelLog reports whether creds may read the kernel log while
// kernel.dmesg_restrict is 1. Linux asks for CAP_SYSLOG in the initial user
// namespace, and it still accepts CAP_SYS_ADMIN for historical reasons.
func CanReadKernelLog(creds *auth.Credentials, k *Kernel) bool {
	root := k.RootUserNamespace()
	return creds.HasCapabilityIn(linux.CAP_SYSLOG, root) || creds.HasCapabilityIn(linux.CAP_SYS_ADMIN, root)
}

// SetKernelLogBufLen sets the size of the ring of the kernel log, in bytes. It
// must run before the first use of the log. It returns false when the log
// exists.
func (k *Kernel) SetKernelLogBufLen(bufLen int) bool {
	k.syslog.mu.Lock()
	defer k.syslog.mu.Unlock()
	if k.syslog.log != nil {
		return false
	}
	k.syslog.bufLen = bufLen
	return true
}

// KernelLog returns the kernel log of k. The first call creates it.
func (k *Kernel) KernelLog() *KernelLog {
	k.syslog.mu.Lock()
	defer k.syslog.mu.Unlock()
	if k.syslog.log == nil {
		bufLen := k.syslog.bufLen
		if bufLen == 0 {
			bufLen = KernelLogDefaultBufLen
		}
		k.syslog.log = NewKernelLog(bufLen, k.uptime)
	}
	return k.syslog.log
}

// uptime returns the time since boot. It is zero before the kernel has a
// timekeeper with clocks.
func (k *Kernel) uptime() time.Duration {
	if k.timekeeper == nil || k.timekeeper.monotonicClock == nil {
		return 0
	}
	return time.Duration(k.timekeeper.monotonicClock.Now().Nanoseconds())
}
