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
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/waiter"
)

// logClock is a clock that tests advance by hand.
type logClock struct{ now time.Duration }

func (c *logClock) read() time.Duration { return c.now }

func newTestLog(bufLen int) (*KernelLog, *logClock) {
	c := &logClock{}
	return NewKernelLog(bufLen, c.read), c
}

// texts returns the texts of all records from seq on.
func texts(l *KernelLog, seq uint64) []string {
	var out []string
	for {
		rec, ok := l.Lookup(seq)
		if !ok {
			return out
		}
		out = append(out, rec.Text)
		seq = rec.Seq + 1
	}
}

func TestKernelLogBufLenRoundsUpToPowerOfTwo(t *testing.T) {
	tests := []struct{ ask, want int }{
		{0, KernelLogMinBufLen},
		{1, KernelLogMinBufLen},
		{5000, 8192},
		{KernelLogDefaultBufLen, KernelLogDefaultBufLen},
		{KernelLogDefaultBufLen + 1, KernelLogDefaultBufLen * 2},
		{1 << 40, KernelLogMaxBufLen},
	}
	for _, tc := range tests {
		if got := NewKernelLog(tc.ask, nil).BufLen(); got != tc.want {
			t.Errorf("NewKernelLog(%d).BufLen() = %d, want %d", tc.ask, got, tc.want)
		}
	}
}

func TestKernelLogAssignsConsecutiveSequenceNumbersFromZero(t *testing.T) {
	l, clock := newTestLog(KernelLogDefaultBufLen)
	clock.now = 1500 * time.Microsecond
	l.Printk(LogInfo, "one")
	clock.now = 2 * time.Second
	l.Emit(LogFacilityUser, LogErr, "two")

	rec, ok := l.Lookup(0)
	if !ok || rec.Seq != 0 || rec.Text != "one" || rec.Time != 1500*time.Microsecond || rec.Facility != LogFacilityKern || rec.Level != LogInfo {
		t.Errorf("record 0 = %+v, %v", rec, ok)
	}
	rec, ok = l.Lookup(1)
	if !ok || rec.Seq != 1 || rec.Text != "two" || rec.Priority() != LogFacilityUser<<3|LogErr {
		t.Errorf("record 1 = %+v, %v", rec, ok)
	}
	if _, ok := l.Lookup(2); ok {
		t.Errorf("Lookup(2) found a record that does not exist")
	}
	if l.FirstSeq() != 0 || l.NextSeq() != 2 {
		t.Errorf("FirstSeq, NextSeq = %d, %d, want 0, 2", l.FirstSeq(), l.NextSeq())
	}
}

func TestKernelLogSplitsLinesAndDropsOneTrailingNewline(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.Printk(LogInfo, "a\nb\n")
	l.Printk(LogInfo, "c\n\n")
	l.Printk(LogInfo, "\n")
	l.Printk(LogInfo, "")
	want := []string{"a", "b", "c", "", "", ""}
	if got := texts(l, 0); strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("records = %q, want %q", got, want)
	}
}

func TestKernelLogTruncatesALongLine(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.Printk(LogInfo, strings.Repeat("x", 5000))
	rec, _ := l.Lookup(0)
	if len(rec.Text) != KernelLogRecordMax {
		t.Errorf("len(Text) = %d, want %d", len(rec.Text), KernelLogRecordMax)
	}
}

func TestKernelLogDropsTheOldestRecordsWhenTheDataRingIsFull(t *testing.T) {
	l, _ := newTestLog(KernelLogMinBufLen)
	// Each record uses (1000+8) bytes. The ring of 4096 bytes holds 4 of them.
	text := strings.Repeat("x", 1000)
	for i := 0; i < 10; i++ {
		l.Printk(LogInfo, text)
	}
	if first, next := l.FirstSeq(), l.NextSeq(); first != 6 || next != 10 {
		t.Errorf("FirstSeq, NextSeq = %d, %d, want 6, 10", first, next)
	}
	rec, ok := l.Lookup(0)
	if !ok || rec.Seq != 6 {
		t.Errorf("Lookup(0) = seq %d, %v, want the oldest record, seq 6", rec.Seq, ok)
	}
}

func TestKernelLogLimitsTheNumberOfRecords(t *testing.T) {
	l, _ := newTestLog(KernelLogMinBufLen)
	// The ring has one descriptor for each 32 bytes. An empty record uses 8
	// bytes, so the descriptors are the limit.
	for i := 0; i < 1000; i++ {
		l.Printk(LogInfo, "")
	}
	if got, want := l.NextSeq()-l.FirstSeq(), uint64(KernelLogMinBufLen/32); got != want {
		t.Errorf("live records = %d, want %d", got, want)
	}
}

func TestKernelLogKeepsSequenceNumbersAcrossManyWraps(t *testing.T) {
	l, _ := newTestLog(KernelLogMinBufLen)
	for i := 0; i < 5000; i++ {
		l.Printk(LogInfo, fmt.Sprintf("line %d", i))
	}
	first := l.FirstSeq()
	rec, ok := l.Lookup(first)
	if !ok || rec.Seq != first || rec.Text != fmt.Sprintf("line %d", first) {
		t.Fatalf("oldest record = %+v, %v", rec, ok)
	}
	last, _ := l.Lookup(l.NextSeq() - 1)
	if last.Text != "line 4999" {
		t.Errorf("newest text = %q, want line 4999", last.Text)
	}
}

func TestKernelLogNotifiesWaitersOfANewRecord(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	e, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := l.EventRegister(&e); err != nil {
		t.Fatal(err)
	}
	defer l.EventUnregister(&e)
	select {
	case <-ch:
		t.Fatal("notified before any record")
	default:
	}
	l.Printk(LogInfo, "x")
	select {
	case <-ch:
	default:
		t.Error("a new record did not notify the waiter")
	}
}

func TestKernelLogKmsgFormat(t *testing.T) {
	rec := KernelLogRecord{Seq: 339, Time: 5140900 * time.Microsecond, Facility: LogFacilityKern, Level: LogInfo, Text: "NET: Registered protocol family 10"}
	if got, want := string(rec.AppendKmsg(nil)), "6,339,5140900,-;NET: Registered protocol family 10\n"; got != want {
		t.Errorf("AppendKmsg = %q, want %q", got, want)
	}
	rec = KernelLogRecord{Seq: 1, Time: 1999 * time.Nanosecond, Facility: LogFacilityUser, Level: LogErr, Text: "tab\there \\ é\x7f"}
	want := "11,1,1,-;tab\\x09here \\x5c \\xc3\\xa9\\x7f\n"
	if got := string(rec.AppendKmsg(nil)); got != want {
		t.Errorf("AppendKmsg = %q, want %q", got, want)
	}
}

func TestKernelLogSyslogFormat(t *testing.T) {
	rec := KernelLogRecord{Time: 12*time.Second + 345*time.Microsecond, Facility: LogFacilityKern, Level: LogWarning, Text: "hello"}
	if got, want := string(rec.AppendSyslog(nil)), "<4>[   12.000345] hello\n"; got != want {
		t.Errorf("AppendSyslog = %q, want %q", got, want)
	}
	rec = KernelLogRecord{Time: 123456 * time.Second, Facility: LogFacilityUser, Level: LogNotice, Text: "late"}
	if got, want := string(rec.AppendSyslog(nil)), "<13>[123456.000000] late\n"; got != want {
		t.Errorf("AppendSyslog = %q, want %q", got, want)
	}
}

func TestWriteDevkmsgParsesThePrefix(t *testing.T) {
	tests := []struct {
		name         string
		data         string
		wantPriority int
		wantText     string
	}{
		{"no prefix gets user facility and level 4", "hello\n", LogFacilityUser<<3 | 4, "hello"},
		{"level only keeps the user facility", "<2>boom", LogFacilityUser<<3 | 2, "boom"},
		{"facility and level", "<30>daemon says", 3<<3 | 6, "daemon says"},
		{"facility 0 becomes user", "<6>x", LogFacilityUser<<3 | 6, "x"},
		{"empty digits count as zero", "<>x", LogFacilityUser<<3 | 0, "x"},
		{"no closing bracket keeps the text", "<6 x", LogFacilityUser<<3 | 4, "<6 x"},
		{"non digit keeps the text", "<a>x", LogFacilityUser<<3 | 4, "<a>x"},
		{"facility above 255 wraps", "<2048>x", LogFacilityUser<<3 | 0, "x"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, _ := newTestLog(KernelLogDefaultBufLen)
			l.SetDevkmsgMode(DevkmsgOn)
			if err := l.WriteDevkmsg(&LogRateLimit{}, "sh", []byte(tc.data)); err != nil {
				t.Fatal(err)
			}
			rec, ok := l.Lookup(0)
			if !ok || rec.Priority() != tc.wantPriority || rec.Text != tc.wantText {
				t.Errorf("record = priority %d, %q (found %v), want priority %d, %q", rec.Priority(), rec.Text, ok, tc.wantPriority, tc.wantText)
			}
		})
	}
}

func TestWriteDevkmsgUsesDefaultMessageLogLevel(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.SetLevels([4]int{7, 2, 1, 7})
	if err := l.WriteDevkmsg(&LogRateLimit{}, "sh", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if rec, _ := l.Lookup(0); rec.Level != 2 {
		t.Errorf("level = %d, want 2", rec.Level)
	}
}

func TestWriteDevkmsgSplitsAtNewlines(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	if err := l.WriteDevkmsg(&LogRateLimit{}, "sh", []byte("<5>a\nb\nc\n")); err != nil {
		t.Fatal(err)
	}
	if got := texts(l, 0); strings.Join(got, "|") != "a|b|c" {
		t.Errorf("records = %q, want a, b, c", got)
	}
	for seq := uint64(0); seq < 3; seq++ {
		if rec, _ := l.Lookup(seq); rec.Level != 5 {
			t.Errorf("record %d has level %d, want 5", seq, rec.Level)
		}
	}
}

func TestWriteDevkmsgRejectsMoreThanOneRecordOfBytes(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	err := l.WriteDevkmsg(&LogRateLimit{}, "sh", make([]byte, KernelLogRecordMax+1))
	if !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Errorf("WriteDevkmsg(1025 bytes) = %v, want EINVAL", err)
	}
	if err := l.WriteDevkmsg(&LogRateLimit{}, "sh", make([]byte, KernelLogRecordMax)); err != nil {
		t.Errorf("WriteDevkmsg(1024 bytes) = %v, want nil", err)
	}
}

func TestWriteDevkmsgOffDropsTheWriteAndSucceeds(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.SetDevkmsgMode(DevkmsgOff)
	if err := l.WriteDevkmsg(&LogRateLimit{}, "sh", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if l.NextSeq() != 0 {
		t.Errorf("a write in the mode off made a record")
	}
}

func TestWriteDevkmsgRateLimitAllowsTenWritesInFiveSeconds(t *testing.T) {
	l, clock := newTestLog(KernelLogDefaultBufLen)
	rl := &LogRateLimit{}
	for i := 0; i < 15; i++ {
		if err := l.WriteDevkmsg(rl, "sh", []byte(fmt.Sprintf("w%d", i))); err != nil {
			t.Fatal(err)
		}
		clock.now += 100 * time.Millisecond
	}
	if got := texts(l, 0); len(got) != 10 || got[9] != "w9" {
		t.Fatalf("records = %q, want w0 to w9", got)
	}

	// The next period starts after 5 seconds. The write reports the 5 drops.
	clock.now = 5*time.Second + time.Millisecond
	if err := l.WriteDevkmsg(rl, "sh", []byte("again")); err != nil {
		t.Fatal(err)
	}
	got := texts(l, 0)
	if len(got) != 12 || got[10] != "sh: 5 callbacks suppressed" || got[11] != "again" {
		t.Errorf("records after the period = %q", got[10:])
	}
	if rec, _ := l.Lookup(10); rec.Facility != LogFacilityKern || rec.Level != LogWarning {
		t.Errorf("the notice has facility %d level %d, want kernel warning", rec.Facility, rec.Level)
	}
}

func TestWriteDevkmsgRateLimitIsPerDescriptor(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	a, b := &LogRateLimit{}, &LogRateLimit{}
	for i := 0; i < 10; i++ {
		_ = l.WriteDevkmsg(a, "sh", []byte("a"))
	}
	_ = l.WriteDevkmsg(a, "sh", []byte("dropped"))
	_ = l.WriteDevkmsg(b, "sh", []byte("b"))
	got := texts(l, 0)
	if len(got) != 11 || got[10] != "b" {
		t.Errorf("records = %q, want ten a and one b", got)
	}
}

func TestWriteDevkmsgOnIgnoresTheRateLimit(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.SetDevkmsgMode(DevkmsgOn)
	rl := &LogRateLimit{}
	for i := 0; i < 50; i++ {
		_ = l.WriteDevkmsg(rl, "sh", []byte("x"))
	}
	if l.NextSeq() != 50 {
		t.Errorf("records = %d, want 50", l.NextSeq())
	}
}

func TestParseDevkmsgMode(t *testing.T) {
	for text, want := range map[string]DevkmsgMode{"on": DevkmsgOn, "off\n": DevkmsgOff, "ratelimit": DevkmsgRatelimit} {
		got, ok := ParseDevkmsgMode(text)
		if !ok || got != want || got.String() != strings.TrimSuffix(text, "\n") {
			t.Errorf("ParseDevkmsgMode(%q) = %v, %v, want %v", text, got, ok, want)
		}
	}
	for _, text := range []string{"", "ON", "yes", "on off", " on"} {
		if _, ok := ParseDevkmsgMode(text); ok {
			t.Errorf("ParseDevkmsgMode(%q) accepted the text", text)
		}
	}
}

func TestReadAllReturnsTheNewestRecordsThatFit(t *testing.T) {
	l, clock := newTestLog(KernelLogDefaultBufLen)
	for i := 1; i <= 3; i++ {
		clock.now = time.Duration(i) * time.Second
		l.Printk(LogInfo, fmt.Sprintf("m%d", i))
	}
	all := "<6>[    1.000000] m1\n<6>[    2.000000] m2\n<6>[    3.000000] m3\n"
	if got := string(l.ReadAll(1000, false)); got != all {
		t.Errorf("ReadAll(1000) = %q, want %q", got, all)
	}
	lineLen := len("<6>[    1.000000] m1\n")
	if got, want := string(l.ReadAll(2*lineLen+3, false)), all[lineLen:]; got != want {
		t.Errorf("ReadAll(small) = %q, want the last two records %q", got, want)
	}
	if got := l.ReadAll(lineLen-1, false); len(got) != 0 {
		t.Errorf("ReadAll(smaller than a record) = %q, want nothing", got)
	}
	if got := string(l.ReadAll(1000, false)); got != all {
		t.Errorf("ReadAll changed the log: %q", got)
	}
}

func TestClearHidesRecordsFromReadAllButKeepsThem(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.Printk(LogInfo, "old")
	l.Clear()
	if got := l.ReadAll(1000, false); len(got) != 0 {
		t.Errorf("ReadAll after Clear = %q, want nothing", got)
	}
	if l.ClearSeq() != 1 {
		t.Errorf("ClearSeq = %d, want 1", l.ClearSeq())
	}
	if _, ok := l.Lookup(0); !ok {
		t.Errorf("Clear removed the record")
	}
	l.Printk(LogInfo, "new")
	if got := string(l.ReadAll(1000, false)); !strings.HasSuffix(got, "new\n") || strings.Contains(got, "old") {
		t.Errorf("ReadAll = %q, want only new", got)
	}
}

func TestReadAllWithClearClearsTheLog(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.Printk(LogInfo, "a")
	if got := l.ReadAll(1000, true); len(got) == 0 {
		t.Fatal("ReadAll(clear) returned nothing")
	}
	if got := l.ReadAll(1000, false); len(got) != 0 {
		t.Errorf("ReadAll after READ_CLEAR = %q, want nothing", got)
	}
}

func TestReadConsumesRecordsAndReturnsAPartialRecord(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	l.Printk(LogInfo, "ab")
	l.Printk(LogInfo, "cd")
	line := "<6>[    0.000000] ab\n"
	if l.UnreadSize() != 2*len(line) {
		t.Fatalf("UnreadSize = %d, want %d", l.UnreadSize(), 2*len(line))
	}
	// Ten bytes of the first record, then its rest, then the whole second one.
	if got := string(l.Read(10)); got != line[:10] {
		t.Errorf("Read(10) = %q, want %q", got, line[:10])
	}
	if l.UnreadSize() != 2*len(line)-10 {
		t.Errorf("UnreadSize = %d, want %d", l.UnreadSize(), 2*len(line)-10)
	}
	if got := string(l.Read(1000)); got != line[10:]+strings.ReplaceAll(line, "ab", "cd") {
		t.Errorf("Read(1000) = %q", got)
	}
	if l.UnreadSize() != 0 || len(l.Read(100)) != 0 {
		t.Errorf("the log has unread bytes after a full read")
	}
	l.Printk(LogInfo, "ef")
	if l.UnreadSize() != len(line) {
		t.Errorf("UnreadSize after a new record = %d, want %d", l.UnreadSize(), len(line))
	}
}

func TestReadSkipsRecordsThatLeftTheRing(t *testing.T) {
	l, _ := newTestLog(KernelLogMinBufLen)
	text := strings.Repeat("x", 1000)
	for i := 0; i < 10; i++ {
		l.Printk(LogInfo, text)
	}
	got := l.Read(1 << 20)
	if n := strings.Count(string(got), "\n"); n != 4 {
		t.Errorf("Read returned %d records, want the 4 that remain", n)
	}
}

func TestConsoleLevels(t *testing.T) {
	l, _ := newTestLog(KernelLogDefaultBufLen)
	if got := l.Levels(); got != [4]int{7, 4, 1, 7} {
		t.Fatalf("Levels = %v, want 7 4 1 7", got)
	}
	l.ConsoleOff()
	if got := l.Levels()[0]; got != 1 {
		t.Errorf("console level after ConsoleOff = %d, want 1", got)
	}
	l.ConsoleOn()
	if got := l.Levels()[0]; got != 7 {
		t.Errorf("console level after ConsoleOn = %d, want 7", got)
	}
	if !l.SetConsoleLevel(3) || l.Levels()[0] != 3 {
		t.Errorf("SetConsoleLevel(3) left level %d", l.Levels()[0])
	}
	if l.SetConsoleLevel(0) || l.SetConsoleLevel(9) {
		t.Errorf("SetConsoleLevel accepted a level outside 1 to 8")
	}
	if l.Levels()[0] != 3 {
		t.Errorf("a rejected level changed the console level to %d", l.Levels()[0])
	}
	l.SetLevels([4]int{5, 4, 2, 7})
	if !l.SetConsoleLevel(1) || l.Levels()[0] != 2 {
		t.Errorf("a level below the minimum gave %d, want the minimum 2", l.Levels()[0])
	}
}
