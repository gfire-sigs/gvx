//go:build darwin

package fdnotifier

import (
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/waiter"
)

func pipePair(t *testing.T) (r, w int32) {
	t.Helper()
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { unix.Close(fds[0]); unix.Close(fds[1]) })
	return int32(fds[0]), int32(fds[1])
}

// TestPollTranslatesLinuxBitsToDarwin polls real pipes with the Linux-format
// masks of the waiter package. EventWrNorm is 0x100 in that format. macOS reads
// 0x100 as POLLWRBAND, so an untranslated mask never reports a writable pipe.
func TestPollTranslatesLinuxBitsToDarwin(t *testing.T) {
	r, w := pipePair(t)

	if got := NonBlockingPoll(w, waiter.EventWrNorm); got != waiter.EventWrNorm {
		t.Errorf("poll of a writable pipe for EventWrNorm = %#x, want %#x", got, waiter.EventWrNorm)
	}
	if got, want := NonBlockingPoll(w, waiter.WritableEvents), waiter.WritableEvents; got != want {
		t.Errorf("poll of a writable pipe for WritableEvents = %#x, want %#x", got, want)
	}
	if got := NonBlockingPoll(r, waiter.ReadableEvents); got != 0 {
		t.Errorf("poll of an empty pipe for ReadableEvents = %#x, want 0", got)
	}

	if _, err := unix.Write(int(w), []byte("x")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := NonBlockingPoll(r, waiter.EventIn); got != waiter.EventIn {
		t.Errorf("poll of a pipe with data for EventIn = %#x, want %#x", got, waiter.EventIn)
	}
	// A request for EventRdHUp must not make the system reject the poll.
	if got := NonBlockingPoll(r, waiter.EventIn|waiter.EventRdHUp); got&waiter.EventIn == 0 {
		t.Errorf("poll with EventRdHUp lost EventIn: %#x", got)
	}

	unix.Close(int(w))
	if got := NonBlockingPoll(r, waiter.EventIn); got&waiter.EventHUp == 0 {
		t.Errorf("poll after the writer closed = %#x, want EventHUp", got)
	}
}

func TestDarwinPollMaskRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mask    waiter.EventMask
		wantReq int16
	}{
		{"in", waiter.EventIn, darwinPollIn},
		{"out and write normal share one bit", waiter.EventOut | waiter.EventWrNorm, darwinPollOut},
		{"write normal", waiter.EventWrNorm, darwinPollOut},
		{"read normal", waiter.EventRdNorm, darwinPollRdNorm},
		{"read hang-up has no bit", waiter.EventRdHUp, 0},
	} {
		if got := toDarwinPoll(tc.mask); got != tc.wantReq {
			t.Errorf("%s: toDarwinPoll(%#x) = %#x, want %#x", tc.name, tc.mask, got, tc.wantReq)
		}
	}
	if got, want := fromDarwinPoll(darwinPollOut, waiter.WritableEvents), waiter.WritableEvents; got != want {
		t.Errorf("fromDarwinPoll(POLLOUT) = %#x, want %#x", got, want)
	}
	if got := fromDarwinPoll(0x100, waiter.EventWrNorm); got != 0 {
		t.Errorf("fromDarwinPoll(POLLWRBAND) = %#x, want 0: the bit is not EventWrNorm", got)
	}
}
