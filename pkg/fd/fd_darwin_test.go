//go:build darwin

package fd

import (
	"testing"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

func TestHostHandleDupSetsCloseOnExec(t *testing.T) {
	t.Parallel()
	h := openTemp(t, "cloexec.bin")
	dup, err := h.Dup()
	if err != nil {
		t.Fatalf("Dup: %v", err)
	}
	defer dup.Close()
	raw, err := dup.RawHandle()
	if err != nil {
		t.Fatalf("RawHandle: %v", err)
	}
	flags, err := unix.FcntlInt(raw, unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("duplicate flags = %#x, want FD_CLOEXEC", flags)
	}
}
