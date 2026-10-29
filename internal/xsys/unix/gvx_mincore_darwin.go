//go:build darwin

package unix

import "unsafe"

//go:cgo_import_dynamic libc_mincore mincore "/usr/lib/libSystem.B.dylib"

// libc_mincore_trampoline_addr is the address of the mincore trampoline in gvx_mincore_darwin_{arm64,amd64}.s.
var libc_mincore_trampoline_addr uintptr

// darwinMincore implements the Linux mincore(2) contract on top of Darwin mincore(2).
// The contract uses MincorePageSize: one result byte per page, and the start
// address must be page-aligned. Callers size the result vector with the same
// page size, so writing more entries than that overflows the caller buffer.
// Darwin reports one byte per host page, which is 16KB on Apple silicon, and
// needs a host-page-aligned address. The function queries the enclosing host
// pages and copies each host-page result to the pages that start inside it, so
// every byte comes from the kernel.
func darwinMincore(addr, length, vecAddr uintptr) Errno {
	if addr&(MincorePageSize-1) != 0 {
		return EINVAL
	}
	if length == 0 {
		return 0
	}
	hostPage := uintptr(Getpagesize())
	base := addr &^ (hostPage - 1)
	span := (addr + length - base + hostPage - 1) &^ (hostPage - 1)
	resident := make([]byte, span/hostPage)
	if _, _, errno := syscall_syscall(libc_mincore_trampoline_addr, base, span, uintptr(unsafe.Pointer(&resident[0]))); errno != 0 {
		return errno
	}
	pages := (length + MincorePageSize - 1) / MincorePageSize
	vec := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&vecAddr))), pages)
	for i := range vec {
		vec[i] = resident[(addr-base+uintptr(i)*MincorePageSize)/hostPage]
	}
	return 0
}
