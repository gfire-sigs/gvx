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

//go:build linux && cgo

// Package rseqarea finds the rseq area that the C library registered for the
// calling thread. A package that uses cgo cannot hold Go assembly, so the
// lookup lives outside package systrap.
package rseqarea

/*
#include <stddef.h>

// glibc 2.35 and later export the place of the rseq area of each thread. The
// references are weak, so that a C library without them links.
extern const ptrdiff_t __rseq_offset __attribute__((weak));
extern const unsigned int __rseq_size __attribute__((weak));

// gvx_thread_pointer reads the thread pointer. GCC before 11 has no
// __builtin_thread_pointer on x86, so the function reads the register.
static void *gvx_thread_pointer(void) {
	void *tp;
#if defined(__x86_64__)
	__asm__("mov %%fs:0, %0" : "=r"(tp));
#elif defined(__aarch64__)
	__asm__("mrs %0, tpidr_el0" : "=r"(tp));
#else
	tp = __builtin_thread_pointer();
#endif
	return tp;
}

static void gvx_rseq_area(void **area, unsigned int *size) {
	*area = NULL;
	*size = 0;
	if (&__rseq_size == NULL || &__rseq_offset == NULL || __rseq_size == 0) {
		return;
	}
	*area = (char *)gvx_thread_pointer() + __rseq_offset;
	*size = __rseq_size;
}
*/
import "C"

import "unsafe"

// Thread returns the rseq area that the C library registered for the calling
// thread, and its length. It returns a zero length when the C library
// registers none.
//
// Precondition: the runtime OS thread must be locked.
func Thread() (uintptr, uint32) {
	var area unsafe.Pointer
	var size C.uint
	C.gvx_rseq_area(&area, &size)
	return uintptr(area), uint32(size)
}
