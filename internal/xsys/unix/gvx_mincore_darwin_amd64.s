//go:build darwin && amd64

#include "textflag.h"

TEXT libc_mincore_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_mincore(SB)
GLOBL	·libc_mincore_trampoline_addr(SB), RODATA, $8
DATA	·libc_mincore_trampoline_addr(SB)/8, $libc_mincore_trampoline<>(SB)
