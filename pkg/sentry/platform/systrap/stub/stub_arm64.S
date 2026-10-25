// Spill and reload code of the macOS systrap stub for arm64.
// Island slots branch to gv_spill with the guest x16 and x17 saved in
// sm->scratch and x17 holding the slot tail address.

#include "gvx_stub.h"

.text
.p2align 4

.globl _gv_text_start
_gv_text_start:

// gv_spill saves the whole guest context into the sysmsg and parks the thread.
.globl _gv_spill
_gv_spill:
    mrs   x16, TPIDRRO_EL0
    and   x16, x16, #0xfffffffffffffff8
    stp   x0, x1, [x16, #(SM_MC+MC_X0+0)]
    ldr   x0, [x16, #SM_SCRATCH]
    ldr   x1, [x16, #(SM_SCRATCH+8)]
    stp   x0, x1, [x16, #(SM_MC+MC_X0+16*8)]
    str   x17, [x16, #SM_TAIL]
    stp   x2, x3, [x16, #(SM_MC+MC_X0+2*8)]
    stp   x4, x5, [x16, #(SM_MC+MC_X0+4*8)]
    stp   x6, x7, [x16, #(SM_MC+MC_X0+6*8)]
    stp   x8, x9, [x16, #(SM_MC+MC_X0+8*8)]
    stp   x10, x11, [x16, #(SM_MC+MC_X0+10*8)]
    stp   x12, x13, [x16, #(SM_MC+MC_X0+12*8)]
    stp   x14, x15, [x16, #(SM_MC+MC_X0+14*8)]
    stp   x18, x19, [x16, #(SM_MC+MC_X0+18*8)]
    stp   x20, x21, [x16, #(SM_MC+MC_X0+20*8)]
    stp   x22, x23, [x16, #(SM_MC+MC_X0+22*8)]
    stp   x24, x25, [x16, #(SM_MC+MC_X0+24*8)]
    stp   x26, x27, [x16, #(SM_MC+MC_X0+26*8)]
    stp   x28, x29, [x16, #(SM_MC+MC_X0+28*8)]
    str   x30, [x16, #(SM_MC+MC_LR)]
    mov   x0, sp
    str   x0, [x16, #(SM_MC+MC_SP)]
    mrs   x0, nzcv
    str   w0, [x16, #(SM_MC+MC_CPSR)]
    mrs   x0, fpsr
    mrs   x1, fpcr
    str   w0, [x16, #(SM_MC+MC_FPSR)]
    str   w1, [x16, #(SM_MC+MC_FPCR)]
    stp   q0, q1, [x16, #(SM_MC+MC_V+0*16)]
    stp   q2, q3, [x16, #(SM_MC+MC_V+2*16)]
    stp   q4, q5, [x16, #(SM_MC+MC_V+4*16)]
    stp   q6, q7, [x16, #(SM_MC+MC_V+6*16)]
    stp   q8, q9, [x16, #(SM_MC+MC_V+8*16)]
    stp   q10, q11, [x16, #(SM_MC+MC_V+10*16)]
    stp   q12, q13, [x16, #(SM_MC+MC_V+12*16)]
    stp   q14, q15, [x16, #(SM_MC+MC_V+14*16)]
    stp   q16, q17, [x16, #(SM_MC+MC_V+16*16)]
    stp   q18, q19, [x16, #(SM_MC+MC_V+18*16)]
    stp   q20, q21, [x16, #(SM_MC+MC_V+20*16)]
    stp   q22, q23, [x16, #(SM_MC+MC_V+22*16)]
    stp   q24, q25, [x16, #(SM_MC+MC_V+24*16)]
    stp   q26, q27, [x16, #(SM_MC+MC_V+26*16)]
    stp   q28, q29, [x16, #(SM_MC+MC_V+28*16)]
    stp   q30, q31, [x16, #(SM_MC+MC_V+30*16)]
    ldr   x0, [x16, #SM_STACK]
    mov   sp, x0
    mov   x0, x16
    mov   w1, #GV_KIND_SYSCALL
    bl    _gv_park
    cmp   w0, #GV_ST_RUN_HOT
    b.ne  Lcold
    mrs   x16, TPIDRRO_EL0
    and   x16, x16, #0xfffffffffffffff8
    // Hot reload: only x0 may differ from the spilled state. The guest x16 and x17
    // still sit in the scratch words of the sysmsg, where the slot stored them.
    ldr   w0, [x16, #(SM_MC+MC_FPSR)]
    ldr   w1, [x16, #(SM_MC+MC_FPCR)]
    msr   fpsr, x0
    msr   fpcr, x1
    ldp   q0, q1, [x16, #(SM_MC+MC_V+0*16)]
    ldp   q2, q3, [x16, #(SM_MC+MC_V+2*16)]
    ldp   q4, q5, [x16, #(SM_MC+MC_V+4*16)]
    ldp   q6, q7, [x16, #(SM_MC+MC_V+6*16)]
    ldp   q8, q9, [x16, #(SM_MC+MC_V+8*16)]
    ldp   q10, q11, [x16, #(SM_MC+MC_V+10*16)]
    ldp   q12, q13, [x16, #(SM_MC+MC_V+12*16)]
    ldp   q14, q15, [x16, #(SM_MC+MC_V+14*16)]
    ldp   q16, q17, [x16, #(SM_MC+MC_V+16*16)]
    ldp   q18, q19, [x16, #(SM_MC+MC_V+18*16)]
    ldp   q20, q21, [x16, #(SM_MC+MC_V+20*16)]
    ldp   q22, q23, [x16, #(SM_MC+MC_V+22*16)]
    ldp   q24, q25, [x16, #(SM_MC+MC_V+24*16)]
    ldp   q26, q27, [x16, #(SM_MC+MC_V+26*16)]
    ldp   q28, q29, [x16, #(SM_MC+MC_V+28*16)]
    ldp   q30, q31, [x16, #(SM_MC+MC_V+30*16)]
    ldr   w0, [x16, #(SM_MC+MC_CPSR)]
    msr   nzcv, x0
    ldr   x0, [x16, #(SM_MC+MC_SP)]
    mov   sp, x0
    ldp   x0, x1, [x16, #(SM_MC+MC_X0+0)]
    ldp   x2, x3, [x16, #(SM_MC+MC_X0+2*8)]
    ldp   x4, x5, [x16, #(SM_MC+MC_X0+4*8)]
    ldp   x6, x7, [x16, #(SM_MC+MC_X0+6*8)]
    ldp   x8, x9, [x16, #(SM_MC+MC_X0+8*8)]
    ldp   x10, x11, [x16, #(SM_MC+MC_X0+10*8)]
    ldp   x12, x13, [x16, #(SM_MC+MC_X0+12*8)]
    ldp   x14, x15, [x16, #(SM_MC+MC_X0+14*8)]
    ldp   x18, x19, [x16, #(SM_MC+MC_X0+18*8)]
    ldp   x20, x21, [x16, #(SM_MC+MC_X0+20*8)]
    ldp   x22, x23, [x16, #(SM_MC+MC_X0+22*8)]
    ldp   x24, x25, [x16, #(SM_MC+MC_X0+24*8)]
    ldp   x26, x27, [x16, #(SM_MC+MC_X0+26*8)]
    ldp   x28, x29, [x16, #(SM_MC+MC_X0+28*8)]
    ldr   x30, [x16, #(SM_MC+MC_LR)]
    ldr   x17, [x16, #SM_TAIL]
    br    x17

// A cold resume traps with brk so the signal handler restores the full state.
Lcold:
    mrs   x16, TPIDRRO_EL0
    and   x16, x16, #0xfffffffffffffff8
    mov   w0, #1
    str   w0, [x16, #SM_COLD]
    brk   #0x5e1f

// gv_thread_entry starts a guest thread. The Sentry passes the sysmsg in x16
// and the private stack in sp.
.globl _gv_thread_entry
_gv_thread_entry:
    mov   x19, x16
    mov   x0, x19
    mov   x3, #2
    mov   x16, #0x80000000
    svc   #0x80
    add   x0, x19, #SM_ALT
    mov   x1, #0
    mov   x16, #53
    svc   #0x80
    mov   x0, x19
    mov   w1, #GV_KIND_START
    bl    _gv_park
    mov   x16, x19
    b     Lcold

// gv_interrupt_entry replaces the guest PC after the Sentry saved the guest
// state into the sysmsg. The Sentry passes the sysmsg in x16 and the private
// stack in sp.
.globl _gv_interrupt_entry
_gv_interrupt_entry:
    mov   x19, x16
    mov   x0, x19
    mov   w1, #GV_KIND_INTERRUPT
    bl    _gv_park
    mov   x16, x19
    b     Lcold

.globl _gv_text_end
_gv_text_end:
