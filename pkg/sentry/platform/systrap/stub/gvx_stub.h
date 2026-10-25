// Shared layout between the macOS systrap stub and the Sentry.
// The Go side mirrors every constant in sysmsg_darwin_arm64.go and checks
// them against the layout table in the hello message at startup.

#ifndef GVX_STUB_H
#define GVX_STUB_H

// Host page size and per-thread span. The span holds the sysmsg at offset 0,
// the private stack below GV_STACK_TOP and the signal alternate stack, which
// the kernel requires to span at least MINSIGSTKSZ (32KB) bytes.
#define GV_BLOCK_SIZE 0x4000
#define GV_THREAD_SPAN 0x10000
#define GV_SYSMSG_SIZE 0x800
#define GV_STACK_TOP 0x1400
#define GV_ALTSTACK_BASE 0x4000
#define GV_ALTSTACK_SIZE 0xc000
#define GV_ALTSTACK_TOP 0x10000

// Offsets inside struct gv_sysmsg (arm64).
#define SM_MAGIC 0
#define SM_STATE 8
#define SM_KIND 12
#define SM_STACK 16
#define SM_TLS 24
#define SM_TAIL 32
#define SM_SIG 40
#define SM_ADDR 48
#define SM_CODE 56
#define SM_MC 64
#define SM_COLD 880
#define SM_WAITER 884
#define SM_ALT 888
#define SM_X18 912
#define SM_SPILL 920
#define SM_SCRATCH 928
#define SM_FMC 944

// Offsets inside the Darwin mcontext64 that follows SM_MC.
#define MC_FAR 0
#define MC_ESR 8
#define MC_X0 16
#define MC_FP 248
#define MC_LR 256
#define MC_SP 264
#define MC_PC 272
#define MC_CPSR 280
#define MC_V 288
#define MC_FPSR 800
#define MC_FPCR 804
#define MC_SIZE 816

// Protocol states of gv_sysmsg.state.
#define GV_ST_NEW 0
#define GV_ST_TRAPPED 2
#define GV_ST_RUN_HOT 3
#define GV_ST_RUN_COLD 4

// Bits of gv_sysmsg.waiter. The Sentry sets GV_WAITER_SENTRY while it sleeps
// on state, and the stub sets GV_WAITER_STUB while it sleeps on state.
#define GV_WAITER_SENTRY 1
#define GV_WAITER_STUB 2

// Iterations of the spin loop of the stub before it sleeps.
#define GV_SPIN_ITERS 1024

// Reasons that gv_sysmsg.kind reports when the state becomes TRAPPED.
#define GV_KIND_START 1
#define GV_KIND_SYSCALL 2
#define GV_KIND_SIGNAL 3
#define GV_KIND_INTERRUPT 4

#define GV_MAGIC 0x3174737876673031ULL
#define GV_HELLO_MAGIC 0x6f6c6c6568767667ULL
#define GV_PROTOCOL_VERSION 1

// Control commands for the template process.
#define GV_CMD_FORK 1
#define GV_CMD_EXIT 2
#define GV_CMD_KILL 3

#ifndef __ASSEMBLER__

#include <stdint.h>

struct gv_sysmsg {
  uint64_t magic;
  uint32_t state;
  uint32_t kind;
  uint64_t stack;
  uint64_t tls;
  uint64_t tail;
  uint64_t sig;
  uint64_t addr;
  uint64_t code;
  // Darwin _STRUCT_MCONTEXT64 (816 bytes).
  uint8_t mc[MC_SIZE];
  uint32_t cold;
  // Bits that tell the other side to call ulock_wake. A side sets its bit
  // before it sleeps on state, and it clears the bit when it wakes.
  uint32_t waiter;
  uint64_t alt[3];
  // The guest x18. The kernel zeroes the real x18 whenever the thread returns
  // from an exception, so patched code keeps the guest value here.
  uint64_t x18;
  // Holds the guest scratch register that a patched x18 slot borrows.
  uint64_t spill;
  // Holds the guest x16 and x17 that a trap or memory slot spills.
  uint64_t scratch[2];
  // The signal handler saves the context of a fault here, so a fault inside
  // the reload code cannot destroy the guest state in mc.
  uint8_t fmc[MC_SIZE];
};

struct gv_ctl {
  uint32_t seq;
  uint32_t ack;
  uint32_t cmd;
  int32_t result;
  uint64_t cookie;
  uint64_t arg;
};

#define GV_LAYOUT_WORDS 15

struct gv_hello {
  uint64_t magic;
  uint32_t version;
  uint32_t kind;  // 0 = template, 1 = forked child.
  uint64_t cookie;
  uint64_t pid;
  uint64_t ctl_addr;
  uint64_t spill;
  uint64_t thread_entry;
  uint64_t interrupt_entry;
  uint64_t text_lo;
  uint64_t text_hi;
  uint64_t page_size;
  uint64_t layout[GV_LAYOUT_WORDS];
};

#endif
#endif
