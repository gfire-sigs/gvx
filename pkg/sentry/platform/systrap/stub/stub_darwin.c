// macOS systrap stub. It links libSystem only for dyld, fork, sigaction and
// sandbox_init. Guest threads run in the same task and execute only the
// assembly and the raw-syscall helpers in this file.

#include <mach/mach.h>
#include <mach/message.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/ucontext.h>
#include <sys/mman.h>
#include <unistd.h>

#include "gvx_stub.h"

extern void gv_text_start(void);
extern void gv_text_end(void);
extern void gv_spill(void);
extern void gv_thread_entry(void);
extern void gv_interrupt_entry(void);
extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
                                        const char *const parameters[],
                                        char **errorbuf);

_Static_assert(offsetof(struct gv_sysmsg, magic) == SM_MAGIC, "magic");
_Static_assert(offsetof(struct gv_sysmsg, state) == SM_STATE, "state");
_Static_assert(offsetof(struct gv_sysmsg, kind) == SM_KIND, "kind");
_Static_assert(offsetof(struct gv_sysmsg, stack) == SM_STACK, "stack");
_Static_assert(offsetof(struct gv_sysmsg, tls) == SM_TLS, "tls");
_Static_assert(offsetof(struct gv_sysmsg, tail) == SM_TAIL, "tail");
_Static_assert(offsetof(struct gv_sysmsg, sig) == SM_SIG, "sig");
_Static_assert(offsetof(struct gv_sysmsg, addr) == SM_ADDR, "addr");
_Static_assert(offsetof(struct gv_sysmsg, code) == SM_CODE, "code");
_Static_assert(offsetof(struct gv_sysmsg, mc) == SM_MC, "mc");
_Static_assert(offsetof(struct gv_sysmsg, cold) == SM_COLD, "cold");
_Static_assert(offsetof(struct gv_sysmsg, waiter) == SM_WAITER, "waiter");
_Static_assert(offsetof(struct gv_sysmsg, alt) == SM_ALT, "alt");
_Static_assert(offsetof(struct gv_sysmsg, x18) == SM_X18, "x18");
_Static_assert(offsetof(struct gv_sysmsg, spill) == SM_SPILL, "spill");
_Static_assert(offsetof(struct gv_sysmsg, scratch) == SM_SCRATCH, "scratch");
_Static_assert(offsetof(struct gv_sysmsg, fmc) == SM_FMC, "fmc");
_Static_assert(sizeof(struct gv_sysmsg) <= GV_SYSMSG_SIZE, "sysmsg size");
_Static_assert(sizeof(_STRUCT_MCONTEXT64) == MC_SIZE, "mcontext size");
_Static_assert(offsetof(_STRUCT_MCONTEXT64, __ss) == MC_X0, "ss");
_Static_assert(offsetof(_STRUCT_MCONTEXT64, __ns) == MC_V, "ns");
_Static_assert(offsetof(_STRUCT_MCONTEXT64, __ns.__fpsr) == MC_FPSR, "fpsr");
_Static_assert(offsetof(_STRUCT_MCONTEXT64, __ss.__pc) == MC_PC, "pc");

// Raw BSD system calls. libSystem wrappers would write errno through the
// thread pointer register, which guest threads use for their sysmsg.
static inline long raw_syscall4(long nr, long a0, long a1, long a2, long a3) {
  register long x0 __asm__("x0") = a0;
  register long x1 __asm__("x1") = a1;
  register long x2 __asm__("x2") = a2;
  register long x3 __asm__("x3") = a3;
  register long x16 __asm__("x16") = nr;
  // XNU returns a second value in x1, so x1 is an output as well.
  __asm__ volatile("svc #0x80"
                   : "+r"(x0), "+r"(x1)
                   : "r"(x2), "r"(x3), "r"(x16)
                   : "memory", "cc");
  return x0;
}

enum { SYS_ulock_wait = 515, SYS_ulock_wake = 516, UL_COMPARE_AND_WAIT_SHARED = 3 };

static inline struct gv_sysmsg *current_sysmsg(void) {
  uint64_t v;
  __asm__ volatile("mrs %0, tpidrro_el0" : "=r"(v));
  return (struct gv_sysmsg *)(v & ~7ULL);
}

static inline int is_resume_state(uint32_t s) {
  return s == GV_ST_RUN_HOT || s == GV_ST_RUN_COLD;
}

// gv_park publishes the trap reason and blocks until the Sentry resumes the
// thread. It returns the resume state.
//
// The Sentry calls ulock_wait only after it sets GV_WAITER_SENTRY and reads
// state again, so the stub calls ulock_wake only when the bit is set. The
// stub then spins for GV_SPIN_ITERS iterations, because the Sentry often
// answers a system call within that time. The stub sleeps after the spin, with
// the same protocol in the other direction: it sets GV_WAITER_STUB, reads
// state again, and calls ulock_wait only while state still holds that value.
// Every flag access is sequentially consistent, so one side always sees the
// store of the other side.
uint32_t gv_park(struct gv_sysmsg *sm, uint32_t kind) {
  sm->kind = kind;
  __atomic_store_n(&sm->state, GV_ST_TRAPPED, __ATOMIC_SEQ_CST);
  if (__atomic_load_n(&sm->waiter, __ATOMIC_SEQ_CST) & GV_WAITER_SENTRY) {
    raw_syscall4(SYS_ulock_wake, UL_COMPARE_AND_WAIT_SHARED, (long)&sm->state, 0, 0);
  }
  for (int i = 0; i < GV_SPIN_ITERS; i++) {
    uint32_t s = __atomic_load_n(&sm->state, __ATOMIC_ACQUIRE);
    if (is_resume_state(s)) {
      return s;
    }
    __asm__ volatile("yield");
  }
  for (;;) {
    __atomic_fetch_or(&sm->waiter, GV_WAITER_STUB, __ATOMIC_SEQ_CST);
    uint32_t s = __atomic_load_n(&sm->state, __ATOMIC_SEQ_CST);
    if (!is_resume_state(s)) {
      raw_syscall4(SYS_ulock_wait, UL_COMPARE_AND_WAIT_SHARED, (long)&sm->state, s, 0);
    }
    __atomic_fetch_and(&sm->waiter, ~(uint32_t)GV_WAITER_STUB, __ATOMIC_SEQ_CST);
    s = __atomic_load_n(&sm->state, __ATOMIC_ACQUIRE);
    if (is_resume_state(s)) {
      return s;
    }
  }
}

static void copy_words(uint64_t *dst, const uint64_t *src, size_t bytes) {
  for (size_t i = 0; i < bytes / 8; i++) {
    ((volatile uint64_t *)dst)[i] = src[i];
  }
}

// gv_sighandler runs on the per-thread alternate stack for every hardware
// fault, brk and illegal instruction raised by guest code. It copies the
// kernel's frame to the sysmsg, parks, and writes the Sentry's state back.
void gv_sighandler(int sig, siginfo_t *info, void *vuc) {
  ucontext_t *uc = vuc;
  struct gv_sysmsg *sm = current_sysmsg();
  if (sm->magic != GV_MAGIC) {
    __builtin_trap();
  }
  if (sm->cold != 0) {
    // Self-inflicted brk from the cold resume path: restore, do not report.
    sm->cold = 0;
  } else {
    copy_words((uint64_t *)sm->fmc, (const uint64_t *)uc->uc_mcontext, MC_SIZE);
    sm->sig = (uint64_t)sig;
    sm->addr = (uint64_t)info->si_addr;
    sm->code = (uint64_t)(int64_t)info->si_code;
    gv_park(sm, GV_KIND_SIGNAL);
  }
  // Keep the kernel-owned exception state, replace thread and NEON state.
  copy_words((uint64_t *)((char *)uc->uc_mcontext + MC_X0),
             (const uint64_t *)(sm->mc + MC_X0), MC_SIZE - MC_X0);
}

// The template forks, so it runs without a sandbox profile. The kernel allows
// one sandbox_init per process lineage, which rules out a second, stricter
// profile in the child. Each child applies the strict profile as its first
// and only one. The template runs trusted code and never hosts a guest.
static const char sandbox_child[] =
    "(version 1)\n"
    "(deny default)\n"
    "(deny syscall-unix (with send-signal SIGKILL))\n"
    "(allow syscall-unix (syscall-number 515 516 53 184))\n"
    "(deny syscall-mach (with send-signal SIGKILL))\n"
    "(allow syscall-mach (machtrap-number MSC_mach_msg_trap MSC_mach_msg2_trap "
    "MSC__kernelrpc_mach_port_deallocate_trap))\n"
    "(deny syscall-mig (with send-signal SIGKILL))\n"
    // macOS 15 counts the delivery of a guest fault to the BSD signal handler
    // as the MIG routine mach_exception_raise. Without this rule the kernel
    // kills the stub at the first guest fault.
    "(allow syscall-mig (kernel-mig-routine mach_exception_raise))\n";

static struct gv_ctl *ctl;

typedef struct {
  mach_msg_header_t h;
  mach_msg_body_t b;
  mach_msg_port_descriptor_t task;
  struct gv_hello hello;
} hello_msg_t;

static mach_port_t sentry_port;

static int send_hello(uint32_t kind, uint64_t cookie) {
  hello_msg_t m;
  memset(&m, 0, sizeof m);
  m.h.msgh_bits = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
  m.h.msgh_size = sizeof m;
  m.h.msgh_remote_port = sentry_port;
  m.h.msgh_id = 77;
  m.b.msgh_descriptor_count = 1;
  m.task.name = mach_task_self();
  m.task.disposition = MACH_MSG_TYPE_COPY_SEND;
  m.task.type = MACH_MSG_PORT_DESCRIPTOR;
  m.hello.magic = GV_HELLO_MAGIC;
  m.hello.version = GV_PROTOCOL_VERSION;
  m.hello.kind = kind;
  m.hello.cookie = cookie;
  m.hello.pid = (uint64_t)getpid();
  m.hello.ctl_addr = (uint64_t)ctl;
  m.hello.spill = (uint64_t)&gv_spill;
  m.hello.thread_entry = (uint64_t)&gv_thread_entry;
  m.hello.interrupt_entry = (uint64_t)&gv_interrupt_entry;
  m.hello.text_lo = (uint64_t)&gv_text_start;
  m.hello.text_hi = (uint64_t)&gv_text_end;
  m.hello.page_size = (uint64_t)getpagesize();
  uint64_t layout[GV_LAYOUT_WORDS] = {
      GV_SYSMSG_SIZE, SM_STATE, SM_KIND,  SM_TLS, SM_TAIL, SM_MC,
      SM_COLD,        SM_ALT,   MC_SIZE,  GV_STACK_TOP, GV_ALTSTACK_TOP, sizeof(struct gv_ctl),
      SM_X18,         SM_SPILL, SM_FMC};
  memcpy(m.hello.layout, layout, sizeof layout);
  return mach_msg(&m.h, MACH_SEND_MSG, sizeof m, 0, 0, MACH_MSG_TIMEOUT_NONE, 0);
}

// fetch_sentry_port reads the send right to the Sentry from the task's
// resource-exception registration. Mach port names do not survive fork, but
// the kernel copies the registration into the child, so the child fetches
// its own right.
static int fetch_sentry_port(void) {
  exception_mask_t masks[EXC_TYPES_COUNT];
  mach_msg_type_number_t count = EXC_TYPES_COUNT;
  mach_port_t ports[EXC_TYPES_COUNT];
  exception_behavior_t behaviors[EXC_TYPES_COUNT];
  thread_state_flavor_t flavors[EXC_TYPES_COUNT];
  if (task_get_exception_ports(mach_task_self(), EXC_MASK_RESOURCE, masks, &count,
                               ports, behaviors, flavors) != KERN_SUCCESS ||
      count < 1 || !MACH_PORT_VALID(ports[0])) {
    return -1;
  }
  sentry_port = ports[0];
  return 0;
}

static int apply_sandbox(const char *profile) {
  char *err = NULL;
  return sandbox_init_with_parameters(profile, 0, NULL, &err);
}

static int install_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))gv_sighandler;
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK | SA_NODEFER;
  sigfillset(&sa.sa_mask);
  static const int sigs[] = {SIGSEGV, SIGBUS, SIGILL, SIGTRAP, SIGFPE, SIGEMT, SIGSYS};
  for (size_t i = 0; i < sizeof sigs / sizeof sigs[0]; i++) {
    if (sigaction(sigs[i], &sa, NULL) != 0) {
      return -1;
    }
  }
  return 0;
}

// child_main runs in the forked process. It drops the channel to the Sentry
// as soon as the ready message is out.
static void child_main(uint64_t cookie) {
  // Forget the Sentry channel at the kernel level before the strict profile
  // applies, then keep only the send right that fetch_sentry_port returned.
  if (fetch_sentry_port() != 0) {
    _exit(42);
  }
  task_set_exception_ports(mach_task_self(), EXC_MASK_RESOURCE, MACH_PORT_NULL,
                           EXCEPTION_DEFAULT, 0);
  if (apply_sandbox(sandbox_child) != 0) {
    _exit(40);
  }
  if (send_hello(1, cookie) != KERN_SUCCESS) {
    _exit(41);
  }
  mach_port_deallocate(mach_task_self(), sentry_port);
  static uint32_t idle;
  for (;;) {
    raw_syscall4(SYS_ulock_wait, UL_COMPARE_AND_WAIT_SHARED, (long)&idle, 0, 0);
  }
}

int main(void) {
  if (fetch_sentry_port() != 0) {
    return 10;
  }
  if (install_handlers() != 0) {
    return 11;
  }
  signal(SIGCHLD, SIG_IGN);
  // The control page is shared with the Sentry. Forked children must not
  // inherit it, because guest code could otherwise send commands to the template.
  ctl = mmap(NULL, GV_BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
  if (ctl == MAP_FAILED || minherit(ctl, GV_BLOCK_SIZE, VM_INHERIT_NONE) != 0) {
    return 14;
  }
  if (send_hello(0, 0) != KERN_SUCCESS) {
    return 13;
  }
  uint32_t last = 0;
  const pid_t sentry_pid = getppid();
  for (;;) {
    uint32_t seq = __atomic_load_n(&ctl->seq, __ATOMIC_ACQUIRE);
    if (seq == last) {
      // A bounded wait doubles as the watchdog. When the Sentry dies, launchd
      // adopts the template. The template then ends its whole process group,
      // which holds every stub task that it forked.
      if (getppid() != sentry_pid) {
        killpg(getpgrp(), SIGKILL);
        _exit(0);
      }
      raw_syscall4(SYS_ulock_wait, UL_COMPARE_AND_WAIT_SHARED, (long)&ctl->seq, seq, 500000);
      continue;
    }
    last = seq;
    switch (ctl->cmd) {
      case GV_CMD_FORK: {
        uint64_t cookie = ctl->cookie;
        pid_t pid = fork();
        if (pid == 0) {
          child_main(cookie);
        }
        ctl->result = pid < 0 ? -1 : (int32_t)pid;
        break;
      }
      case GV_CMD_KILL: {
        // The template is the parent of every guest-hosting stub, so it is the
        // one process that may signal them after the Sentry locks itself down.
        pid_t victim = (pid_t)ctl->arg;
        ctl->result = victim > 1 && kill(victim, SIGKILL) == 0 ? 0 : -1;
        break;
      }
      case GV_CMD_EXIT:
        _exit(0);
      default:
        ctl->result = -2;
    }
    __atomic_store_n(&ctl->ack, seq, __ATOMIC_RELEASE);
    raw_syscall4(SYS_ulock_wake, UL_COMPARE_AND_WAIT_SHARED | 0x100 /* ULF_WAKE_ALL */,
                 (long)&ctl->ack, 0, 0);
  }
}
