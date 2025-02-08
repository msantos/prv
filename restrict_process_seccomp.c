/* Copyright (c) 2017-2025, Michael Santos <michael.santos@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include "restrict_process.h"
#ifdef RESTRICT_PROCESS_seccomp
#include <errno.h>
#include <stddef.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

/* macros from openssh-7.2/restrict_process-seccomp-filter.c */

/* Linux seccomp_filter restrict_process */
#define SECCOMP_FILTER_FAIL SECCOMP_RET_KILL

/* Use a signal handler to emit violations when debugging */
#ifdef RESTRICT_PROCESS_SECCOMP_FILTER_DEBUG
#undef SECCOMP_FILTER_FAIL
#define SECCOMP_FILTER_FAIL SECCOMP_RET_TRAP
#endif /* RESTRICT_PROCESS_SECCOMP_FILTER_DEBUG */

/* Simple helpers to avoid manual errors (but larger BPF programs). */
#define SC_DENY(_nr, _errno)                                                   \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##_nr, 0, 1)                        \
  , BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ERRNO | (_errno))
#define SC_ALLOW(_nr)                                                          \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##_nr, 0, 1)                        \
  , BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW)
#define SC_ALLOW_ARG(_nr, _arg_nr, _arg_val)                                   \
  BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_##_nr, 0, 4)                        \
  , /* load first syscall argument */                                          \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS,                                       \
               offsetof(struct seccomp_data, args[(_arg_nr)])),                \
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, (_arg_val), 0, 1),                   \
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW), /* reload syscall number;  \
                                                       all rules expect it in  \
                                                       accumulator */          \
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr))

/*
 * http://outflux.net/teach-seccomp/
 * https://github.com/gebi/teach-seccomp
 *
 */
#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))

#if defined(__i386__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_I386
#elif defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__arm__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_ARM
#elif defined(__aarch64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#warning "seccomp: unsupported platform"
#define SECCOMP_AUDIT_ARCH 0
#endif

int restrict_process_init(void) {
  struct sock_filter filter[] = {
      /* Ensure the syscall arch convention is as expected. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_FILTER_FAIL),
      /* Load the syscall number for checking. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

/* Syscalls to non-fatally deny */
#ifdef __NR__llseek
      SC_DENY(_llseek, ESPIPE),
#endif
#ifdef __NR_lseek
      SC_DENY(lseek, ESPIPE),
#endif

/* Syscalls to allow */
#ifdef __NR_prctl
      SC_ALLOW(prctl),
#endif
#ifdef __NR_brk
      SC_ALLOW(brk),
#endif
#ifdef __NR_clock_getres
      SC_ALLOW(clock_getres),
#endif
#ifdef __NR_clock_gettime
      SC_ALLOW(clock_gettime),
#endif
#ifdef __NR_close
      SC_ALLOW(close),
#endif

#ifdef __NR_exit_group
      SC_ALLOW(exit_group),
#endif

#ifdef __NR_fcntl
      SC_ALLOW(fcntl),
#endif
#ifdef __NR_fcntl64
      SC_ALLOW(fcntl64),
#endif
#ifdef __NR_fstat
      SC_ALLOW(fstat),
#endif
#ifdef __NR_fstat64
      SC_ALLOW(fstat64),
#endif
#ifdef __NR_newfstatat
      SC_ALLOW(newfstatat),
#endif
#ifdef __NR_ioctl
      SC_ALLOW(ioctl),
#endif

#ifdef __NR_gettimeofday
      SC_ALLOW(gettimeofday),
#endif

#ifdef __NR_pread
      SC_ALLOW(pread),
#endif
#ifdef __NR_preadv
      SC_ALLOW(preadv),
#endif
#ifdef __NR_pwrite
      SC_ALLOW(pwrite),
#endif
#ifdef __NR_pwritev
      SC_ALLOW(pwritev),
#endif
#ifdef __NR_read
      SC_ALLOW(read),
#endif
#ifdef __NR_readv
      SC_ALLOW(readv),
#endif

#ifdef __NR_sigaction
      SC_ALLOW(sigaction),
#endif
#ifdef __NR_sigprocmask
      SC_ALLOW(sigprocmask),
#endif
#ifdef __NR_sigreturn
      SC_ALLOW(sigreturn),
#endif

#ifdef __NR_uname
      SC_ALLOW(uname),
#endif
#ifdef __NR_write
      SC_ALLOW(write),
#endif
#ifdef __NR_writev
      SC_ALLOW(writev),
#endif

#ifdef __NR_getrandom
      SC_ALLOW(getrandom),
#endif

#ifdef __NR_restart_syscall
      SC_ALLOW(restart_syscall),
#endif

#ifdef __NR_mmap
      SC_ALLOW(mmap),
#endif
#ifdef __NR_mprotect
      SC_ALLOW(mprotect),
#endif
#ifdef __NR_munmap
      SC_ALLOW(munmap),
#endif

      /* Default deny */
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_FILTER_FAIL)};

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
    return -1;

  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}

int restrict_process_stdin(void) {
  struct sock_filter filter[] = {
      /* Ensure the syscall arch convention is as expected. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, arch)),
      BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_FILTER_FAIL),
      /* Load the syscall number for checking. */
      BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),

/* Syscalls to non-fatally deny */
#ifdef __NR__llseek
      SC_DENY(_llseek, ESPIPE),
#endif
#ifdef __NR_lseek
      SC_DENY(lseek, ESPIPE),
#endif

/* Syscalls to allow */

/* Used to test if input is file or stdin */
#ifdef __NR_fstat
      SC_ALLOW(fstat),
#endif
#ifdef __NR_fstat64
      SC_ALLOW(fstat64),
#endif
#ifdef __NR_newfstatat
      SC_ALLOW(newfstatat),
#endif
#ifdef __NR_brk
      SC_ALLOW(brk),
#endif
#ifdef __NR_ioctl
      SC_ALLOW(ioctl),
#endif

#ifdef __NR_clock_getres
      SC_ALLOW(clock_getres),
#endif
#ifdef __NR_clock_gettime
      SC_ALLOW(clock_gettime),
#endif
#ifdef __NR_close
      SC_ALLOW(close),
#endif

#ifdef __NR_exit_group
      SC_ALLOW(exit_group),
#endif

#ifdef __NR_gettimeofday
      SC_ALLOW(gettimeofday),
#endif

#ifdef __NR_pread
      SC_ALLOW(pread),
#endif
#ifdef __NR_preadv
      SC_ALLOW(preadv),
#endif
#ifdef __NR_pwrite
      SC_ALLOW(pwrite),
#endif
#ifdef __NR_pwritev
      SC_ALLOW(pwritev),
#endif
#ifdef __NR_read
      SC_ALLOW(read),
#endif
#ifdef __NR_readv
      SC_ALLOW(readv),
#endif

#ifdef __NR_sigaction
      SC_ALLOW(sigaction),
#endif
#ifdef __NR_sigprocmask
      SC_ALLOW(sigprocmask),
#endif
#ifdef __NR_sigreturn
      SC_ALLOW(sigreturn),
#endif
#ifdef __NR_write
      SC_ALLOW(write),
#endif
#ifdef __NR_writev
      SC_ALLOW(writev),
#endif

#ifdef __NR_getrandom
      SC_ALLOW(getrandom),
#endif

#ifdef __NR_restart_syscall
      SC_ALLOW(restart_syscall),
#endif

#ifdef __NR_mmap
      SC_ALLOW(mmap),
#endif
#ifdef __NR_mprotect
      SC_ALLOW(mprotect),
#endif
#ifdef __NR_munmap
      SC_ALLOW(munmap),
#endif

      /* Default deny */
      BPF_STMT(BPF_RET + BPF_K, SECCOMP_FILTER_FAIL)};

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
}
#endif
