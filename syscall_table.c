#define _GNU_SOURCE
#include "syscall_table.h"
#include <stddef.h>
#include <sys/syscall.h>

// Helper macros to define syscalls easily
#define A_INT {ARG_INT, TYPE_NONE}
#define A_HEX {ARG_HEX, TYPE_NONE}
#define A_PTR {ARG_PTR, TYPE_NONE}
#define A_STR {ARG_STRING, TYPE_NONE}
#define A_FD {ARG_FD, TYPE_NONE}
#define A_BUF(len_idx) {ARG_BUFFER, len_idx}
#define A_BUF_NO_LEN {ARG_BUFFER, -1}
#define A_FLG(t) {ARG_BITMASK, t}
#define A_ENM(t) {ARG_ENUM, t}

#define SC_0(nr, name)                                                         \
  {                                                                            \
    nr, #name, 0, { {0} }                                                      \
  }
#define SC_1(nr, name, t1)                                                     \
  {                                                                            \
    nr, #name, 1, { t1 }                                                       \
  }
#define SC_2(nr, name, t1, t2)                                                 \
  {                                                                            \
    nr, #name, 2, { t1, t2 }                                                   \
  }
#define SC_3(nr, name, t1, t2, t3)                                             \
  {                                                                            \
    nr, #name, 3, { t1, t2, t3 }                                               \
  }
#define SC_4(nr, name, t1, t2, t3, t4)                                         \
  {                                                                            \
    nr, #name, 4, { t1, t2, t3, t4 }                                           \
  }
#define SC_5(nr, name, t1, t2, t3, t4, t5)                                     \
  {                                                                            \
    nr, #name, 5, { t1, t2, t3, t4, t5 }                                       \
  }
#define SC_6(nr, name, t1, t2, t3, t4, t5, t6)                                 \
  {                                                                            \
    nr, #name, 6, { t1, t2, t3, t4, t5, t6 }                                   \
  }

#include "constants.h"

// Table for common syscalls. This is NOT exhaustive but covers most standard
// x86_64 syscalls.
static const syscall_info_t known_syscalls[] = {
#ifdef __NR_read
    SC_3(__NR_read, read, A_FD, A_BUF(2), A_INT),
#endif
#ifdef __NR_write
    SC_3(__NR_write, write, A_FD, A_BUF(2), A_INT),
#endif
#ifdef __NR_open
    SC_2(__NR_open, open, A_STR, A_FLG(TYPE_OPEN_FLAGS)),
#endif
#ifdef __NR_close
    SC_1(__NR_close, close, A_FD),
#endif
#ifdef __NR_stat
    SC_2(__NR_stat, stat, A_STR, A_PTR),
#endif
#ifdef __NR_fstat
    SC_2(__NR_fstat, fstat, A_FD, A_PTR),
#endif
#ifdef __NR_lstat
    SC_2(__NR_lstat, lstat, A_STR, A_PTR),
#endif
#ifdef __NR_poll
    SC_3(__NR_poll, poll, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_lseek
    SC_3(__NR_lseek, lseek, A_FD, A_INT, A_ENM(TYPE_LSEEK_WHENCE)),
#endif
#ifdef __NR_mmap
    SC_6(__NR_mmap, mmap, A_PTR, A_INT, A_FLG(TYPE_MMAP_PROT),
#endif
         A_FLG(TYPE_MMAP_FLAGS), A_FD, A_INT),
#ifdef __NR_mprotect
    SC_3(__NR_mprotect, mprotect, A_PTR, A_INT, A_FLG(TYPE_MMAP_PROT)),
#endif
#ifdef __NR_munmap
    SC_2(__NR_munmap, munmap, A_PTR, A_INT),
#endif
#ifdef __NR_brk
    SC_1(__NR_brk, brk, A_PTR),
#endif
#ifdef __NR_rt_sigaction
    SC_4(__NR_rt_sigaction, rt_sigaction, A_INT, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_rt_sigprocmask
    SC_4(__NR_rt_sigprocmask, rt_sigprocmask, A_INT, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_rt_sigreturn
    SC_0(__NR_rt_sigreturn, rt_sigreturn),
#endif
#ifdef __NR_ioctl
    SC_3(__NR_ioctl, ioctl, A_FD, A_HEX, A_HEX),
#endif
#ifdef __NR_pread64
    SC_4(__NR_pread64, pread64, A_FD, A_BUF(2), A_INT, A_INT),
#endif
#ifdef __NR_pwrite64
    SC_4(__NR_pwrite64, pwrite64, A_FD, A_BUF(2), A_INT, A_INT),
#endif
#ifdef __NR_readv
    SC_3(__NR_readv, readv, A_FD, A_PTR, A_INT),
#endif
#ifdef __NR_writev
    SC_3(__NR_writev, writev, A_FD, A_PTR, A_INT),
#endif
#ifdef __NR_access
    SC_2(__NR_access, access, A_STR, A_FLG(TYPE_ACCESS_MODE)),
#endif
#ifdef __NR_pipe
    SC_1(__NR_pipe, pipe, A_PTR),
#endif
#ifdef __NR_select
    SC_5(__NR_select, select, A_INT, A_PTR, A_PTR, A_PTR, A_PTR),
#endif
#ifdef __NR_sched_yield
    SC_0(__NR_sched_yield, sched_yield),
#endif
#ifdef __NR_mremap
    SC_5(__NR_mremap, mremap, A_PTR, A_INT, A_INT, A_FLG(TYPE_MREMAP_FLAGS),
#endif
         A_PTR),
#ifdef __NR_msync
    SC_3(__NR_msync, msync, A_PTR, A_INT, A_FLG(TYPE_MSYNC_FLAGS)),
#endif
#ifdef __NR_mincore
    SC_3(__NR_mincore, mincore, A_PTR, A_INT, A_PTR),
#endif
#ifdef __NR_madvise
    SC_3(__NR_madvise, madvise, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_shmget
    SC_3(__NR_shmget, shmget, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_shmat
    SC_3(__NR_shmat, shmat, A_INT, A_PTR, A_INT), // TODO: shmflg
#endif
#ifdef __NR_shmctl
    SC_3(__NR_shmctl, shmctl, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_dup
    SC_1(__NR_dup, dup, A_FD),
#endif
#ifdef __NR_dup2
    SC_2(__NR_dup2, dup2, A_FD, A_FD),
#endif
#ifdef __NR_pause
    SC_0(__NR_pause, pause),
#endif
#ifdef __NR_nanosleep
    SC_2(__NR_nanosleep, nanosleep, A_PTR, A_PTR),
#endif
#ifdef __NR_getitimer
    SC_0(__NR_getitimer, getitimer), // args missing
#endif
#ifdef __NR_alarm
    SC_1(__NR_alarm, alarm, A_INT),
#endif
#ifdef __NR_setitimer
    SC_0(__NR_setitimer, setitimer), // args missing
#endif
#ifdef __NR_getpid
    SC_0(__NR_getpid, getpid),
#endif
#ifdef __NR_sendfile
    SC_4(__NR_sendfile, sendfile, A_FD, A_FD, A_PTR, A_INT),
#endif
#ifdef __NR_socket
    SC_3(__NR_socket, socket, A_ENM(TYPE_SOCKET_DOMAIN),
#endif
         A_ENM(TYPE_SOCKET_TYPE), A_ENM(TYPE_SOCKET_PROTO)),
#ifdef __NR_connect
    SC_3(__NR_connect, connect, A_FD, A_PTR, A_INT),
#endif
#ifdef __NR_accept
    SC_3(__NR_accept, accept, A_FD, A_PTR, A_PTR),
#endif
#ifdef __NR_sendto
    SC_6(__NR_sendto, sendto, A_FD, A_PTR, A_INT, A_HEX, A_PTR, A_INT),
#endif
#ifdef __NR_recvfrom
    SC_6(__NR_recvfrom, recvfrom, A_FD, A_PTR, A_INT, A_HEX, A_PTR, A_PTR),
#endif
#ifdef __NR_sendmsg
    SC_3(__NR_sendmsg, sendmsg, A_FD, A_PTR, A_HEX),
#endif
#ifdef __NR_recvmsg
    SC_3(__NR_recvmsg, recvmsg, A_FD, A_PTR, A_HEX),
#endif
#ifdef __NR_shutdown
    SC_3(__NR_shutdown, shutdown, A_FD, A_INT, A_INT),
#endif
#ifdef __NR_bind
    SC_3(__NR_bind, bind, A_FD, A_PTR, A_INT),
#endif
#ifdef __NR_listen
    SC_2(__NR_listen, listen, A_FD, A_INT),
#endif
#ifdef __NR_getsockname
    SC_3(__NR_getsockname, getsockname, A_FD, A_PTR, A_PTR),
#endif
#ifdef __NR_getpeername
    SC_3(__NR_getpeername, getpeername, A_FD, A_PTR, A_PTR),
#endif
#ifdef __NR_socketpair
    SC_4(__NR_socketpair, socketpair, A_INT, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_setsockopt
    SC_5(__NR_setsockopt, setsockopt, A_FD, A_INT, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_getsockopt
    SC_5(__NR_getsockopt, getsockopt, A_FD, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_clone
    SC_5(__NR_clone, clone, A_FLG(TYPE_CLONE_FLAGS), A_PTR, A_PTR, A_PTR,
#endif
         A_PTR),
#ifdef __NR_fork
    SC_0(__NR_fork, fork),
#endif
#ifdef __NR_vfork
    SC_0(__NR_vfork, vfork),
#endif
#ifdef __NR_execve
    SC_3(__NR_execve, execve, A_STR, A_PTR, A_PTR),
#endif
#ifdef __NR_exit
    SC_1(__NR_exit, exit, A_INT),
#endif
#ifdef __NR_wait4
    SC_4(__NR_wait4, wait4, A_INT, A_PTR, A_INT, A_PTR),
#endif
#ifdef __NR_kill
    SC_2(__NR_kill, kill, A_INT, A_INT),
#endif
#ifdef __NR_uname
    SC_1(__NR_uname, uname, A_PTR),
#endif
#ifdef __NR_semget
    SC_3(__NR_semget, semget, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_semop
    SC_3(__NR_semop, semop, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_semctl
    SC_4(__NR_semctl, semctl, A_INT, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_shmdt
    SC_1(__NR_shmdt, shmdt, A_PTR),
#endif
#ifdef __NR_msgget
    SC_2(__NR_msgget, msgget, A_INT, A_INT),
#endif
#ifdef __NR_msgsnd
    SC_4(__NR_msgsnd, msgsnd, A_INT, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_msgrcv
    SC_5(__NR_msgrcv, msgrcv, A_INT, A_PTR, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_msgctl
    SC_3(__NR_msgctl, msgctl, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_fcntl
    SC_3(__NR_fcntl, fcntl, A_FD, A_ENM(TYPE_FCNTL_CMD), A_HEX),
#endif
#ifdef __NR_flock
    SC_2(__NR_flock, flock, A_FD, A_INT),
#endif
#ifdef __NR_fsync
    SC_1(__NR_fsync, fsync, A_FD),
#endif
#ifdef __NR_fdatasync
    SC_1(__NR_fdatasync, fdatasync, A_FD),
#endif
#ifdef __NR_truncate
    SC_2(__NR_truncate, truncate, A_STR, A_INT),
#endif
#ifdef __NR_ftruncate
    SC_2(__NR_ftruncate, ftruncate, A_FD, A_INT),
#endif
#ifdef __NR_getdents
    SC_3(__NR_getdents, getdents, A_FD, A_PTR, A_INT),
#endif
#ifdef __NR_getcwd
    SC_2(__NR_getcwd, getcwd, A_BUF(1), A_INT),
#endif
#ifdef __NR_chdir
    SC_1(__NR_chdir, chdir, A_STR),
#endif
#ifdef __NR_fchdir
    SC_1(__NR_fchdir, fchdir, A_FD),
#endif
#ifdef __NR_rename
    SC_2(__NR_rename, rename, A_STR, A_STR),
#endif
#ifdef __NR_mkdir
    SC_2(__NR_mkdir, mkdir, A_STR, A_FLG(TYPE_ALL_PERMS)),
#endif
#ifdef __NR_rmdir
    SC_1(__NR_rmdir, rmdir, A_STR),
#endif
#ifdef __NR_creat
    SC_2(__NR_creat, creat, A_STR, A_FLG(TYPE_ALL_PERMS)),
#endif
#ifdef __NR_link
    SC_2(__NR_link, link, A_STR, A_STR),
#endif
#ifdef __NR_unlink
    SC_1(__NR_unlink, unlink, A_STR),
#endif
#ifdef __NR_symlink
    SC_2(__NR_symlink, symlink, A_STR, A_STR),
#endif
#ifdef __NR_readlink
    SC_3(__NR_readlink, readlink, A_STR, A_BUF(2), A_INT),
#endif
#ifdef __NR_chmod
    SC_2(__NR_chmod, chmod, A_STR, A_FLG(TYPE_ALL_PERMS)),
#endif
#ifdef __NR_fchmod
    SC_2(__NR_fchmod, fchmod, A_FD, A_FLG(TYPE_ALL_PERMS)),
#endif
#ifdef __NR_chown
    SC_3(__NR_chown, chown, A_STR, A_INT, A_INT),
#endif
#ifdef __NR_fchown
    SC_3(__NR_fchown, fchown, A_FD, A_INT, A_INT),
#endif
#ifdef __NR_lchown
    SC_3(__NR_lchown, lchown, A_STR, A_INT, A_INT),
#endif
#ifdef __NR_umask
    SC_1(__NR_umask, umask, A_INT),
#endif
#ifdef __NR_gettimeofday
    SC_2(__NR_gettimeofday, gettimeofday, A_PTR, A_PTR),
#endif
#ifdef __NR_getrlimit
    SC_2(__NR_getrlimit, getrlimit, A_INT, A_PTR),
#endif
#ifdef __NR_getrusage
    SC_2(__NR_getrusage, getrusage, A_INT, A_PTR),
#endif
#ifdef __NR_sysinfo
    SC_1(__NR_sysinfo, sysinfo, A_PTR),
#endif
#ifdef __NR_times
    SC_1(__NR_times, times, A_PTR),
#endif
#ifdef __NR_ptrace
    SC_4(__NR_ptrace, ptrace, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_getuid
    SC_0(__NR_getuid, getuid),
#endif
#ifdef __NR_syslog
    SC_3(__NR_syslog, syslog, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_getgid
    SC_0(__NR_getgid, getgid),
#endif
#ifdef __NR_setuid
    SC_1(__NR_setuid, setuid, A_INT),
#endif
#ifdef __NR_setgid
    SC_1(__NR_setgid, setgid, A_INT),
#endif
#ifdef __NR_geteuid
    SC_0(__NR_geteuid, geteuid),
#endif
#ifdef __NR_getegid
    SC_0(__NR_getegid, getegid),
#endif
#ifdef __NR_setpgid
    SC_2(__NR_setpgid, setpgid, A_INT, A_INT),
#endif
#ifdef __NR_getppid
    SC_0(__NR_getppid, getppid),
#endif
#ifdef __NR_getpgrp
    SC_0(__NR_getpgrp, getpgrp),
#endif
#ifdef __NR_setsid
    SC_0(__NR_setsid, setsid),
#endif
#ifdef __NR_setreuid
    SC_2(__NR_setreuid, setreuid, A_INT, A_INT),
#endif
#ifdef __NR_setregid
    SC_2(__NR_setregid, setregid, A_INT, A_INT),
#endif
#ifdef __NR_getgroups
    SC_2(__NR_getgroups, getgroups, A_INT, A_PTR),
#endif
#ifdef __NR_setgroups
    SC_2(__NR_setgroups, setgroups, A_INT, A_PTR),
#endif
#ifdef __NR_setresuid
    SC_3(__NR_setresuid, setresuid, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_getresuid
    SC_3(__NR_getresuid, getresuid, A_PTR, A_PTR, A_PTR),
#endif
#ifdef __NR_setresgid
    SC_3(__NR_setresgid, setresgid, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_getresgid
    SC_3(__NR_getresgid, getresgid, A_PTR, A_PTR, A_PTR),
#endif
#ifdef __NR_getpgid
    SC_1(__NR_getpgid, getpgid, A_INT),
#endif
#ifdef __NR_setfsuid
    SC_1(__NR_setfsuid, setfsuid, A_INT),
#endif
#ifdef __NR_setfsgid
    SC_1(__NR_setfsgid, setfsgid, A_INT),
#endif
#ifdef __NR_getsid
    SC_1(__NR_getsid, getsid, A_INT),
#endif
#ifdef __NR_capget
    SC_2(__NR_capget, capget, A_PTR, A_PTR),
#endif
#ifdef __NR_capset
    SC_2(__NR_capset, capset, A_PTR, A_PTR),
#endif
#ifdef __NR_rt_sigpending
    SC_2(__NR_rt_sigpending, rt_sigpending, A_PTR, A_INT),
#endif
#ifdef __NR_rt_sigtimedwait
    SC_4(__NR_rt_sigtimedwait, rt_sigtimedwait, A_PTR, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_rt_sigqueueinfo
    SC_3(__NR_rt_sigqueueinfo, rt_sigqueueinfo, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_rt_sigsuspend
    SC_2(__NR_rt_sigsuspend, rt_sigsuspend, A_PTR, A_INT),
#endif
#ifdef __NR_sigaltstack
    SC_2(__NR_sigaltstack, sigaltstack, A_PTR, A_PTR),
#endif
#ifdef __NR_utime
    SC_2(__NR_utime, utime, A_STR, A_PTR),
#endif
#ifdef __NR_mknod
    SC_3(__NR_mknod, mknod, A_STR, A_FLG(TYPE_ALL_PERMS), A_INT),
#endif
#ifdef __NR_uselib
    SC_1(__NR_uselib, uselib, A_STR),
#endif
#ifdef __NR_personality
    SC_1(__NR_personality, personality, A_HEX),
#endif
#ifdef __NR_ustat
    SC_2(__NR_ustat, ustat, A_INT, A_PTR),
#endif
#ifdef __NR_statfs
    SC_2(__NR_statfs, statfs, A_STR, A_PTR),
#endif
#ifdef __NR_fstatfs
    SC_2(__NR_fstatfs, fstatfs, A_FD, A_PTR),
#endif
#ifdef __NR_sysfs
    SC_3(__NR_sysfs, sysfs, A_INT, A_STR, A_INT), // Legacy
#endif
#ifdef __NR_getpriority
    SC_2(__NR_getpriority, getpriority, A_INT, A_INT),
#endif
#ifdef __NR_setpriority
    SC_3(__NR_setpriority, setpriority, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_sched_setparam
    SC_2(__NR_sched_setparam, sched_setparam, A_INT, A_PTR),
#endif
#ifdef __NR_sched_getparam
    SC_2(__NR_sched_getparam, sched_getparam, A_INT, A_PTR),
#endif
#ifdef __NR_sched_setscheduler
    SC_3(__NR_sched_setscheduler, sched_setscheduler, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_sched_getscheduler
    SC_1(__NR_sched_getscheduler, sched_getscheduler, A_INT),
#endif
#ifdef __NR_sched_get_priority_max
    SC_1(__NR_sched_get_priority_max, sched_get_priority_max, A_INT),
#endif
#ifdef __NR_sched_get_priority_min
    SC_1(__NR_sched_get_priority_min, sched_get_priority_min, A_INT),
#endif
#ifdef __NR_sched_rr_get_interval
    SC_2(__NR_sched_rr_get_interval, sched_rr_get_interval, A_INT, A_PTR),
#endif
#ifdef __NR_mlock
    SC_2(__NR_mlock, mlock, A_PTR, A_INT),
#endif
#ifdef __NR_munlock
    SC_2(__NR_munlock, munlock, A_PTR, A_INT),
#endif
#ifdef __NR_mlockall
    SC_1(__NR_mlockall, mlockall, A_INT),
#endif
#ifdef __NR_munlockall
    SC_0(__NR_munlockall, munlockall),
#endif
#ifdef __NR_vhangup
    SC_0(__NR_vhangup, vhangup),
#endif
#ifdef __NR_modify_ldt
    SC_3(__NR_modify_ldt, modify_ldt, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_pivot_root
    SC_2(__NR_pivot_root, pivot_root, A_STR, A_STR),
#endif
#ifdef __NR__sysctl
    SC_1(__NR__sysctl, _sysctl, A_PTR),
#endif
#ifdef __NR_prctl
    SC_5(__NR_prctl, prctl, A_INT, A_HEX, A_HEX, A_HEX, A_HEX),
#endif
#ifdef __NR_arch_prctl
    SC_2(__NR_arch_prctl, arch_prctl, A_INT, A_PTR),
#endif
#ifdef __NR_adjtimex
    SC_1(__NR_adjtimex, adjtimex, A_PTR),
#endif
#ifdef __NR_setrlimit
    SC_2(__NR_setrlimit, setrlimit, A_INT, A_PTR),
#endif
#ifdef __NR_chroot
    SC_1(__NR_chroot, chroot, A_STR),
#endif
#ifdef __NR_sync
    SC_0(__NR_sync, sync),
#endif
#ifdef __NR_acct
    SC_1(__NR_acct, acct, A_STR),
#endif
#ifdef __NR_settimeofday
    SC_2(__NR_settimeofday, settimeofday, A_PTR, A_PTR),
#endif
#ifdef __NR_mount
    SC_5(__NR_mount, mount, A_STR, A_STR, A_STR, A_INT, A_PTR),
#endif
#ifdef __NR_umount2
    SC_2(__NR_umount2, umount2, A_STR, A_INT),
#endif
#ifdef __NR_swapon
    SC_2(__NR_swapon, swapon, A_STR, A_INT),
#endif
#ifdef __NR_swapoff
    SC_1(__NR_swapoff, swapoff, A_STR),
#endif
#ifdef __NR_reboot
    SC_4(__NR_reboot, reboot, A_INT, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_sethostname
    SC_2(__NR_sethostname, sethostname, A_STR, A_INT),
#endif
#ifdef __NR_setdomainname
    SC_2(__NR_setdomainname, setdomainname, A_STR, A_INT),
#endif
#ifdef __NR_iopl
    SC_1(__NR_iopl, iopl, A_INT),
#endif
#ifdef __NR_ioperm
    SC_3(__NR_ioperm, ioperm, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_create_module
    SC_2(__NR_create_module, create_module, A_PTR, A_INT), // Removed in 2.6
#endif
#ifdef __NR_init_module
    SC_3(__NR_init_module, init_module, A_PTR, A_INT, A_STR),
#endif
#ifdef __NR_delete_module
    SC_2(__NR_delete_module, delete_module, A_STR, A_INT),
#endif
#ifdef __NR_get_kernel_syms
    SC_1(__NR_get_kernel_syms, get_kernel_syms, A_PTR), // Removed
#endif
#ifdef __NR_query_module
    SC_5(__NR_query_module, query_module, A_STR, A_INT, A_PTR, A_INT,
#endif
         A_PTR), // Removed
#ifdef __NR_quotactl
    SC_4(__NR_quotactl, quotactl, A_INT, A_STR, A_INT, A_PTR),
#endif
#ifdef __NR_nfsservctl
    SC_3(__NR_nfsservctl, nfsservctl, A_INT, A_PTR, A_PTR), // Removed
#endif
#ifdef __NR_getpmsg
    SC_5(__NR_getpmsg, getpmsg, A_INT, A_PTR, A_PTR, A_PTR,
#endif
         A_PTR), // Not implemented
#ifdef __NR_putpmsg
    SC_5(__NR_putpmsg, putpmsg, A_INT, A_PTR, A_PTR, A_PTR,
#endif
         A_PTR), // Not implemented
#ifdef __NR_afs_syscall
    SC_5(__NR_afs_syscall, afs_syscall, A_INT, A_INT, A_INT, A_INT,
#endif
         A_INT), // Not implemented
#ifdef __NR_tuxcall
    SC_3(__NR_tuxcall, tuxcall, A_INT, A_INT, A_INT), // Not implemented
#endif
#ifdef __NR_security
    SC_3(__NR_security, security, A_INT, A_INT, A_INT), // Not implemented
#endif
#ifdef __NR_gettid
    SC_0(__NR_gettid, gettid),
#endif
#ifdef __NR_readahead
    SC_3(__NR_readahead, readahead, A_FD, A_INT, A_INT),
#endif
#ifdef __NR_setxattr
    SC_5(__NR_setxattr, setxattr, A_STR, A_STR, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_lsetxattr
    SC_5(__NR_lsetxattr, lsetxattr, A_STR, A_STR, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_fsetxattr
    SC_5(__NR_fsetxattr, fsetxattr, A_FD, A_STR, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_getxattr
    SC_4(__NR_getxattr, getxattr, A_STR, A_STR, A_PTR, A_INT),
#endif
#ifdef __NR_lgetxattr
    SC_4(__NR_lgetxattr, lgetxattr, A_STR, A_STR, A_PTR, A_INT),
#endif
#ifdef __NR_fgetxattr
    SC_4(__NR_fgetxattr, fgetxattr, A_FD, A_STR, A_PTR, A_INT),
#endif
#ifdef __NR_listxattr
    SC_3(__NR_listxattr, listxattr, A_STR, A_STR, A_INT),
#endif
#ifdef __NR_llistxattr
    SC_3(__NR_llistxattr, llistxattr, A_STR, A_STR, A_INT),
#endif
#ifdef __NR_flistxattr
    SC_3(__NR_flistxattr, flistxattr, A_FD, A_STR, A_INT),
#endif
#ifdef __NR_removexattr
    SC_2(__NR_removexattr, removexattr, A_STR, A_STR),
#endif
#ifdef __NR_lremovexattr
    SC_2(__NR_lremovexattr, lremovexattr, A_STR, A_STR),
#endif
#ifdef __NR_fremovexattr
    SC_2(__NR_fremovexattr, fremovexattr, A_FD, A_STR),
#endif
#ifdef __NR_tkill
    SC_2(__NR_tkill, tkill, A_INT, A_INT),
#endif
#ifdef __NR_time
    SC_1(__NR_time, time, A_PTR),
#endif
#ifdef __NR_futex
    SC_6(__NR_futex, futex, A_PTR, A_INT, A_INT, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_sched_setaffinity
    SC_3(__NR_sched_setaffinity, sched_setaffinity, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_sched_getaffinity
    SC_3(__NR_sched_getaffinity, sched_getaffinity, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_set_thread_area
    SC_1(__NR_set_thread_area, set_thread_area, A_PTR),
#endif
#ifdef __NR_io_setup
    SC_2(__NR_io_setup, io_setup, A_INT, A_PTR),
#endif
#ifdef __NR_io_destroy
    SC_1(__NR_io_destroy, io_destroy, A_INT),
#endif
#ifdef __NR_io_getevents
    SC_5(__NR_io_getevents, io_getevents, A_INT, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_io_submit
    SC_3(__NR_io_submit, io_submit, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_io_cancel
    SC_3(__NR_io_cancel, io_cancel, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_get_thread_area
    SC_1(__NR_get_thread_area, get_thread_area, A_PTR),
#endif
#ifdef __NR_lookup_dcookie
    SC_3(__NR_lookup_dcookie, lookup_dcookie, A_INT, A_BUF(2), A_INT),
#endif
#ifdef __NR_epoll_create
    SC_1(__NR_epoll_create, epoll_create, A_INT),
#endif
#ifdef __NR_epoll_ctl_old
    SC_4(__NR_epoll_ctl_old, epoll_ctl_old, A_INT, A_INT, A_INT,
#endif
         A_PTR), // Deprecated?
#ifdef __NR_epoll_wait_old
    SC_4(__NR_epoll_wait_old, epoll_wait_old, A_INT, A_PTR, A_INT,
#endif
         A_INT), // Deprecated?
#ifdef __NR_remap_file_pages
    SC_5(__NR_remap_file_pages, remap_file_pages, A_PTR, A_INT, A_INT, A_INT,
#endif
         A_INT),
#ifdef __NR_getdents64
    SC_3(__NR_getdents64, getdents64, A_FD, A_PTR, A_INT),
#endif
#ifdef __NR_set_tid_address
    SC_1(__NR_set_tid_address, set_tid_address, A_PTR),
#endif
#ifdef __NR_restart_syscall
    SC_0(__NR_restart_syscall, restart_syscall),
#endif
#ifdef __NR_semtimedop
    SC_4(__NR_semtimedop, semtimedop, A_INT, A_PTR, A_INT, A_PTR),
#endif
#ifdef __NR_fadvise64
    SC_4(__NR_fadvise64, fadvise64, A_FD, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_timer_create
    SC_3(__NR_timer_create, timer_create, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_timer_settime
    SC_4(__NR_timer_settime, timer_settime, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_timer_gettime
    SC_2(__NR_timer_gettime, timer_gettime, A_INT, A_PTR),
#endif
#ifdef __NR_timer_getoverrun
    SC_1(__NR_timer_getoverrun, timer_getoverrun, A_INT),
#endif
#ifdef __NR_timer_delete
    SC_1(__NR_timer_delete, timer_delete, A_INT),
#endif
#ifdef __NR_clock_settime
    SC_2(__NR_clock_settime, clock_settime, A_INT, A_PTR),
#endif
#ifdef __NR_clock_gettime
    SC_2(__NR_clock_gettime, clock_gettime, A_INT, A_PTR),
#endif
#ifdef __NR_clock_getres
    SC_2(__NR_clock_getres, clock_getres, A_INT, A_PTR),
#endif
#ifdef __NR_clock_nanosleep
    SC_4(__NR_clock_nanosleep, clock_nanosleep, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_exit_group
    SC_1(__NR_exit_group, exit_group, A_INT),
#endif
#ifdef __NR_epoll_wait
    SC_4(__NR_epoll_wait, epoll_wait, A_INT, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_epoll_ctl
    SC_4(__NR_epoll_ctl, epoll_ctl, A_INT, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_tgkill
    SC_3(__NR_tgkill, tgkill, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_utimes
    SC_2(__NR_utimes, utimes, A_STR, A_PTR),
#endif
#ifdef __NR_vserver
    SC_5(__NR_vserver, vserver, A_INT, A_INT, A_INT, A_INT,
#endif
         A_INT), // Not implemented
#ifdef __NR_mbind
    SC_6(__NR_mbind, mbind, A_PTR, A_INT, A_INT, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_set_mempolicy
    SC_3(__NR_set_mempolicy, set_mempolicy, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_get_mempolicy
    SC_5(__NR_get_mempolicy, get_mempolicy, A_PTR, A_PTR, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_mq_open
    SC_4(__NR_mq_open, mq_open, A_STR, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_mq_unlink
    SC_1(__NR_mq_unlink, mq_unlink, A_STR),
#endif
#ifdef __NR_mq_timedsend
    SC_5(__NR_mq_timedsend, mq_timedsend, A_INT, A_STR, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_mq_timedreceive
    SC_5(__NR_mq_timedreceive, mq_timedreceive, A_INT, A_STR, A_INT, A_PTR,
#endif
         A_PTR),
#ifdef __NR_mq_notify
    SC_2(__NR_mq_notify, mq_notify, A_INT, A_PTR),
#endif
#ifdef __NR_mq_getsetattr
    SC_3(__NR_mq_getsetattr, mq_getsetattr, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_rseq
    SC_4(__NR_rseq, rseq, A_PTR, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_kexec_load
    SC_4(__NR_kexec_load, kexec_load, A_INT, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_waitid
    SC_5(__NR_waitid, waitid, A_INT, A_INT, A_PTR, A_INT, A_PTR),
#endif
#ifdef __NR_add_key
    SC_5(__NR_add_key, add_key, A_STR, A_STR, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_request_key
    SC_4(__NR_request_key, request_key, A_STR, A_STR, A_STR, A_INT),
#endif
#ifdef __NR_keyctl
    SC_5(__NR_keyctl, keyctl, A_INT, A_INT, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_ioprio_set
    SC_3(__NR_ioprio_set, ioprio_set, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_ioprio_get
    SC_2(__NR_ioprio_get, ioprio_get, A_INT, A_INT),
#endif
#ifdef __NR_inotify_init
    SC_0(__NR_inotify_init, inotify_init),
#endif
#ifdef __NR_inotify_add_watch
    SC_3(__NR_inotify_add_watch, inotify_add_watch, A_INT, A_STR, A_INT),
#endif
#ifdef __NR_inotify_rm_watch
    SC_2(__NR_inotify_rm_watch, inotify_rm_watch, A_INT, A_INT),
#endif
#ifdef __NR_migrate_pages
    SC_4(__NR_migrate_pages, migrate_pages, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_openat
    SC_4(__NR_openat, openat, A_FD, A_STR, A_FLG(TYPE_OPEN_FLAGS), A_HEX),
#endif
#ifdef __NR_mkdirat
    SC_3(__NR_mkdirat, mkdirat, A_FD, A_STR, A_FLG(TYPE_ALL_PERMS)),
#endif
#ifdef __NR_mknodat
    SC_4(__NR_mknodat, mknodat, A_FD, A_STR, A_FLG(TYPE_ALL_PERMS), A_INT),
#endif
#ifdef __NR_fchownat
    SC_5(__NR_fchownat, fchownat, A_FD, A_STR, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_futimesat
    SC_3(__NR_futimesat, futimesat, A_FD, A_STR, A_PTR),
#endif
#ifdef __NR_newfstatat
    SC_4(__NR_newfstatat, newfstatat, A_FD, A_STR, A_PTR, A_INT),
#endif
#ifdef __NR_unlinkat
    SC_3(__NR_unlinkat, unlinkat, A_FD, A_STR, A_INT),
#endif
#ifdef __NR_renameat
    SC_4(__NR_renameat, renameat, A_FD, A_STR, A_FD, A_STR),
#endif
#ifdef __NR_linkat
    SC_5(__NR_linkat, linkat, A_FD, A_STR, A_FD, A_STR, A_INT),
#endif
#ifdef __NR_symlinkat
    SC_3(__NR_symlinkat, symlinkat, A_STR, A_FD, A_STR),
#endif
#ifdef __NR_readlinkat
    SC_4(__NR_readlinkat, readlinkat, A_FD, A_STR, A_BUF_NO_LEN, A_INT),
#endif
#ifdef __NR_fchmodat
    SC_3(__NR_fchmodat, fchmodat, A_FD, A_STR, A_FLG(TYPE_ALL_PERMS)),
#endif
#ifdef __NR_faccessat
    SC_3(__NR_faccessat, faccessat, A_FD, A_STR, A_FLG(TYPE_ACCESS_MODE)),
#endif
#ifdef __NR_pselect6
    SC_6(__NR_pselect6, pselect6, A_INT, A_PTR, A_PTR, A_PTR, A_PTR, A_PTR),
#endif
#ifdef __NR_ppoll
    SC_5(__NR_ppoll, ppoll, A_PTR, A_INT, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_unshare
    SC_1(__NR_unshare, unshare, A_INT),
#endif
#ifdef __NR_set_robust_list
    SC_2(__NR_set_robust_list, set_robust_list, A_PTR, A_INT),
#endif
#ifdef __NR_get_robust_list
    SC_3(__NR_get_robust_list, get_robust_list, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_splice
    SC_6(__NR_splice, splice, A_FD, A_PTR, A_FD, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_tee
    SC_4(__NR_tee, tee, A_FD, A_FD, A_INT, A_INT),
#endif
#ifdef __NR_sync_file_range
    SC_4(__NR_sync_file_range, sync_file_range, A_FD, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_vmsplice
    SC_4(__NR_vmsplice, vmsplice, A_FD, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_move_pages
    SC_6(__NR_move_pages, move_pages, A_INT, A_INT, A_PTR, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_utimensat
    SC_4(__NR_utimensat, utimensat, A_FD, A_STR, A_PTR, A_INT),
#endif
#ifdef __NR_epoll_pwait
    SC_6(__NR_epoll_pwait, epoll_pwait, A_INT, A_PTR, A_INT, A_INT, A_PTR,
#endif
         A_INT),
#ifdef __NR_signalfd
    SC_3(__NR_signalfd, signalfd, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_timerfd_create
    SC_2(__NR_timerfd_create, timerfd_create, A_INT, A_INT),
#endif
#ifdef __NR_timerfd_settime
    SC_4(__NR_timerfd_settime, timerfd_settime, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_timerfd_gettime
    SC_2(__NR_timerfd_gettime, timerfd_gettime, A_INT, A_PTR),
#endif
#ifdef __NR_eventfd
    SC_1(__NR_eventfd, eventfd, A_INT),
#endif
#ifdef __NR_fallocate
    SC_4(__NR_fallocate, fallocate, A_FD, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_timerfd_settime
    SC_3(__NR_timerfd_settime, timerfd_settime, A_INT, A_INT,
#endif
         A_PTR), // Dupe? No, different args?
                 // ...
#ifdef __NR_eventfd2
    SC_2(__NR_eventfd2, eventfd2, A_INT, A_INT),
#endif
#ifdef __NR_epoll_create1
    SC_1(__NR_epoll_create1, epoll_create1, A_INT),
#endif
#ifdef __NR_dup3
    SC_3(__NR_dup3, dup3, A_FD, A_FD, A_INT),
#endif
#ifdef __NR_pipe2
    SC_2(__NR_pipe2, pipe2, A_PTR, A_INT),
#endif
#ifdef __NR_inotify_init1
    SC_1(__NR_inotify_init1, inotify_init1, A_INT),
#endif
#ifdef __NR_preadv
    SC_4(__NR_preadv, preadv, A_FD, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_pwritev
    SC_4(__NR_pwritev, pwritev, A_FD, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_rt_tgsigqueueinfo
    SC_4(__NR_rt_tgsigqueueinfo, rt_tgsigqueueinfo, A_INT, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_perf_event_open
    SC_5(__NR_perf_event_open, perf_event_open, A_PTR, A_INT, A_INT, A_INT,
#endif
         A_INT),
#ifdef __NR_recvmmsg
    SC_5(__NR_recvmmsg, recvmmsg, A_FD, A_PTR, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_fanotify_init
    SC_2(__NR_fanotify_init, fanotify_init, A_INT, A_INT),
#endif
#ifdef __NR_fanotify_mark
    SC_5(__NR_fanotify_mark, fanotify_mark, A_INT, A_INT, A_INT, A_FD, A_STR),
#endif
#ifdef __NR_prlimit64
    SC_4(__NR_prlimit64, prlimit64, A_INT, A_INT, A_PTR, A_PTR),
#endif
#ifdef __NR_name_to_handle_at
    SC_5(__NR_name_to_handle_at, name_to_handle_at, A_FD, A_STR, A_PTR, A_PTR,
#endif
         A_INT),
#ifdef __NR_open_by_handle_at
    SC_3(__NR_open_by_handle_at, open_by_handle_at, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_clock_adjtime
    SC_2(__NR_clock_adjtime, clock_adjtime, A_INT, A_PTR),
#endif
#ifdef __NR_syncfs
    SC_1(__NR_syncfs, syncfs, A_FD),
#endif
#ifdef __NR_sendmmsg
    SC_4(__NR_sendmmsg, sendmmsg, A_FD, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_setns
    SC_2(__NR_setns, setns, A_FD, A_INT),
#endif
#ifdef __NR_getcpu
    SC_3(__NR_getcpu, getcpu, A_PTR, A_PTR, A_PTR),
#endif
#ifdef __NR_process_vm_readv
    SC_6(__NR_process_vm_readv, process_vm_readv, A_INT, A_PTR, A_INT, A_PTR,
#endif
         A_INT, A_INT),
#ifdef __NR_process_vm_writev
    SC_6(__NR_process_vm_writev, process_vm_writev, A_INT, A_PTR, A_INT, A_PTR,
#endif
         A_INT, A_INT),
#ifdef __NR_kcmp
    SC_5(__NR_kcmp, kcmp, A_INT, A_INT, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_finit_module
    SC_3(__NR_finit_module, finit_module, A_FD, A_STR, A_INT),
#endif
#ifdef __NR_sched_setattr
    SC_3(__NR_sched_setattr, sched_setattr, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_sched_getattr
    SC_4(__NR_sched_getattr, sched_getattr, A_INT, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_renameat2
    SC_5(__NR_renameat2, renameat2, A_FD, A_STR, A_FD, A_STR, A_INT),
#endif
#ifdef __NR_seccomp
    SC_3(__NR_seccomp, seccomp, A_INT, A_INT, A_PTR),
#endif
#ifdef __NR_getrandom
    SC_3(__NR_getrandom, getrandom, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_memfd_create
    SC_2(__NR_memfd_create, memfd_create, A_STR, A_INT),
#endif
#ifdef __NR_kexec_file_load
    SC_5(__NR_kexec_file_load, kexec_file_load, A_FD, A_FD, A_INT, A_STR,
#endif
         A_INT),
#ifdef __NR_bpf
    SC_3(__NR_bpf, bpf, A_INT, A_PTR, A_INT),
#endif
#ifdef __NR_execveat
    SC_5(__NR_execveat, execveat, A_FD, A_STR, A_PTR, A_PTR, A_INT),
#endif
#ifdef __NR_userfaultfd
    SC_1(__NR_userfaultfd, userfaultfd, A_INT),
#endif
#ifdef __NR_membarrier
    SC_3(__NR_membarrier, membarrier, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_mlock2
    SC_3(__NR_mlock2, mlock2, A_PTR, A_INT, A_INT),
#endif
#ifdef __NR_copy_file_range
    SC_6(__NR_copy_file_range, copy_file_range, A_FD, A_PTR, A_FD, A_PTR, A_INT,
#endif
         A_INT),
#ifdef __NR_preadv2
    SC_6(__NR_preadv2, preadv2, A_FD, A_PTR, A_INT, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_pwritev2
    SC_6(__NR_pwritev2, pwritev2, A_FD, A_PTR, A_INT, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_pkey_mprotect
    SC_4(__NR_pkey_mprotect, pkey_mprotect, A_PTR, A_INT, A_INT, A_INT),
#endif
#ifdef __NR_pkey_alloc
    SC_2(__NR_pkey_alloc, pkey_alloc, A_INT, A_INT),
#endif
#ifdef __NR_pkey_free
    SC_1(__NR_pkey_free, pkey_free, A_INT),
#endif
#ifdef __NR_statx
    SC_5(__NR_statx, statx, A_FD, A_STR, A_INT, A_INT, A_PTR),
#endif
};

const syscall_info_t *get_syscall_info(int nr) {
  for (size_t i = 0; i < sizeof(known_syscalls) / sizeof(known_syscalls[0]);
       i++) {
    if (known_syscalls[i].nr == nr) {
      return &known_syscalls[i];
    }
  }
  return NULL;
}
