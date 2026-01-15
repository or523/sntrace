#define _GNU_SOURCE
#include "constants.h"
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sched.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>


typedef struct {
  unsigned long long val;
  const char *name;
} value_name_t;

static const value_name_t open_flags[] = {
    {O_RDONLY, "O_RDONLY"},
    {O_WRONLY, "O_WRONLY"},
    {O_RDWR, "O_RDWR"},
    {O_CREAT, "O_CREAT"},
    {O_EXCL, "O_EXCL"},
    {O_NOCTTY, "O_NOCTTY"},
    {O_TRUNC, "O_TRUNC"},
    {O_APPEND, "O_APPEND"},
    {O_NONBLOCK, "O_NONBLOCK"},
    {O_DSYNC, "O_DSYNC"},
    {O_SYNC, "O_SYNC"}, // O_RSYNC usually same
    // { O_DIRECTORY, "O_DIRECTORY" }, // _GNU_SOURCE might be needed
    // { O_NOFOLLOW, "O_NOFOLLOW" },
    // { O_CLOEXEC, "O_CLOEXEC" },
    {0, NULL}};

static const value_name_t access_mode[] = {
    {R_OK, "R_OK"}, {W_OK, "W_OK"}, {X_OK, "X_OK"}, {F_OK, "F_OK"}, {0, NULL}};

static const value_name_t mmap_prot[] = {{PROT_READ, "PROT_READ"},
                                         {PROT_WRITE, "PROT_WRITE"},
                                         {PROT_EXEC, "PROT_EXEC"},
                                         {PROT_NONE, "PROT_NONE"},
                                         {0, NULL}};

#ifndef MAP_DENYWRITE
#define MAP_DENYWRITE 0x0800
#endif

static const value_name_t mmap_flags[] = {
    {MAP_SHARED, "MAP_SHARED"},       {MAP_PRIVATE, "MAP_PRIVATE"},
    {MAP_FIXED, "MAP_FIXED"},         {MAP_ANONYMOUS, "MAP_ANONYMOUS"},
    {MAP_DENYWRITE, "MAP_DENYWRITE"}, {0, NULL}};

static const value_name_t lseek_whence[] = {{SEEK_SET, "SEEK_SET"},
                                            {SEEK_CUR, "SEEK_CUR"},
                                            {SEEK_END, "SEEK_END"},
                                            {0, NULL}};

static const value_name_t socket_domain[] = {
    {AF_UNIX, "AF_UNIX"},     {AF_INET, "AF_INET"},
    {AF_INET6, "AF_INET6"},   {AF_NETLINK, "AF_NETLINK"},
    {AF_PACKET, "AF_PACKET"}, {0, NULL}};

static const value_name_t socket_type[] = {{SOCK_STREAM, "SOCK_STREAM"},
                                           {SOCK_DGRAM, "SOCK_DGRAM"},
                                           {SOCK_RAW, "SOCK_RAW"},
                                           {SOCK_SEQPACKET, "SOCK_SEQPACKET"},
                                           {0, NULL}};

static const value_name_t socket_proto[] = {{IPPROTO_IP, "IPPROTO_IP"},
                                            {IPPROTO_TCP, "IPPROTO_TCP"},
                                            {IPPROTO_UDP, "IPPROTO_UDP"},
                                            {IPPROTO_ICMP, "IPPROTO_ICMP"},
                                            {0, NULL}};

static const value_name_t mremap_flags[] = {
#ifdef MREMAP_MAYMOVE
    {MREMAP_MAYMOVE, "MREMAP_MAYMOVE"},
#endif
#ifdef MREMAP_FIXED
    {MREMAP_FIXED, "MREMAP_FIXED"},
#endif
    {0, NULL}};

static const value_name_t msync_flags[] = {{MS_ASYNC, "MS_ASYNC"},
                                           {MS_SYNC, "MS_SYNC"},
                                           {MS_INVALIDATE, "MS_INVALIDATE"},
                                           {0, NULL}};

static const value_name_t all_perms[] = {
    {S_IRWXU, "S_IRWXU"}, {S_IRUSR, "S_IRUSR"},
    {S_IWUSR, "S_IWUSR"}, {S_IXUSR, "S_IXUSR"},
    {S_IRWXG, "S_IRWXG"}, {S_IRGRP, "S_IRGRP"},
    {S_IWGRP, "S_IWGRP"}, {S_IXGRP, "S_IXGRP"},
    {S_IRWXO, "S_IRWXO"}, {S_IROTH, "S_IROTH"},
    {S_IWOTH, "S_IWOTH"}, {S_IXOTH, "S_IXOTH"},
    {S_ISUID, "S_ISUID"}, {S_ISGID, "S_ISGID"},
    {S_ISVTX, "S_ISVTX"}, {0, NULL}};

static const value_name_t fcntl_cmd[] = {
    {F_DUPFD, "F_DUPFD"}, {F_GETFD, "F_GETFD"},   {F_SETFD, "F_SETFD"},
    {F_GETFL, "F_GETFL"}, {F_SETFL, "F_SETFL"},   {F_GETLK, "F_GETLK"},
    {F_SETLK, "F_SETLK"}, {F_SETLKW, "F_SETLKW"}, {0, NULL}};

static const value_name_t poll_events[] = {{POLLIN, "POLLIN"},
                                           {POLLPRI, "POLLPRI"},
                                           {POLLOUT, "POLLOUT"},
                                           {POLLERR, "POLLERR"},
                                           {POLLHUP, "POLLHUP"},
                                           {POLLNVAL, "POLLNVAL"},
                                           {0, NULL}};

// Clone flags are numerous, listing common ones
static const value_name_t clone_flags[] = {
    {CLONE_VM, "CLONE_VM"},
    {CLONE_FS, "CLONE_FS"},
    {CLONE_FILES, "CLONE_FILES"},
    {CLONE_SIGHAND, "CLONE_SIGHAND"},
    {CLONE_PTRACE, "CLONE_PTRACE"},
    {CLONE_VFORK, "CLONE_VFORK"},
    {CLONE_PARENT, "CLONE_PARENT"},
    {CLONE_THREAD, "CLONE_THREAD"},
    {CLONE_NEWNS, "CLONE_NEWNS"},
    {CLONE_SYSVSEM, "CLONE_SYSVSEM"},
    {CLONE_SETTLS, "CLONE_SETTLS"},
    {CLONE_PARENT_SETTID, "CLONE_PARENT_SETTID"},
    {CLONE_CHILD_CLEARTID, "CLONE_CHILD_CLEARTID"},
    {CLONE_DETACHED, "CLONE_DETACHED"},
    {CLONE_UNTRACED, "CLONE_UNTRACED"},
    {CLONE_CHILD_SETTID, "CLONE_CHILD_SETTID"},
    {CLONE_NEWUTS, "CLONE_NEWUTS"},
    {CLONE_NEWIPC, "CLONE_NEWIPC"},
    {CLONE_NEWUSER, "CLONE_NEWUSER"},
    {CLONE_NEWPID, "CLONE_NEWPID"},
    {CLONE_NEWNET, "CLONE_NEWNET"},
    {CLONE_IO, "CLONE_IO"},
    {CLONE_IO, "CLONE_IO"},
    {0, NULL}};

static const value_name_t ptrace_requests[] = {
    {PTRACE_TRACEME, "PTRACE_TRACEME"},
    {PTRACE_PEEKTEXT, "PTRACE_PEEKTEXT"},
    {PTRACE_PEEKDATA, "PTRACE_PEEKDATA"},
    {PTRACE_PEEKUSER, "PTRACE_PEEKUSER"},
    {PTRACE_POKETEXT, "PTRACE_POKETEXT"},
    {PTRACE_POKEDATA, "PTRACE_POKEDATA"},
    {PTRACE_POKEUSER, "PTRACE_POKEUSER"},
    {PTRACE_CONT, "PTRACE_CONT"},
    {PTRACE_KILL, "PTRACE_KILL"},
    {PTRACE_SINGLESTEP, "PTRACE_SINGLESTEP"},
    {PTRACE_GETREGS, "PTRACE_GETREGS"},
    {PTRACE_SETREGS, "PTRACE_SETREGS"},
    {PTRACE_GETFPREGS, "PTRACE_GETFPREGS"},
    {PTRACE_SETFPREGS, "PTRACE_SETFPREGS"},
    {PTRACE_ATTACH, "PTRACE_ATTACH"},
    {PTRACE_DETACH, "PTRACE_DETACH"},
    {PTRACE_GETFPXREGS, "PTRACE_GETFPXREGS"},
    {PTRACE_SETFPXREGS, "PTRACE_SETFPXREGS"},
    {PTRACE_SYSCALL, "PTRACE_SYSCALL"},
    {PTRACE_SETOPTIONS, "PTRACE_SETOPTIONS"},
    {PTRACE_GETEVENTMSG, "PTRACE_GETEVENTMSG"},
    {PTRACE_GETSIGINFO, "PTRACE_GETSIGINFO"},
    {PTRACE_SETSIGINFO, "PTRACE_SETSIGINFO"},
    {0, NULL}};

static const value_name_t *get_table(int type_id) {
  switch (type_id) {
  case TYPE_OPEN_FLAGS:
    return open_flags;
  case TYPE_ACCESS_MODE:
    return access_mode;
  case TYPE_MMAP_PROT:
    return mmap_prot;
  case TYPE_MMAP_FLAGS:
    return mmap_flags;
  case TYPE_LSEEK_WHENCE:
    return lseek_whence;
  case TYPE_SOCKET_DOMAIN:
    return socket_domain;
  case TYPE_SOCKET_TYPE:
    return socket_type;
  case TYPE_SOCKET_PROTO:
    return socket_proto;
  case TYPE_MREMAP_FLAGS:
    return mremap_flags;
  case TYPE_MSYNC_FLAGS:
    return msync_flags;
  case TYPE_ALL_PERMS:
    return all_perms;
  case TYPE_FCNTL_CMD:
    return fcntl_cmd;
  case TYPE_POLL_EVENTS:
    return poll_events;
  case TYPE_CLONE_FLAGS:
    return clone_flags;
  case TYPE_PTRACE_REQUEST:
    return ptrace_requests;
  default:
    return NULL;
  }
}

void print_bitmask(int type_id, unsigned long long val) {
  const value_name_t *table = get_table(type_id);
  if (!table) {
    printf("0x%llx", val);
    return;
  }

  int first = 1;
  unsigned long long rem = val;

  // Handle 0 specifically if it is a valid flag (like PROT_NONE=0, but
  // O_RDONLY=0) Actually O_RDONLY is 0. If val is 0, we must check if 0 is in
  // table.
  if (val == 0) {
    for (int i = 0; table[i].name; i++) {
      if (table[i].val == 0) {
        printf("%s", table[i].name);
        return;
      }
    }
    printf("0");
    return;
  }

  for (int i = 0; table[i].name; i++) {
    if (table[i].val != 0 && (val & table[i].val) == table[i].val) {
      if (!first)
        printf("|");
      printf("%s", table[i].name);
      rem &= ~table[i].val;
      first = 0;
    }
  }

  if (rem) {
    if (!first)
      printf("|");
    printf("0x%llx", rem);
  }
}

void print_enum(int type_id, unsigned long long val) {
  const value_name_t *table = get_table(type_id);
  if (!table) {
    printf("%llu", val);
    return;
  }

  for (int i = 0; table[i].name; i++) {
    if (table[i].val == val) {
      printf("%s", table[i].name);
      return;
    }
  }
  printf("%llu", val);
}
