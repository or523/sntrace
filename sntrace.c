#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "arg_printers.h"
#include "constants.h"
#include "syscall_table.h"
#include "syscalls.h"

// ... (other includes) ...

// Fallback definitions in case headers are old
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

// We need these structs even if headers don't have them fully defined in some
// envs
#ifndef SECCOMP_IOCTL_NOTIF_RECV
struct seccomp_notif {
  __u64 id;
  __u32 pid;
  __u32 flags;
  struct seccomp_data data;
};

struct seccomp_notif_resp {
  __u64 id;
  __u64 val;
  __s32 error;
  __u32 flags;
};

#define SECCOMP_IOC_MAGIC '!'
#define SECCOMP_IO_NOTIF_RECV _IOWR(SECCOMP_IOC_MAGIC, 0, struct seccomp_notif)
#define SECCOMP_IO_NOTIF_SEND                                                  \
  _IOWR(SECCOMP_IOC_MAGIC, 1, struct seccomp_notif_resp)
#define SECCOMP_IO_NOTIF_ID_VALID _IOR(SECCOMP_IOC_MAGIC, 2, __u64)

#define SECCOMP_IOCTL_NOTIF_RECV SECCOMP_IO_NOTIF_RECV
#define SECCOMP_IOCTL_NOTIF_SEND_RESP SECCOMP_IO_NOTIF_SEND
#endif

#ifndef SECCOMP_IOCTL_NOTIF_SEND_RESP
#define SECCOMP_IOCTL_NOTIF_SEND_RESP SECCOMP_IOCTL_NOTIF_SEND
#endif

static void tracer_loop(int notify_fd, int pidfd, pid_t pid) {
  struct seccomp_notif req;
  struct seccomp_notif_resp resp;
  struct seccomp_data *data = &req.data;
  struct pollfd pfds[2];

  while (1) {
    memset(&req, 0, sizeof(req));
    memset(&resp, 0, sizeof(resp));
    memset(pfds, 0, sizeof(pfds));

    pfds[0].fd = notify_fd;
    pfds[0].events = POLLIN;
    pfds[1].fd = pidfd;
    pfds[1].events = POLLIN;

    // Wait for notification or child exit
    if (poll(pfds, 2, -1) < 0) {
      if (errno == EINTR)
        continue;
      perror("poll");
      break;
    }

    if (pfds[1].revents & POLLIN) {
      // Child exited
      break;
    }

    if (!(pfds[0].revents & POLLIN)) {
      continue;
    }

    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) < 0) {
      if (errno == EINTR)
        continue;
      perror("ioctl(NOTIF_RECV)");
      break;
    }

    const syscall_info_t *info = get_syscall_info(data->nr);
    if (info) {
      printf("%s(", info->name);
      for (int i = 0; i < info->num_args; i++) {
        if (i > 0)
          printf(", ");
        unsigned long long val = data->args[i];
        switch (info->args[i].format) {
        case ARG_INT:
          print_arg_int((int)val);
          break;
        case ARG_HEX:
          print_arg_hex(val);
          break;
        case ARG_PTR:
          print_arg_ptr(val);
          break;
        case ARG_STRING:
          print_arg_string(pid, val);
          break;
        case ARG_FD:
          print_arg_fd(pid, (int)val);
          break;
        case ARG_BUFFER: {
          int len_idx = info->args[i].type_id;
          int buf_len = 32; // Default cap
          if (len_idx >= 0 && len_idx < info->num_args) {
            // Retrieve length from the specified argument
            // Note: arguments are unsigned long long (64-bit)
            buf_len = (int)data->args[len_idx];
            // Cap strictly to 32 here, or let printer handle it?
            // User said "capped by 32 max bytes".
            // print_arg_buffer likely takes a length and prints up to that.
            if (buf_len > 32)
              buf_len = 32;
            if (buf_len < 0)
              buf_len = 0;
          }
          print_arg_buffer(pid, val, buf_len);
          break;
        }
        case ARG_BITMASK:
          print_bitmask(info->args[i].type_id, val);
          break;
        case ARG_ENUM:
          print_enum(info->args[i].type_id, val);
          break;
        }
      }
      printf(")\n");
    } else {
      // Fallback for unknown syscalls
      const char *name = syscall_name(data->nr);
      if (name) {
        printf("Syscall: %s (", name);
      } else {
        printf("Syscall: %d (", data->nr);
      }
      // Print raw hex args
      for (int i = 0; i < 6; i++) {
        if (i > 0)
          printf(", ");
        printf("0x%llx", (unsigned long long)data->args[i]);
      }
      printf(")\n");
    }

    // Tell kernel to continue the syscall
    resp.id = req.id;
    resp.flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    resp.val = 0;
    resp.error = 0;

    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND_RESP, &resp) < 0) {
      if (errno != ENOENT) {
        perror("ioctl(NOTIF_SEND_RESP)");
      }
    }
  }
}

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

// Restartable sequences
#ifndef __NR_rseq
#define __NR_rseq 334
#endif

// Helper to find the seccomp listener FD in the child's file descriptors
static int find_seccomp_listener(pid_t pid) {
  char path[512];
  char link_dest[512];
  DIR *dir;
  struct dirent *entry;
  int listener_fd = -1;
  int pidfd = -1;

  // Open pidfd for the child
  pidfd = syscall(__NR_pidfd_open, pid, 0);
  if (pidfd < 0) {
    perror("pidfd_open");
    return -1;
  }

  snprintf(path, sizeof(path), "/proc/%d/fd", pid);
  dir = opendir(path);
  if (!dir) {
    // Child might not have created fd dir yet, or exited
    close(pidfd);
    return -1;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_type != DT_LNK)
      continue;

    snprintf(path, sizeof(path), "/proc/%d/fd/%s", pid, entry->d_name);
    ssize_t len = readlink(path, link_dest, sizeof(link_dest) - 1);
    if (len != -1) {
      link_dest[len] = '\0';
      // fprintf(stderr, "Debug: Scanning %s -> %s\n", path, link_dest);
      if (strstr(link_dest, "anon_inode:seccomp notify") != NULL ||
          strstr(link_dest, "anon_inode:[seccomp]") != NULL) {

        // Use pidfd_getfd to duplicate the FD
        int target_fd = atoi(entry->d_name);
        int fd = syscall(__NR_pidfd_getfd, pidfd, target_fd, 0);

        if (fd >= 0) {
          listener_fd = fd;
          break;
        } else {
          perror("pidfd_getfd");
        }
      }
    }
  }

  closedir(dir);
  close(pidfd);
  return listener_fd;
}

static int install_syscall_filter(void) {
  struct sock_filter filter[] = {
      // Load architecture
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, arch))),

      // Return SECCOMP_RET_USER_NOTIF for all syscalls
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
  };

  struct sock_fprog prog = {
      .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
      .filter = filter,
  };

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
    perror("prctl(NO_NEW_PRIVS)");
    return -1;
  }

  int listener = syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
                         SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
  if (listener < 0) {
    perror("seccomp");
    return -1;
  }

  return listener;
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <command> [args...]\n", argv[0]);
    return 1;
  }

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    // Child
    // Install filter
    int notify_fd = install_syscall_filter();
    if (notify_fd < 0) {
      exit(1);
    }

    // Any syscall from here on is trapped, including execvp.
    // The parent must attach and handle notifications.
    // If the parent isn't ready, we block here.

    execvp(argv[1], &argv[1]);
    perror("execvp");
    exit(1);
  } else {
    // Parent
    int pidfd = syscall(__NR_pidfd_open, pid, 0);
    if (pidfd < 0) {
      perror("pidfd_open");
      kill(pid, SIGKILL);
      return 1;
    }

    int notify_fd = -1;
    // Poll for the seccomp listener
    // Try for a limited time (e.g. 5 seconds)
    for (int i = 0; i < 50; i++) {
      notify_fd = find_seccomp_listener(pid);
      if (notify_fd >= 0)
        break;
      usleep(100000); // 100ms
    }

    if (notify_fd < 0) {
      fprintf(stderr,
              "Failed to find seccomp listener FD in child (timed out)\n");
      kill(pid, SIGKILL);
      close(pidfd);
      return 1;
    }

    printf("sntrace: tracing %s (pid %d)...\n", argv[1], pid);
    tracer_loop(notify_fd, pidfd, pid);
    close(notify_fd);
    close(pidfd);
  }

  return 0;
}
