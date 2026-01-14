#define _GNU_SOURCE
#include "arg_printers.h"
#include "remote_mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h> // for PATH_MAX
#include <unistd.h>

#include <fcntl.h>

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

void print_arg_int(int val) { printf("%d", val); }

void print_arg_hex(unsigned long long val) { printf("0x%llx", val); }

void print_arg_ptr(unsigned long long addr) {
  if (addr == 0) {
    printf("NULL");
  } else {
    printf("0x%llx", addr);
  }
}

void print_arg_string(pid_t pid, unsigned long long addr) {
  if (addr == 0) {
    printf("NULL");
    return;
  }

  char buf[256]; // Limits print length for simplicity
  ssize_t ret = read_remote_string(pid, (void *)addr, buf, sizeof(buf));

  if (ret < 0) {
    printf("0x%llx", addr); // Fallback if read fails
  } else {
    printf("\"%s\"", buf);
    // Note: read_remote_string guarantees null termination in our impl
    if ((size_t)ret >= sizeof(buf) - 1) {
      printf("...");
    }
  }
}

void print_arg_fd(pid_t pid, int fd) {
  char path[PATH_MAX];
  char link[64];

  if (fd == AT_FDCWD) {
    printf("AT_FDCWD");
    return;
  }

  if (fd < 0) {
    printf("%d", fd);
    return;
  }

  snprintf(link, sizeof(link), "/proc/%d/fd/%d", pid, fd);
  ssize_t len = readlink(link, path, sizeof(path) - 1);

  if (len >= 0) {
    path[len] = '\0';
    printf("%d<%s>", fd, path);
  } else {
    printf("%d", fd);
  }
}

void print_arg_buffer(pid_t pid, unsigned long long addr, int len) {
  if (addr == 0) {
    printf("NULL");
    return;
  }

  // Cap read length
  size_t read_len = (len > 32) ? 32 : (size_t)len;
  if (read_len == 0)
    read_len = 32; // Default if len unknown/0

  unsigned char buf[32];
  ssize_t ret = read_remote_memory(pid, (void *)addr, buf, read_len);

  if (ret < 0) {
    printf("0x%llx", addr);
  } else {
    printf("\"");
    for (ssize_t i = 0; i < ret; i++) {
      printf("\\x%02x", buf[i]);
    }
    if (ret < len || ret == 32)
      printf("...");
    printf("\"");
  }
}
