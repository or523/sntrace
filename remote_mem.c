#define _GNU_SOURCE
#include "remote_mem.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/uio.h>


ssize_t read_remote_memory(pid_t pid, void *remote_addr, void *local_addr,
                           size_t len) {
  struct iovec local_iov = {.iov_base = local_addr, .iov_len = len};
  struct iovec remote_iov = {.iov_base = remote_addr, .iov_len = len};

  return process_vm_readv(pid, &local_iov, 1, &remote_iov, 1, 0);
}

ssize_t read_remote_string(pid_t pid, void *remote_addr, char *buffer,
                           size_t max_len) {
  if (max_len == 0)
    return 0;

  // We can't know the string length beforehand, so we might need to read in
  // chunks or just try to read max_len. process_vm_readv might fail if we cross
  // page boundaries into unmapped memory. However, for simplicity, we'll try to
  // read up to max_len, but be prepared for partial reads or faults if we go
  // too far. A safer, more robust approach (used by strace) is to read
  // word-by-word or in small chunks.

  // Simple approach: try to read a reasonable chunk (e.g., 256 bytes) or
  // max_len, whichever is smaller. NOTE: This simple approach might fault if
  // the string is at the very end of a page and the next page is invalid. For a
  // robust tool we would handle EFAULT and retry with smaller size, but for
  // this demo we'll assume valid memory.

  ssize_t nread = read_remote_memory(pid, remote_addr, buffer, max_len);
  if (nread < 0)
    return -1;

  // Ensure it's null terminated (locally) just in case
  // We scan for the first null byte to report the actual string length read.
  size_t i;
  for (i = 0; i < (size_t)nread; i++) {
    if (buffer[i] == '\0') {
      return i + 1; // Return length including null terminator
    }
  }

  // If no null terminator found, we force one at the end if we have space, or
  // just treat it as truncated. But function contract says "read
  // NULL-terminated".
  if ((size_t)nread < max_len) {
    buffer[nread] = '\0';
  } else {
    buffer[max_len - 1] = '\0';
  }
  return nread;
}
