#ifndef REMOTE_MEM_H
#define REMOTE_MEM_H

#include <sys/types.h>
#include <unistd.h>

// Read data from child process memory
ssize_t read_remote_memory(pid_t pid, void *remote_addr, void *local_addr,
                           size_t len);

// Read a NULL-terminated string from child process memory
// Returns bytes read on success (including partial reads if truncated), -1 on
// error.
ssize_t read_remote_string(pid_t pid, void *remote_addr, char *buffer,
                           size_t max_len);

#endif
