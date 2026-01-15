#ifndef CONSTANTS_H
#define CONSTANTS_H

// Type IDs for flag sets
enum arg_type_t {
  TYPE_NONE = 0,
  TYPE_OPEN_FLAGS,    // O_RDONLY, O_CREAT...
  TYPE_ACCESS_MODE,   // R_OK, W_OK...
  TYPE_MMAP_PROT,     // PROT_READ...
  TYPE_MMAP_FLAGS,    // MAP_PRIVATE...
  TYPE_LSEEK_WHENCE,  // SEEK_SET...
  TYPE_SOCKET_DOMAIN, // AF_INET...
  TYPE_SOCKET_TYPE,   // SOCK_STREAM...
  TYPE_SOCKET_PROTO,  // IPPROTO_TCP...
  TYPE_MREMAP_FLAGS,
  TYPE_MSYNC_FLAGS,
  TYPE_ALL_PERMS, // 0777 etc (mode_t)
  TYPE_CLONE_FLAGS,
  TYPE_FCNTL_CMD,
  TYPE_IOCTL_REQ, // Hard to map all, but maybe some?
  TYPE_POLL_EVENTS,
  TYPE_PTRACE_REQUEST
};

void print_bitmask(int type_id, unsigned long long val);
void print_enum(int type_id, unsigned long long val);

#endif
