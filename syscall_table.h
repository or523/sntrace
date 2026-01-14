#ifndef SYSCALL_TABLE_H
#define SYSCALL_TABLE_H

typedef enum {
  ARG_INT,
  ARG_HEX,
  ARG_PTR,
  ARG_STRING,
  ARG_FD,
  ARG_BUFFER,
  ARG_BITMASK, // val is a bitmask of flags
  ARG_ENUM     // val is one of a set of values
} arg_format_t;

typedef struct {
  arg_format_t format;
  int type_id; // ID for flags/enums, or Arg index for ARG_BUFFER (0-based)
} arg_def_t;

typedef struct {
  int nr;
  const char *name;
  int num_args;
  arg_def_t args[6];
} syscall_info_t;

// Get syscall info by number. Returns NULL if unknown.
const syscall_info_t *get_syscall_info(int nr);

#endif
