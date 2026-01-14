#ifndef ARG_PRINTERS_H
#define ARG_PRINTERS_H

#define ARG_PRINTERS_H

#include "constants.h"
#include <sys/types.h>


void print_arg_int(int val);
void print_arg_hex(unsigned long long val);
void print_arg_string(pid_t pid, unsigned long long addr);
void print_arg_fd(pid_t pid, int fd);
void print_arg_ptr(unsigned long long addr);
void print_arg_buffer(pid_t pid, unsigned long long addr, int len);

#endif
