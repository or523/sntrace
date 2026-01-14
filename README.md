# 🚀 sntrace

**sntrace** ("Seccomp Notification Trace") is a lightweight, modern system call tracer for Linux. It intercepts and inspects system calls using the powerful `SECCOMP_RET_USER_NOTIF` feature, eliminating the high overhead associated with traditional `ptrace`-based tools like `strace`.

---

## ✨ Features

*   ⚡ **Zero-Overhead Interception**: Uses seccomp user notifications to avoid process context switching.
*   🔍 **Deep Argument Inspection**:
    *   **Dynamic Buffers**: Automatically detects and prints buffer contents with correct lengths (e.g., `write`, `read`).
    *   **Smart FD Resolution**: Resolves file descriptors to actual paths (e.g., `3</etc/passwd>`) and handles `AT_FDCWD` correctly.
    *   **Bitmask Decoding**: Fully decodes flags for `open`, `mmap` (including `MAP_DENYWRITE`), `access`, and more.
    *   **String Decoding**: Safely reads and displays string arguments from the child process's memory.
*   🧵 **Modern Syscall Support**: Includes support for newer syscalls like `rseq` (restartable sequences).
*   🛡️ **Safe Tracing**: Non-intrusive monitoring that respects process isolation.

## 🛠️ Building

`sntrace` is built for Linux (x86_64).

**Requirements:**
*   Linux Kernel 5.0+ (for `SECCOMP_RET_USER_NOTIF`)
*   GCC or Clang
*   Make

**Compile:**

```bash
make
```

This generates:
*   `sntrace`: The tracer executable.
*   `dummy_prog`: A test program for usage verification.

## 💻 Usage

Run `sntrace` followed by the command you want to trace. Note that it typically requires `sudo` or `CAP_SYS_ADMIN` capability to use seccomp notifications.

```bash
sudo ./sntrace <command> [arguments...]
```

### Examples

**Trace `ls -la`:**
```bash
sudo ./sntrace ls -la
```

**Trace the test program:**
```bash
sudo ./sntrace ./dummy_prog
```

## 📸 Sample Output

Witness the detail `sntrace` provides compared to raw hex dumps:

```
sntrace: tracing ./dummy_prog (pid 4700)...
...
openat(AT_FDCWD, "/etc/ld.so.cache", 0x80000, 0x0)
mmap(NULL, 19491, PROT_READ, MAP_PRIVATE, 3</etc/ld.so.cache>, 0)
close(3</etc/ld.so.cache>)
...
mmap(NULL, 2170256, PROT_READ, MAP_PRIVATE|MAP_DENYWRITE, 3</usr/lib/libc.so.6>, 0)
...
rseq(0x7e177a283060, 32, 0, 1392848979)
...
write(1<pipe:[29082]>, "Hello from dummy!\n", 18)
exit_group(0)
```

Key highlights in this output:
*   `AT_FDCWD` correctly identified in `openat`.
*   File descriptors like `3` resolved to `</etc/ld.so.cache>`.
*   `MAP_DENYWRITE` flag decoded in `mmap`.
*   `rseq` syscall recognized and arguments parsed.
*   `write` buffer printed cleanly as a string ("Hello from dummy!\n") with exact length.

## 🏗️ Architecture

*   **`sntrace.c`**: The core engine. Sets up the seccomp filter, forks the child, and runs the notification loop using `poll()` to handle events and child exit signals via `pidfd`.
*   **`syscall_table.c`**: Massive database mapping syscall numbers to names and argument types.
*   **`arg_printers.c`**: Specialized logic for reading remote memory and formatting arguments (strings, buffers, FDs).
*   **`remote_mem.c`**: Utilities for `process_vm_readv` to safely access child memory.

## ⚠️ Limitations

*   **x86_64 Only**: Currently optimized for 64-bit Intel/AMD architectures.
*   **Entry-Only Tracing**: Due to the nature of seccomp notifications, `sntrace` inspects syscalls *before* they execute. Capturing return values would require emulation or `ptrace`.

---

*Handcrafted with ❤️ for better Linux observability.*
