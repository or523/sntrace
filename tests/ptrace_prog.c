#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>


int main() {
  pid_t child = fork();
  if (child == 0) {
    // Child process
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    // Stop ourselves so parent can see us
    raise(SIGSTOP);
    exit(0);
  } else {
    // Parent process
    int status;
    waitpid(child, &status, 0); // Wait for SIGSTOP

    // Detach
    // We are not tracing the parent, we are tracing the child of this program.
    // Wait, sntrace will trace THIS program (parent).
    // If sntrace traces the parent, it will see calls made by parent.
    // Parent calls waitpid.

    // Let's make the parent do some ptrace calls on child?
    // But sntrace follows forks now...
    // If sntrace follows forks, it will see child doing PTRACE_TRACEME.

    // Let's also have parent try a ptrace call
    // This might fail if it's not attached, but we just want to see the syscall
    // arguments. Actually, parent hasn't attached. Child did TRACEME. Parent
    // can do PTRACE_CONT.

    ptrace(PTRACE_CONT, child, NULL, NULL);

    waitpid(child, &status, 0);
  }
  return 0;
}
