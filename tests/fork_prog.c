#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


int main() {
  pid_t pid = fork();

  if (pid < 0) {
    perror("fork");
    return 1;
  }

  if (pid > 0) {
    // Parent
    printf("Parent (PID %d) existing. Child is %d.\n", getpid(), pid);
    return 0;
  } else {
    // Child
    // Sleep to ensure parent exits first
    struct timespec ts = {1, 0};
    nanosleep(&ts, NULL);

    printf("Child (PID %d) alive after parent exit.\n", getpid());

    // Perform some syscalls
    write(1, "Child writing\n", 14);

    return 0;
  }
}
