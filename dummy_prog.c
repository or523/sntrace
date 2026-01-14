#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>


int main() {
  printf("Dummy program started (PID: %d)\n", getpid());
  write(1, "Hello from dummy!\n", 18);
  return 0;
}
