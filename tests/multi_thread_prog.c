#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>


void *thread_func(void *arg) {
  long tid = syscall(SYS_gettid);
  printf("Thread (TID %ld): Hello from thread!\n", tid);
  // Perform some syscalls
  write(1, "Thread writing\n", 15);
  return NULL;
}

int main() {
  pthread_t t1, t2;
  long tid = syscall(SYS_gettid);

  printf("Main (TID %ld): Starting threads\n", tid);

  if (pthread_create(&t1, NULL, thread_func, NULL) != 0) {
    perror("pthread_create");
    return 1;
  }

  if (pthread_create(&t2, NULL, thread_func, NULL) != 0) {
    perror("pthread_create");
    return 1;
  }

  write(1, "Main writing\n", 13);

  pthread_join(t1, NULL);
  pthread_join(t2, NULL);

  printf("Main (TID %ld): Threads finished\n", tid);
  return 0;
}
