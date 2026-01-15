CC = gcc
CFLAGS = -Wall -g -pthread

PROGS = dummy_prog multi_thread_prog fork_prog

all: $(PROGS)

dummy_prog: dummy_prog.c
	$(CC) $(CFLAGS) -o dummy_prog dummy_prog.c

multi_thread_prog: multi_thread_prog.c
	$(CC) $(CFLAGS) -o multi_thread_prog multi_thread_prog.c

fork_prog: fork_prog.c
	$(CC) $(CFLAGS) -o fork_prog fork_prog.c

clean:
	rm -f $(PROGS)
