CC = gcc
CFLAGS = -Wall -g
TARGET = sntrace


all: $(TARGET) dummy_prog multi_thread_prog fork_prog


OBJS = sntrace.o syscalls.o remote_mem.o arg_printers.o syscall_table.o constants.o

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

sntrace.o: sntrace.c syscalls.h remote_mem.h arg_printers.h syscall_table.h constants.h
	$(CC) $(CFLAGS) -c sntrace.c

syscalls.o: syscalls.c syscalls.h
	$(CC) $(CFLAGS) -c syscalls.c

remote_mem.o: remote_mem.c remote_mem.h
	$(CC) $(CFLAGS) -c remote_mem.c

arg_printers.o: arg_printers.c arg_printers.h remote_mem.h constants.h
	$(CC) $(CFLAGS) -c arg_printers.c

syscall_table.o: syscall_table.c syscall_table.h constants.h
	$(CC) $(CFLAGS) -c syscall_table.c

constants.o: constants.c constants.h
	$(CC) $(CFLAGS) -c constants.c


dummy_prog: dummy_prog.c
	$(CC) $(CFLAGS) -o dummy_prog dummy_prog.c

multi_thread_prog: multi_thread_prog.c
	$(CC) $(CFLAGS) -pthread -o multi_thread_prog multi_thread_prog.c

fork_prog: fork_prog.c
	$(CC) $(CFLAGS) -o fork_prog fork_prog.c

clean:
	rm -f $(TARGET) dummy_prog multi_thread_prog fork_prog

