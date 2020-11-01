CC=gcc
CFLAGS=-g -O0 -Wall
LDFLAGS=-lpcap
DEPS=arp.o config.o util.o constant.o

all: ex2

ex2: ex2.o $(DEPS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ $^ -c $(CFLAGS)

clean:
	rm -rf *.o
	rm -rf ex2