CC=gcc
CFLAGS=-g -O0 -Wall
LDFLAGS=-lpcap

all: ex2

ex2: ex2.o arp.o config.o util.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) -o $@ $^ -c

clean:
	rm -rf ex2.o arp.o config.o util.o
	rm -rf ex2