CC=gcc
CFLAGS=-g -O2 -Wall -fsanitize=address
LDFLAGS=-lpcap -fsanitize=address

.PHONY: all
all: testprog testrecv testsend

testprog: testprog.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

testrecv: testrecv.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

testsend: testsend.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-rm -rf testprog
	-rm -rf testrecv
	-rm -rf testsend