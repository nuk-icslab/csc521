CC=gcc
CFLAGS=-g -O2 -Wall -fsanitize=address
LDFLAGS=-lpcap -fsanitize=address
SRCDIR=src

.PHONY: all clean
all: testprog testrecv testsend

testprog: $(SRCDIR)/testprog.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

testrecv: $(SRCDIR)/testrecv.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

testsend: $(SRCDIR)/testsend.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	-rm -rf testprog
	-rm -rf testrecv
	-rm -rf testsend