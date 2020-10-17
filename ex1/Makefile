CC=gcc
CFLAGS=-g -O0 -Wall
LDFLAGS=-lpcap

testprog: testprog.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

testrecv: testrecv.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

testsend: testsend.c
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf testprog
	rm -rf testrecv
	rm -rf testsend