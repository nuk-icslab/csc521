CC=gcc
CFLAGS=-g -O0 -Wall
LDFLAGS=-lpcap

testprog: testprog.c
	$(CC) $(CGLAGS) -o $@ $^ $(LDFLAGS)

testrecv: testrecv.c
	$(CC) $(CGLAGS) -o $@ $^ $(LDFLAGS)

testsend: testsend.c
	$(CC) $(CGLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf testprog
	rm -rf testrecv
	rm -rf testsend