CFLAGS:=-std=c11 -I../libsodium/src/libsodium/include -Wall -Wextra -pedantic -O2 $(CFLAGS) $(MORECFLAGS)
ARCHSUFFIX?=-$(shell uname -m)

all: crypta$(ARCHSUFFIX)

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

crypta.o: crypta.c $(wildcard *.h)
	$(CC) $(CFLAGS) $< -c -o $@


crypta$(ARCHSUFFIX): crypta.o fileutils.o cryptutils.o
	$(CC) $(CFLAGS) -L ../libsodium/src/libsodium/.libs/ $^ -o $@ -lsodium

bench-genkey: bench-genkey.o
	$(CC) $(CFLAGS) -L ../libsodium/src/libsodium/.libs/ $^ -o $@ -lsodium

clean:
	rm -f *.o crypta crypta$(ARCHSUFFIX)
