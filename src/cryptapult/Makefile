CFLAGS:=-std=c11 -I../libsodium/src/libsodium/include -Wall -Wextra -pedantic -O2 $(CFLAGS) $(MORECFLAGS)
ARCHSUFFIX?=-$(shell uname -m)
FINAL_BINARIES:=crypta$(ARCHSUFFIX) bench-genkey genkey

all: crypta$(ARCHSUFFIX) genkey

%.o: %.c
	$(CC) $(CFLAGS) $< -c -o $@

crypta.o: crypta.c $(wildcard *.h)
	$(CC) $(CFLAGS) $< -c -o $@


crypta$(ARCHSUFFIX): crypta.o fileutils.o cryptutils.o
bench-genkey: bench-genkey.o
genkey: genkey.o keyfiles.o

$(FINAL_BINARIES):
	$(CC) $(CFLAGS) -L ../libsodium/src/libsodium/.libs/ $^ -o $@ -lsodium

clean:
	rm -f *.o crypta $(FINAL_BINARIES)
