CFLAGS:=-std=c11 -Wall -pedantic -O2 $(CFLAGS) $(MORECFLAGS)
ARCHSUFFIX?=-$(shell uname -m)

all: crypta$(ARCHSUFFIX)

%.o: %.c
	$(CC) $(CFLAGS) -Wextra $< -c -o $@

crypta.o: crypta.c $(wildcard *.h)
	$(CC) $(CFLAGS) -Wextra $< -c -o $@


tweetnacl.o: tweetnacl.c tweetnacl.h
	$(CC) $(CFLAGS) $< -c -o $@

crypta$(ARCHSUFFIX): crypta.o tweetnacl.o fileutils.o cryptutils.o
	$(CC) $(CFLAGS) -Wextra $^ -o $@

clean:
	rm -f *.o crypta crypta$(ARCHSUFFIX)
