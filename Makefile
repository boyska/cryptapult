CFLAGS:=-std=c11 -Wall -pedantic -O2 $(CFLAGS) $(MORECFLAGS)
ARCHSUFFIX?=-$(shell uname -m)

all: crypta$(ARCHSUFFIX)

crypta.o: crypta.c
	$(CC) $(CFLAGS) -Wextra $^ -c -o $@

crypta$(ARCHSUFFIX): crypta.o tweetnacl.o
	$(CC) $(CFLAGS) -Wextra $^ -o $@

clean:
	rm -f *.o crypta crypta$(ARCHSUFFIX)
