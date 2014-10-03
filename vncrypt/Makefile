
CFLAGS = -Wall -Werror -O4

LDFLAGS = 

PROGS = testbn testgc

all: $(PROGS)

testbn: testbn.o testcomm.o vnrabin_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testgc: testgc.o testcomm.o vnrabin_gc.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgcrypt -lgpg-error

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(PROGS) vgcore.*

