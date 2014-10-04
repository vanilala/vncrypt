
CFLAGS = -Wall -Werror -Wno-unused-result -g

LDFLAGS = 

PROGS = testbn testgc \
	testpkbn

all: $(PROGS)

testbn: testbn.o testcomm.o vncrypt_bn.o vnrabin_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testpkbn: testpkbn.o testcomm.o vncrypt_bn.o vnwilliamspk_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testgc: testgc.o testcomm.o vnrabin_gc.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgcrypt -lgpg-error

rabin: rabin.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(PROGS) vgcore.*

