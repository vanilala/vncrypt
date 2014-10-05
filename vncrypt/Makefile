
CFLAGS = -Wall -Werror -Wno-unused-result -g

LDFLAGS = 

PROGS = testrabin_bn testrabin_gc \
	testrsa_bn testrsa_org \
	testwilliams_bn

all: $(PROGS)

testrabin_bn: testrabin_bn.o testcomm.o vncrypt_bn.o vnrabin_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrabin_gc: testrabin_gc.o testcomm.o vnrabin_gc.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgcrypt -lgpg-error

testwilliams_bn: testwilliams_bn.o testcomm.o vncrypt_bn.o vnwilliams_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrsa_bn: testrsa_bn.o testcomm.o vnrsa_bn.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrsa_org: testrsa_org.o testcomm.o vnrsa_org.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

rabin: rabin.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(PROGS) vgcore.*

