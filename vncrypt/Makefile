
CFLAGS = -Wall -Werror -Wno-unused-result -g

LDFLAGS = 

PROGS = testrabin_bn testrabin_gc \
	testrsa_all testrsa_bn testrsa_gmp testrsa_org \
	testwilliams_bn \

COMM_OBJS = vnasymcrypt.o testcomm.o

all: $(PROGS)

testrsa_all: $(COMM_OBJS) vncrypt_bn.o vncrypt_gmp.o \
		testrsa_all.o vnrsa_bn.o vnrsa_gmp.o vnrsa_org.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto -lgmp

testrsa_bn: $(COMM_OBJS) testrsa_bn.o vnrsa_bn.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrsa_org: $(COMM_OBJS) testrsa_org.o vnrsa_org.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrsa_gmp: $(COMM_OBJS) testrsa_gmp.o vnrsa_gmp.o vncrypt_gmp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgmp

testrabin_bn: $(COMM_OBJS) testrabin_bn.o vncrypt_bn.o vnrabin_bn.o vnrabinenc_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrabin_gc: $(COMM_OBJS) testrabin_gc.o vnrabin_gc.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgcrypt -lgpg-error

testwilliams_bn: $(COMM_OBJS) testwilliams_bn.o vncrypt_bn.o vnwilliams_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto


%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(PROGS) vgcore.*

