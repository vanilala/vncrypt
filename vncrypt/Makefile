
CFLAGS = -Wall -Werror -g
#-Wno-unused-result

CPPFLAGS = $(CFLAGS) -Wno-invalid-offsetof

LDFLAGS = 

PROGS = testrsa_all testrsa_bn testrsa_gmp testrsa_org \
	testrabin_all \
	testmodrabin_bn testmodrabin_gc testmodrabin_lip \
	testrabin_gmp testrabin_bn \
	testwilliams_bn \
	testdsa_org testecdsa_org \
	testmodrabin_ctp testecies_ctp testelgamal_ctp

COMM_OBJS = vnasymcrypt.o testcomm.o

LIP_OBJS = lip/lip.o

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

testrabin_all: $(COMM_OBJS) \
		vncrypt_bn.o vncrypt_gmp.o vncrypt_gc.o vncrypt_lip.o \
		testrabin_all.o \
		vnmodrabin_bn.o vnmodrabin_gc.o vnmodrabin_lip.o \
		vnrabinenc_bn.o vnrabinenc_gmp.o \
		$(LIP_OBJS)
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto -lgmp -lgcrypt -lgpg-error -lm

testmodrabin_bn: $(COMM_OBJS) vncrypt_bn.o testmodrabin_bn.o vnmodrabin_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testmodrabin_gc: $(COMM_OBJS) vncrypt_gc.o testmodrabin_gc.o vnmodrabin_gc.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgcrypt -lgpg-error

testmodrabin_lip: $(COMM_OBJS) vncrypt_lip.o testmodrabin_lip.o vnmodrabin_lip.o \
	$(LIP_OBJS)
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lm

$(LIP_OBJS): CFLAGS = -Ilip -g
vnmodrabin_lip.o: CFLAGS += -Ilip -Wno-unused-function
vncrypt_lip.o: CFLAGS += -Ilip -Wno-unused-function
testmodrabin_lip.o: CFLAGS += -Ilip -Wno-unused-function

testrabin_bn: $(COMM_OBJS) testrabin_bn.o vnrabinenc_bn.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrabin_gmp: $(COMM_OBJS) testrabin_gmp.o vnrabinenc_gmp.o vncrypt_gmp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgmp

testwilliams_bn: $(COMM_OBJS) testwilliams_bn.o vncrypt_bn.o vnwilliams_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testdsa_org: $(COMM_OBJS) testdsa_org.o vndsa_org.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testecdsa_org: $(COMM_OBJS) testecdsa_org.o vnecdsa_org.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testmodrabin_ctp: $(COMM_OBJS) vncrypt_ctp.o testmodrabin_ctp.o vnmodrabin_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

testecies_ctp: $(COMM_OBJS) testecies_ctp.o vnecies_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

testelgamal_ctp: $(COMM_OBJS) testelgamal_ctp.o vnelgamal_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

test: $(PROGS)
	for cmd in $(PROGS) ; \
	do \
		./$$cmd; \
	done

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

%.o: %.cpp
	gcc $(CPPFLAGS) -c -o $@ $<

clean:
	rm -f *.o lip/*.o $(PROGS) vgcore.* core

