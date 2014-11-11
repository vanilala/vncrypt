
CFLAGS = -Wall -Werror -g
#-Wno-unused-result

CPPFLAGS = $(CFLAGS) -Wno-invalid-offsetof

LDFLAGS =

######################################################################

BN_PROGS = testrsa_bn testmodrabin_bn testrabin_bn testwilliams_bn

ORG_PROGS = testrsa_org testdsa_org testecdsa_org

GMP_PROGS = testrsa_gmp testrabin_gmp testrw_gmp testmodrabin_gmp

CTP_PROGS = testrsa_ctp testrabin_ctp testrw_ctp testecies_ctp testelgamal_ctp

GC_PROGS = testmodrabin_gc 

LIP_PROGS = testmodrabin_lip

PROGS = $(LIP_PROGS) $(BN_PROGS) $(ORG_PROGS) $(GMP_PROGS) $(CTP_PROGS) $(GC_PROGS) \
	testrsa_all testrabin_all testrw_all \
	testmqq_org

######################################################################

COMM_OBJS = vnasymcrypt.o testcomm.o

LIP_OBJS = lip/lip.o

MQQ_OBJS = mqqsign/keygen.o mqqsign/mqq-sign.o mqqsign/mqq-verify.o

######################################################################

all: $(PROGS)

testmodrabin_lip: $(COMM_OBJS) vncrypt_lip.o testmodrabin_lip.o vnmodrabin_lip.o \
	$(LIP_OBJS)
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lm

$(LIP_OBJS): CFLAGS = -Ilip -g
vnmodrabin_lip.o: CFLAGS += -Ilip -Wno-unused-function
vncrypt_lip.o: CFLAGS += -Ilip -Wno-unused-function
testmodrabin_lip.o: CFLAGS += -Ilip -Wno-unused-function

testmqq_org: $(COMM_OBJS) testmqq_org.o vnmqq_org.o $(MQQ_OBJS)
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(MQQ_OBJS): CFLAGS = -g

#=====================================================================

testrsa_all: $(COMM_OBJS) vncrypt_bn.o vncrypt_gmp.o vncrypt_ctp.o \
		testrsa_all.o vnrsa_bn.o vnrsa_gmp.o vnrsa_org.o vnrsa_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto -lgmp -lcryptopp

testrabin_all: $(COMM_OBJS) \
		vncrypt_bn.o vncrypt_gmp.o vncrypt_gc.o vncrypt_lip.o \
		testrabin_all.o \
		vnmodrabin_bn.o vnmodrabin_gc.o vnmodrabin_lip.o \
		vnrabinenc_bn.o vnrabinenc_gmp.o \
		$(LIP_OBJS)
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto -lgmp -lgcrypt -lgpg-error -lm

testrw_all: $(COMM_OBJS) vncrypt_ctp.o vnrw_ctp.o vncrypt_gmp.o vnrw_gmp.o testrw_all.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgmp -lcryptopp

#=====================================================================

testrsa_gmp: $(COMM_OBJS) testrsa_gmp.o vnrsa_gmp.o vncrypt_gmp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgmp

testmodrabin_gmp: $(COMM_OBJS) vncrypt_gmp.o testmodrabin_gmp.o vnmodrabin_gmp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgmp

testrabin_gmp: $(COMM_OBJS) testrabin_gmp.o vnrabinenc_gmp.o vncrypt_gmp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgmp

testrw_gmp: $(COMM_OBJS) vncrypt_gmp.o testrw_gmp.o vnrw_gmp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgmp

#=====================================================================

testrsa_bn: $(COMM_OBJS) testrsa_bn.o vnrsa_bn.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrsa_org: $(COMM_OBJS) testrsa_org.o vnrsa_org.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testmodrabin_bn: $(COMM_OBJS) vncrypt_bn.o testmodrabin_bn.o vnmodrabin_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testrabin_bn: $(COMM_OBJS) testrabin_bn.o vnrabinenc_bn.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testwilliams_bn: $(COMM_OBJS) testwilliams_bn.o vncrypt_bn.o vnwilliams_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testdsa_org: $(COMM_OBJS) testdsa_org.o vndsa_org.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

testecdsa_org: $(COMM_OBJS) testecdsa_org.o vnecdsa_org.o vncrypt_bn.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcrypto

#=====================================================================

testrsa_ctp: $(COMM_OBJS) testrsa_ctp.o vnrsa_ctp.o vncrypt_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

testrabin_ctp: $(COMM_OBJS) testrabin_ctp.o vnrabin_ctp.o vncrypt_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

testrw_ctp: $(COMM_OBJS) vncrypt_ctp.o testrw_ctp.o vnrw_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

testecies_ctp: $(COMM_OBJS) testecies_ctp.o vnecies_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

testelgamal_ctp: $(COMM_OBJS) testelgamal_ctp.o vnelgamal_ctp.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lcryptopp

#=====================================================================

testmodrabin_gc: $(COMM_OBJS) vncrypt_gc.o testmodrabin_gc.o vnmodrabin_gc.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS) -lgcrypt -lgpg-error

#=====================================================================

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
	rm -f *.o $(LIP_OBJS) $(MQQ_OBJS) $(PROGS) vgcore.* core

