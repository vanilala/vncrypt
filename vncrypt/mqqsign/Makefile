
PROGS = testmqq

all: $(PROGS)

testmqq: testmqq.o mqq-sign.o mqq-verify.o keygen.o
	gcc $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(PROGS) *.o
