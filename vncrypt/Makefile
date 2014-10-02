
CFLAGS = -Wall -Werror -g

PROGS = testbn testgmp

all: $(PROGS)

testbn: testbn.o testcomm.o vnrabin_bn.o
	gcc $(CFLAGS) -o $@ $^ -lcrypto

testgmp: testgmp.o testcomm.o vnrabin_gmp.o
	gcc $(CFLAGS) -o $@ $^ -lgmp

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(PROGS)

