
CFLAGS = -Wall -Werror

PROGS = testbn

all: $(PROGS)

testbn: testbn.o testcomm.o vnrabin_bn.o
	gcc $(CFLAGS) -o $@ $^ -lm -lssl -lcrypto

%.o: %.c
	gcc $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(PROGS)

