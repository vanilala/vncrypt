
#include "mqqsig.h"

#include <string.h>
#include <stdio.h>

extern int crypto_sign_keypair(unsigned char* pk, unsigned char *sk);

extern int crypto_sign( unsigned char *sm,unsigned long long *smlen,
	const unsigned char *m,unsigned long long mlen, const unsigned char *sk);

extern int crypto_sign_open( unsigned char *m,unsigned long long *mlen,
	const unsigned char *sm,unsigned long long smlen, const unsigned char *pk);

extern int sign(unsigned char *hash, const unsigned char *sk, uint8_t result[N/8]);

extern int verify(const uint8_t Signature[N/8],
	const uint8_t publicKey[PUBLICKEY_SIZE_L][PUBLICKEY_SIZE_S], uint8_t hash[PUBLICKEY_SIZE_S]);


void test()
{
	uint8_t pk[ PUBLIC_KEY_SIZE_BYTES ] = { 0 }, sk[ PRIVATE_KEY_SIZE_BYTES ] = { 0 };

	unsigned char m[ 1024 * 64 ] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	unsigned char sm[ 1024 * 64 ] = { 0 };
	unsigned long long mlen = strlen( m ), smlen = sizeof( sm );

	int ret = 0, i = 0;

	crypto_sign_keypair( pk, sk );

#if 0
	ret = sign( m, sk, sm );

	printf( "sign %d\n", ret );

	ret = verify(sm, (const uint8_t (*)[PUBLICKEY_SIZE_S]) pk, m );

	printf( "verify %d\n", ret );

#else
	ret = crypto_sign( sm, &smlen, m, mlen, sk );

	printf( "sign %d, smlen %llu\n", ret, smlen );

	for( i = 0; i < smlen; i++ ) printf( "%02X ", sm[i] );
	printf( "\n" );

	ret = crypto_sign_open( m, &mlen, sm, smlen, pk );

	printf( "verify %d, mlen %llu\n", ret, mlen );
#endif
}

int main( int argc, const char * argv[] )
{
	test();

	return 0;
}

