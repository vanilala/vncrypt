
#include "vnrabin_bn.h"

#include <openssl/bn.h>

#include <string.h>

int VN_BN_jacobi( const BIGNUM *za, const BIGNUM *zn, int *jacobi, BN_CTX *ctx )
{
	int ret = 0, e = 0, s = 0, mod = -1, amod = -1;

	BIGNUM zero, three, za1, zn1;

	BN_init( &zero );
	BN_init( &three );
	BN_init( &za1 );
	BN_init( &zn1 );

	BN_set_word( &zero, 0 );
	BN_set_word( &three, 3 );

	BN_copy( &za1, za );
	BN_copy( &zn1, zn );

	for( *jacobi = 1; 0 == ret; )
	{
		if( ! BN_is_odd( &zn1 ) ) { ret = -1; break; }
		if( BN_cmp( &zn1, &three ) < 0 ) { ret = -1; break; }
		if( ( BN_cmp( &za1, &zn1 ) > 0 ) || ( BN_cmp( &za1, &zero ) < 0 ) ) { ret = -1; break; }

		if( BN_is_zero( &za1 ) ) break;         // step1
		if( BN_is_one( &za1 ) ) break;          // step2

		for( e = 0; ; e++ )                     // step3
		{
			if( BN_is_odd( &za1 ) ) break;
			BN_rshift1( &za1, &za1 );
		}

		if( 0 == ( e % 2 ) )                    // step4
		{
			s = 1;
		} else {
			mod = BN_mod_word( &zn1, 8 );

			if( 1 == mod || 7 == mod ) s = 1;
			if( 3 == mod || 5 == mod ) s = -1;
		}

		amod = BN_mod_word( &za1, 4 );          // step5
		mod =  BN_mod_word( &zn1, 4 );
		if( 3 == mod && 3 == amod ) s = - s;

		BN_mod( &zn1, &zn1, &za1, ctx );    // step6

		*jacobi = ( *jacobi ) * s;              // step7

		if( BN_is_one( &za1 ) ) break;
		BN_swap( &za1, &zn1 );
	}

	BN_free( &zero );
	BN_free( &three );
	BN_free( &za1 );
	BN_free( &zn1 );

	return ret;
}

void VN_BN_dump_hex( const BIGNUM * za, struct iovec * hex )
{
	char * tmp = BN_bn2hex( za );

	hex->iov_len = strlen( tmp );
	hex->iov_base = strdup( tmp );

	OPENSSL_free( tmp );
}

void VN_BN_load_hex( const struct iovec * hex, BIGNUM * za )
{
	BIGNUM * tmp = NULL;

	BN_hex2bn( &tmp, hex->iov_base );
	BN_copy( za, tmp );

	BN_free( tmp );
}

