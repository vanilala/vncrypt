
#include "vncrypt_bn.h"

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

		BN_mod( &zn1, &zn1, &za1, ctx );        // step6

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

/***********************************************************

http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm


function extended_gcd(a, b)
    s := 0;    old_s := 1
    t := 1;    old_t := 0
    r := b;    old_r := a
    while r != 0
        quotient := old_r div r
        (old_r, r) := (r, old_r - quotient * r)
        (old_s, s) := (s, old_s - quotient * s)
        (old_t, t) := (t, old_t - quotient * t)       
    output "BÃ©zout coefficients:", (old_s, old_t)
    output "greatest common divisor:", old_r
    output "quotients by the gcd:", (t, s)

************************************************************/

void VN_BN_gcdext( const BIGNUM * za, const BIGNUM * zb,
	BIGNUM * zx, BIGNUM * zy, BIGNUM * gcd, BN_CTX * ctx )
{
	BIGNUM zs, old_s, zt, old_t, zr, old_r, quot, tmp;

	BN_init( &zs );
	BN_init( &old_s );
	BN_init( &zt );
	BN_init( &old_t );
	BN_init( &zr );
	BN_init( &old_r );
	BN_init( &quot );
	BN_init( &tmp );

	BN_set_word( &zs, 0 );
	BN_set_word( &old_s, 1 );
	BN_set_word( &zt, 1 );
	BN_set_word( &old_t, 0 );
	BN_copy( &zr, zb );
	BN_copy( &old_r, za );

	while( ! BN_is_zero( &zr ) )
	{
		BN_div( &quot, &tmp, &old_r, &zr, ctx );

		BN_mul( &tmp, &quot, &zr, ctx );
		BN_sub( &tmp, &old_r, &tmp );
		BN_copy( &old_r, &zr );
		BN_copy( &zr, &tmp );

		BN_mul( &tmp, &quot, &zs, ctx );
		BN_sub( &tmp, &old_s, &tmp );
		BN_copy( &old_s, &zs );
		BN_copy( &zs, &tmp );

		BN_mul( &tmp, &quot, &zt, ctx );
		BN_sub( &tmp, &old_t, &tmp );
		BN_copy( &old_t, &zt );
		BN_copy( &zt, &tmp );
	}

	BN_copy( zx, &old_s );
	BN_copy( zy, &old_t );
	BN_copy( gcd, &old_r );

	BN_free( &zs );
	BN_free( &old_s );
	BN_free( &zt );
	BN_free( &old_t );
	BN_free( &zr );
	BN_free( &old_r );
	BN_free( &quot );
	BN_free( &tmp );
}

void VN_BN_dump_hex( const BIGNUM * za, struct vn_iovec * hex )
{
	char * tmp = BN_bn2hex( za );

	hex->i.iov_len = strlen( tmp );
	hex->i.iov_base = strdup( tmp );

	OPENSSL_free( tmp );
}

void VN_BN_load_hex( const struct vn_iovec * hex, BIGNUM * za )
{
	BIGNUM * tmp = NULL;

	BN_hex2bn( &tmp, hex->i.iov_base );
	BN_copy( za, tmp );

	BN_free( tmp );
}

void VN_BN_dump_bin( const BIGNUM * za, struct vn_iovec * bin )
{
	bin->i.iov_len = BN_num_bytes( za );
	bin->i.iov_base = malloc( bin->i.iov_len + 1);
	BN_bn2bin( za, bin->i.iov_base );
}

