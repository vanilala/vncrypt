
#include "vncrypt_gmp.h"

#include <string.h>
#include <stdlib.h>

void VN_GMP_dump_hex( const mpz_t za, struct vn_iovec * hex )
{
	hex->i.iov_len = ( mpz_sizeinbase( za, 2 ) / 8 + 1 ) * 2;
	hex->i.iov_base = calloc( 1, hex->i.iov_len + 1 );

	mpz_get_str( (char*)hex->i.iov_base, 16, za );
}

void VN_GMP_load_hex( const struct vn_iovec * hex, mpz_t za )
{
	mpz_set_str( za, (char*)hex->i.iov_base, 16 );
}

void VN_GMP_dump_bin( const mpz_t za, struct vn_iovec * bin )
{
	bin->i.iov_len = mpz_sizeinbase( za, 2 ) / 8 + 1;
	bin->i.iov_base = malloc( bin->i.iov_len + 1 );
	((char*)bin->i.iov_base)[ bin->i.iov_len ] = '\0';
	mpz_export( bin->i.iov_base, &bin->i.iov_len, 1, 1, 0, 0, za );
}

