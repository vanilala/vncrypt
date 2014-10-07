
#include "vncrypt_gc.h"

unsigned long VN_gcry_mpi_mod_ui( const gcry_mpi_t za, unsigned long m )
{
	unsigned long ret = 0;

	if( m == 4 )
	{
		if( gcry_mpi_test_bit( za, 0 ) ) ret |= 0x1;
		if( gcry_mpi_test_bit( za, 1 ) ) ret |= 0x2;
	} else if( m == 8 ) {
		if( gcry_mpi_test_bit( za, 0 ) ) ret |= 0x1;
		if( gcry_mpi_test_bit( za, 1 ) ) ret |= 0x2;
		if( gcry_mpi_test_bit( za, 2 ) ) ret |= 0x4;
	} else if( m == 16 ) {
		if( gcry_mpi_test_bit( za, 0 ) ) ret |= 0x1;
		if( gcry_mpi_test_bit( za, 1 ) ) ret |= 0x2;
		if( gcry_mpi_test_bit( za, 2 ) ) ret |= 0x4;
		if( gcry_mpi_test_bit( za, 3 ) ) ret |= 0x8;
	} else {
		gcry_mpi_t r = gcry_mpi_new( 128 );
		gcry_mpi_t d = gcry_mpi_set_ui( NULL, m );

		gcry_mpi_mod( r, za, d );

		gcry_mpi_print( GCRYMPI_FMT_USG, (unsigned char*)&ret, sizeof( ret ), NULL, r );

		gcry_mpi_release( r );
		gcry_mpi_release( d );
	}

	return ret;
}


int VN_gcry_mpi_jacobi( const gcry_mpi_t za, const gcry_mpi_t zn, int *jacobi )
{
	int ret = 0, e = 0, s = 0, mod = -1, amod = -1;

	gcry_mpi_t za1, zn1;

	za1 = gcry_mpi_copy( za );
	zn1 = gcry_mpi_copy( zn );

	for( *jacobi = 1; 0 == ret; )
	{
		if( ! gcry_mpi_test_bit( zn1, 0 ) ) { ret = -1; break; }
		if( gcry_mpi_cmp_ui( zn1, 3 ) < 0 ) { ret = -1; break; }
		if( ( gcry_mpi_cmp( za1, zn1 ) > 0 )
			|| ( gcry_mpi_cmp_ui( za1, 0 ) < 0 ) ) { ret = -1; break; }

		if( gcry_mpi_cmp_ui( za1, 0 ) == 0 ) break;      // step1
		if( gcry_mpi_cmp_ui( za1, 1 ) == 0 ) break;      // step2

		for( e = 0; ; e++ )                              // step3
		{
			if( gcry_mpi_test_bit( za1, 0 ) ) break;
			gcry_mpi_rshift( za1, za1, 1 );
		}

		if( 0 == ( e % 2 ) )                             // step4
		{
			s = 1;
		} else {
			mod = VN_gcry_mpi_mod_ui( zn1, 8 );

			if( 1 == mod || 7 == mod ) s = 1;
			if( 3 == mod || 5 == mod ) s = -1;
		}

		amod = VN_gcry_mpi_mod_ui( za1, 4 );             // step5
		mod = VN_gcry_mpi_mod_ui( zn1, 4 );
		if( 3 == mod && 3 == amod ) s = - s;

		gcry_mpi_mod( zn1, zn1, za1 );                   // step6

		*jacobi = ( *jacobi ) * s;                       // step7

		if( gcry_mpi_cmp_ui( za1, 1 ) == 0 ) break;
		gcry_mpi_swap( za1, zn1 );
	}

	gcry_mpi_release( za1 );
	gcry_mpi_release( zn1 );

	return ret;
}

void VN_GC_dump_hex( const gcry_mpi_t za, struct vn_iovec * hex )
{
	hex->i.iov_len = ( gcry_mpi_get_nbits( za ) / 8 + 1 ) * 4;
	hex->i.iov_base = calloc( 1, hex->i.iov_len + 1 );

	gcry_mpi_print( GCRYMPI_FMT_HEX, (unsigned char*)hex->i.iov_base,
		hex->i.iov_len, &( hex->i.iov_len ), za );

	if( hex->i.iov_len > 0 ) hex->i.iov_len--;
}

void VN_GC_dump_bin( const gcry_mpi_t za, struct vn_iovec * bin )
{
	bin->i.iov_len = gcry_mpi_get_nbits( za ) / 8 + 1;
	bin->i.iov_base = malloc( bin->i.iov_len );
	gcry_mpi_print( GCRYMPI_FMT_USG, (unsigned char*)bin->i.iov_base,
			bin->i.iov_len, &( bin->i.iov_len ), za );
}

