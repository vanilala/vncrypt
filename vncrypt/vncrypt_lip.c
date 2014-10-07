
#include "vncrypt_lip.h"

#include "vnasymcrypt.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>

void VN_LIP_dump_hex( verylong za, struct vn_iovec * hex )
{
	int i = 0;
	struct vn_iovec bin;

	VN_LIP_dump_bin( za, &bin );

	hex->i.iov_len = bin.i.iov_len * 2;
	hex->i.iov_base = calloc( 1, hex->i.iov_len + 1 );

	for( i = 0; i < bin.i.iov_len; i++ )
	{
		sprintf( ((char*)hex->i.iov_base) + 2 * i, "%02X",
			((unsigned char*)bin.i.iov_base)[ i ] );
	}

	free( bin.i.iov_base );
}

void VN_LIP_load_hex( const struct vn_iovec * hex, verylong * za )
{
	zhsread( (char*)hex->i.iov_base, za );
}

void VN_LIP_dump_bin( verylong za, struct vn_iovec * bin )
{
	unsigned char * head = ztobitstring( za ), * tail = NULL, tmp;

	bin->i.iov_len = ( head[3] << 24 ) | ( head[2] << 16 ) | ( head[1] << 8 ) | ( head[0] );
	bin->i.iov_base = head;
	bin->next = NULL;

	//memmove( head, head + 4, bin->i.iov_len );

	/* reverse bitstring, for compatible with BN_bn2bin/mpz_export */
	tail = head + 4 + bin->i.iov_len - 1;
	for( ; head < tail; head++, tail-- )
	{
		tmp = *head;
		*head = *tail;
		*tail = tmp;
	}
}

void VN_LIP_load_bin( const unsigned char * ptr, int length, verylong * za )
{
	int i = 0;

	unsigned char * tmp = (unsigned char*)malloc( length + sizeof( int ) + 1 );

	/* set length */
	tmp[0] = length & 0xFF;
	tmp[1] = ( length >> 8 ) & 0xFF;
	tmp[2] = ( length >> 16 ) & 0xFF;
	tmp[3] = ( length >> 24 ) & 0xFF;

	//memcpy( tmp + 4, ptr, length );

	/* reverse bitstring, for compatible with BN_bin2bin/mpz_import */
	for( i = 0; i < length; i++ ) tmp[ i + 4 ] = ptr[ length - 1 - i ];
	zbitstringtoz( tmp, za );

	free( tmp );
}

