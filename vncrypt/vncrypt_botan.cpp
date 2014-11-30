
#include "vncrypt_botan.h"

#include <botan/bigint.h>

using namespace Botan;

void VN_Botan_dump_hex( const void * za, struct vn_iovec * hex )
{
	BigInt * tmp = (BigInt*)za;

	hex->i.iov_len = tmp->encoded_size( BigInt::Hexadecimal );
	hex->i.iov_base = calloc( 1, hex->i.iov_len + 1 );

	BigInt::encode( (byte*)hex->i.iov_base, *tmp, BigInt::Hexadecimal );
}

void VN_Botan_load_hex( const struct vn_iovec * hex, void * za )
{
	BigInt * tmp = (BigInt*)za;

	*tmp = BigInt::decode( (byte*)hex->i.iov_base, hex->i.iov_len, BigInt::Hexadecimal );
}

void VN_Botan_dump_bin( const void * za, struct vn_iovec * bin )
{
	BigInt * tmp = (BigInt*)za;

	bin->i.iov_len = tmp->encoded_size( BigInt::Binary );
	bin->i.iov_base = calloc( 1, bin->i.iov_len + 1 );

	BigInt::encode( (byte*)bin->i.iov_base, *tmp, BigInt::Binary );
}

