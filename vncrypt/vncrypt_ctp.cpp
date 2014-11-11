
#include "vncrypt_ctp.h"

#include <crypto++/hex.h>
#include <crypto++/integer.h>

#include <stdio.h>

using namespace CryptoPP;

void VN_CTP_dump_hex( void * integer, struct vn_iovec * hex )
{
	HexEncoder encoder;

	Integer * p = (Integer*)integer;
	p->Encode( encoder, p->MinEncodedSize() );

	hex->i.iov_base = calloc( 1, encoder.MaxRetrievable() + 1 );
	hex->i.iov_len = encoder.Get( (byte*)hex->i.iov_base, encoder.MaxRetrievable() );
}

void VN_CTP_load_hex( const struct vn_iovec * hex, void * integer )
{
	Integer * p = (Integer*)integer;

	HexDecoder decoder;
	decoder.Put2( (byte*)hex->i.iov_base, hex->i.iov_len, 1, 1 );

	p->Decode( decoder, decoder.MaxRetrievable() );
}

