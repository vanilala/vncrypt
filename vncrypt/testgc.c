
#include "vnrabin_gc.h"
#include "testcomm.h"

#include <gcrypt.h>

#include <stdio.h>
#include <stdlib.h>

void test( int keyBits, long length, int value, int encryptCount, int decryptCount )
{
	const char * gcryVersion = gcry_check_version( NULL );
	printf( "libgcrypt Version: %s\n", gcryVersion );

	//gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	VNAsymCryptCtx_t * ctx = VNRabin_GCCtx_New();

	VN_Test( ctx, keyBits, length, value, encryptCount, decryptCount );

	VNRabin_GCCtx_Free( ctx );
}

int main( int argc, const char * argv[] )
{
	if( argc < 6 )
	{
		printf( "Usage: %s <key bits> <plain length> <base value> "
			"<encrypt count> <decrypt count>\n", argv[0] );
		printf( "\t%s 64 15 1 10 10\n", argv[0] );
		return -1;
	}

	int keyBits = atoi( argv[1] );
	int length = atoi( argv[2] );
	int value = atoi( argv[3] );
	int encryptCount = atoi( argv[4] );
	int decryptCount = atoi( argv[5] );

	test( keyBits, length, value, encryptCount, decryptCount );

	return 0;
}

