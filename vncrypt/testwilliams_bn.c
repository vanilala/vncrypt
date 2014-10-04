
#include "vnwilliams_bn.h"
#include "testcomm.h"

#include <stdio.h>
#include <stdlib.h>

void test( int keyBits, long length, int value, int encryptCount, int decryptCount )
{
	VNAsymCryptCtx_t * ctx = VNWilliamsEnc_BNCtx_New();

	VN_Test( ctx, keyBits, length, value, encryptCount, decryptCount );

	VNWilliamsEnc_BNCtx_Free( ctx );
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

