
#include "vnmodrabin_gc.h"
#include "testcomm.h"

#include <gcrypt.h>

int main( int argc, const char * argv[] )
{
	const char * gcryVersion = gcry_check_version( NULL );
	printf( "libgcrypt Version: %s\n", gcryVersion );

	//gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNModRabinSign_GC_CtxNew,
		.mEncCtxNew = NULL,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

