

#include "vnrabinenc_gmp.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = NULL,
		.mEncCtxNew = VNRabinEnc_GMP_CtxNew,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

