
#include "vnwilliams_bn.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNWilliamsEnc_BNCtx_New,
		.mSignCtxFree = VNWilliamsEnc_BNCtx_Free,
		.mEncCtxNew = NULL,
		.mEncCtxFree = NULL
	};

	VN_Test( argc, argv, &env );

	return 0;
}

