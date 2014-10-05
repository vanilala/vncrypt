
#include "vnwilliams_bn.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNWilliamsEnc_BN_CtxNew,
		.mSignCtxFree = VNWilliamsEnc_BN_CtxFree,
		.mEncCtxNew = NULL,
		.mEncCtxFree = NULL
	};

	VN_Test( argc, argv, &env );

	return 0;
}

