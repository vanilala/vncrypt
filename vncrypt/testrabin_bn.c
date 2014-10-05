
#include "vnrabin_bn.h"
#include "vnrabinenc_bn.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNRabin_BN_CtxNew,
		.mSignCtxFree = VNRabin_BN_CtxFree,
		.mEncCtxNew = VNRabinEnc_BN_CtxNew,
		.mEncCtxFree = VNRabinEnc_BN_CtxFree
	};

	VN_Test( argc, argv, &env );

	return 0;
}

