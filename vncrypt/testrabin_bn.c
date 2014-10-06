
#include "vnrabin_bn.h"
#include "vnrabinenc_bn.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNRabin_BN_CtxNew,
		.mEncCtxNew = VNRabinEnc_BN_CtxNew,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

