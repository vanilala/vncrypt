
#include "vnrw_botan.h"
#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNRWSign_Botan_CtxNew( args->mE );

	VN_Run( ctx, args );

	VNAsymCryptCtxFree( ctx );
}

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = test,
		.mSignCtxNew = NULL,
		.mEncCtxNew = NULL,
		.mDefaultE = 2,
		.mDefaultKeyBits = 512
	};

	VN_Test( argc, argv, &env );

	return 0;
}

