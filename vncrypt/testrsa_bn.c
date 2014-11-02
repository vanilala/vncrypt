
#include "vnrsa_bn.h"
#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNRsaSign_BN_CtxNew( args->mRsaE );

	VN_Run( ctx, args );

	VNAsymCryptCtxFree( ctx );

	ctx = VNRsaEnc_BN_CtxNew( args->mRsaE );

	VN_Run( ctx, args );

	VNAsymCryptCtxFree( ctx );
}

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = test,
		.mSignCtxNew = NULL,
		.mEncCtxNew = NULL,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

