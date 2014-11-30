
#include "vnrsa_gmp.h"
#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNRsaSign_GMP_CtxNew( args->mE );

	VN_Run( ctx, args );

	VNAsymCryptCtxFree( ctx );

	ctx = VNRsaEnc_GMP_CtxNew( args->mE );

	VN_Run( ctx, args );

	VNAsymCryptCtxFree( ctx );
}

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = test,
		.mSignCtxNew = NULL,
		.mEncCtxNew = NULL,
		.mDefaultE = 3
	};

	VN_Test( argc, argv, &env );

	return 0;
}

