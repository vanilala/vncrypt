
#include "vnrsa_gmp.h"
#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNRsaSign_GMP_CtxNew( 3 );

	VN_Run( ctx, args );

	VNRsa_GMP_CtxFree( ctx );

	ctx = VNRsaEnc_GMP_CtxNew( 3 );

	VN_Run( ctx, args );

	VNRsa_GMP_CtxFree( ctx );
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

