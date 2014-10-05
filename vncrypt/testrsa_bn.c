
#include "vnrsa_bn.h"
#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNRsaSign_BNCtx_New( 3 );

	VN_Run( ctx, args );

	VNRsa_BNCtx_Free( ctx );

	ctx = VNRsaEnc_BNCtx_New( 3 );

	VN_Run( ctx, args );

	VNRsa_BNCtx_Free( ctx );
}

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = test,
		.mSignCtxNew = NULL,
		.mSignCtxFree = NULL,
		.mEncCtxNew = NULL,
		.mEncCtxFree = NULL
	};

	VN_Test( argc, argv, &env );

	return 0;
}

