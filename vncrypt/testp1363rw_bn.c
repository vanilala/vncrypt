
#include "vnp1363rw_bn.h"
#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNP1363RWSign_BN_CtxNew( args->mE );

	VN_Run( ctx, args );

	VNAsymCryptCtxFree( ctx );
}

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = test,
		.mSignCtxNew = NULL,
		.mEncCtxNew = NULL,
		.mDefaultE = 2
	};

	VN_Test( argc, argv, &env );

	return 0;
}

