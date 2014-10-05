
#include "vnrsa_org.h"
#include "testcomm.h"

#include <openssl/err.h>

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNRsaSign_ORGCtx_New( 3 );

	VN_Run( ctx, args );

	VNRsa_ORGCtx_Free( ctx );

	ctx = VNRsaEnc_ORGCtx_New( 3 );

	VN_Run( ctx, args );

	VNRsa_ORGCtx_Free( ctx );
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

	ERR_load_crypto_strings();

	VN_Test( argc, argv, &env );

	ERR_free_strings();

	return 0;
}

