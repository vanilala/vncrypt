
#include "vnrsa_org.h"
#include "testcomm.h"

#include <openssl/err.h>

void test( VNTestArgs_t * args )
{
	VNAsymCryptCtx_t * ctx = VNRsaSign_ORG_CtxNew( 3 );

	VN_Run( ctx, args );

	VNAsymCryptCtxFree( ctx );

	ctx = VNRsaEnc_ORG_CtxNew( 3 );

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

	ERR_load_crypto_strings();

	VN_Test( argc, argv, &env );

	ERR_free_strings();

	return 0;
}

