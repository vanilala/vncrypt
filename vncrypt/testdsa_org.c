
#include "vndsa_org.h"
#include "testcomm.h"

#include <openssl/err.h>

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNDsaSign_ORG_CtxNew,
		.mEncCtxNew = NULL,
	};

	ERR_load_crypto_strings();

	VN_Test( argc, argv, &env );

	ERR_free_strings();

	return 0;
}

