
#include "vnmodrabin_gmp.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNModRabinSign_GMP_CtxNew,
		.mEncCtxNew = NULL,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

