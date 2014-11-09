
#include "vnrw_gmp.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNRWSign_GMP_CtxNew,
		.mEncCtxNew = VNRWEnc_GMP_CtxNew,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

