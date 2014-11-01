

#include "vnrabin_ctp.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNRabinSign_CTP_CtxNew,
		.mEncCtxNew = VNRabinEnc_CTP_CtxNew,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

