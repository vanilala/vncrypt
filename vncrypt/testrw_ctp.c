
#include "vnrw_ctp.h"
#include "testcomm.h"

int main( int argc, const char * argv[] )
{
	VNTestEnv_t env = {
		.mTestMain = NULL,
		.mSignCtxNew = VNRWSign_CTP_CtxNew,
		.mEncCtxNew = NULL,
	};

	VN_Test( argc, argv, &env );

	return 0;
}

