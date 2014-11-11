
#include "vnrw_ctp.h"
#include "vnrw_gmp.h"

#include "vnasymcrypt.h"

#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	int ret = 0;

	struct vn_iovec pubKey, privKey;
	struct vn_iovec srcPlain, gmpPlain, gmpCipher, ctpPlain, ctpCipher;

	VN_GenSrc( args, &srcPlain );

	VNIovecPrint( "SrcText ", &srcPlain, 1 );

	VNAsymCryptCtx_t * gmpCtx = VNRWSign_GMP_CtxNew();
	VNAsymCryptCtx_t * ctpCtx = VNRWSign_CTP_CtxNew();

	printf( "###### GenKeys from GMP ######\n" );
	VNAsymCryptGenKeys( gmpCtx, args->mKeyBits );
	VN_PrintKey( gmpCtx );

	VNAsymCryptDumpPrivKey( gmpCtx, &pubKey, &privKey );

	printf( "###### LoadKeys to CTP ######\n" );
	VNAsymCryptLoadPrivKey( ctpCtx, &pubKey, &privKey );
	VN_PrintKey( ctpCtx );

	printf( "###### Try PrivEncrypt ######\n" );
	{
		ret = VNAsymCryptPrivEncrypt( ctpCtx, srcPlain.i.iov_base, args->mLength, &ctpCipher );
		printf( "CTP %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( gmpCtx, srcPlain.i.iov_base, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "CTP", &ctpCipher, 1 );
		VNIovecPrint( "GMP", &gmpCipher, 1 );
	}

	printf( "###### Try PubDecrypt ######\n" );
	{
		ret = VNAsymCryptPubDecrypt( ctpCtx, ctpCipher.i.iov_base, ctpCipher.i.iov_len,
			&ctpPlain, args->mLength );
		printf( "CTP %d\n", ret );

		ret = VNAsymCryptPubDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "GMP", &gmpPlain, 1 );
		VNIovecPrint( "CTP", &ctpPlain, 1 );
	}

	VNIovecFreeBufferAndTail( &gmpPlain );
	VNIovecFreeBufferAndTail( &gmpCipher );
	VNIovecFreeBufferAndTail( &ctpPlain );
	VNIovecFreeBufferAndTail( &ctpCipher );

	printf( "###### Try PubEncrypt ######\n" );
	{
		ret = VNAsymCryptPubEncrypt( gmpCtx, srcPlain.i.iov_base, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "GMP", &gmpCipher, 1 );
	}

	printf( "###### Try PrivDecrypt ######\n" );
	{
		ret = VNAsymCryptPrivDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "GMP", &gmpPlain, 1 );
	}

	VNAsymCryptCtxFree( gmpCtx );
	VNAsymCryptCtxFree( ctpCtx );

	VNIovecFreeBufferAndTail( &srcPlain );
	VNIovecFreeBufferAndTail( &gmpPlain );
	VNIovecFreeBufferAndTail( &gmpCipher );
	VNIovecFreeBufferAndTail( &ctpPlain );
	VNIovecFreeBufferAndTail( &ctpCipher );

	VNIovecFreeBufferAndTail( &pubKey );
	VNIovecFreeBufferAndTail( &privKey );
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

