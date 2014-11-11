
#include "vnrw_ctp.h"
#include "vnrw_gmp.h"
#include "vnrw_bn.h"

#include "vnasymcrypt.h"

#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	int ret = 0;

	struct vn_iovec pubKey, privKey;
	struct vn_iovec srcPlain, gmpPlain, gmpCipher, ctpPlain, ctpCipher, bnPlain, bnCipher;

	VN_GenSrc( args, &srcPlain );

	VNIovecPrint( "SrcText ", &srcPlain, 1 );

	VNAsymCryptCtx_t * gmpCtx = VNRWSign_GMP_CtxNew();
	VNAsymCryptCtx_t * ctpCtx = VNRWSign_CTP_CtxNew();
	VNAsymCryptCtx_t * bnCtx = VNRWSign_BN_CtxNew();

	printf( "###### GenKeys from GMP ######\n" );
	VNAsymCryptGenKeys( gmpCtx, args->mKeyBits );
	VN_PrintKey( gmpCtx );

	VNAsymCryptDumpPrivKey( gmpCtx, &pubKey, &privKey );

	printf( "###### LoadKeys to CTP ######\n" );
	VNAsymCryptLoadPrivKey( ctpCtx, &pubKey, &privKey );
	VN_PrintKey( ctpCtx );

	printf( "###### LoadKeys to BN ######\n" );
	VNAsymCryptLoadPrivKey( bnCtx, &pubKey, &privKey );
	VN_PrintKey( ctpCtx );

	printf( "###### Try PrivEncrypt ######\n" );
	{
		ret = VNAsymCryptPrivEncrypt( gmpCtx, srcPlain.i.iov_base, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( ctpCtx, srcPlain.i.iov_base, args->mLength, &ctpCipher );
		printf( "CTP %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( bnCtx, srcPlain.i.iov_base, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		VNIovecPrint( "GMP", &gmpCipher, 1 );
		VNIovecPrint( "CTP", &ctpCipher, 1 );
		VNIovecPrint( "BN", &bnCipher, 1 );
	}

	printf( "###### Try PubDecrypt ######\n" );
	{
		ret = VNAsymCryptPubDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		ret = VNAsymCryptPubDecrypt( ctpCtx, ctpCipher.i.iov_base, ctpCipher.i.iov_len,
			&ctpPlain, args->mLength );
		printf( "CTP %d\n", ret );

		ret = VNAsymCryptPubDecrypt( bnCtx, bnCipher.i.iov_base, bnCipher.i.iov_len,
			&bnPlain, args->mLength );
		printf( "BN %d\n", ret );

		VNIovecPrint( "GMP", &gmpPlain, 1 );
		VNIovecPrint( "CTP", &ctpPlain, 1 );
		VNIovecPrint( "BN", &bnPlain, 1 );
	}

	VNIovecFreeBufferAndTail( &gmpPlain );
	VNIovecFreeBufferAndTail( &gmpCipher );
	VNIovecFreeBufferAndTail( &ctpPlain );
	VNIovecFreeBufferAndTail( &ctpCipher );
	VNIovecFreeBufferAndTail( &bnPlain );
	VNIovecFreeBufferAndTail( &bnCipher );

	printf( "###### Try PubEncrypt ######\n" );
	{
		ret = VNAsymCryptPubEncrypt( gmpCtx, srcPlain.i.iov_base, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		ret = VNAsymCryptPubEncrypt( bnCtx, srcPlain.i.iov_base, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		VNIovecPrint( "GMP", &gmpCipher, 1 );
		VNIovecPrint( "BN", &bnCipher, 1 );
	}

	printf( "###### Try PrivDecrypt ######\n" );
	{
		ret = VNAsymCryptPrivDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		ret = VNAsymCryptPrivDecrypt( bnCtx, bnCipher.i.iov_base, bnCipher.i.iov_len,
			&bnPlain, args->mLength );
		printf( "BN %d\n", ret );

		VNIovecPrint( "GMP", &gmpPlain, 1 );
		VNIovecPrint( "BN", &bnPlain, 1 );
	}

	VNAsymCryptCtxFree( gmpCtx );
	VNAsymCryptCtxFree( ctpCtx );
	VNAsymCryptCtxFree( bnCtx );

	VNIovecFreeBufferAndTail( &srcPlain );
	VNIovecFreeBufferAndTail( &gmpPlain );
	VNIovecFreeBufferAndTail( &gmpCipher );
	VNIovecFreeBufferAndTail( &ctpPlain );
	VNIovecFreeBufferAndTail( &ctpCipher );
	VNIovecFreeBufferAndTail( &bnPlain );
	VNIovecFreeBufferAndTail( &bnCipher );

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

