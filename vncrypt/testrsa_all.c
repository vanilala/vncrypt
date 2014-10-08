
#include "vnrsa_bn.h"
#include "vnrsa_gmp.h"
#include "vnrsa_org.h"

#include "vnasymcrypt.h"

#include "testcomm.h"

void test( VNTestArgs_t * args )
{
	int ret = 0;

	struct vn_iovec pubKey, privKey;
	struct vn_iovec srcPlain, orgPlain, orgCipher, bnPlain, bnCipher, gmpPlain, gmpCipher;

	VN_GenSrc( args, &srcPlain );

	VNIovecPrint( "SrcText ", &srcPlain );

	VNAsymCryptCtx_t * orgCtx = VNRsaSign_ORG_CtxNew( 3 );
	VNAsymCryptCtx_t * bnCtx = VNRsaSign_BN_CtxNew( 3 );
	VNAsymCryptCtx_t * gmpCtx = VNRsaSign_GMP_CtxNew( 3 );

	printf( "###### GenKeys from ORG ######\n" );
	VNAsymCryptGenKeys( orgCtx, args->mKeyBits );
	VN_PrintKey( orgCtx );

	VNAsymCryptDumpPrivKey( orgCtx, &pubKey, &privKey );

	printf( "###### LoadKeys to BN ######\n" );
	VNAsymCryptLoadPrivKey( bnCtx, &pubKey, &privKey );
	VN_PrintKey( bnCtx );

	printf( "###### LoadKeys to GMP ######\n" );
	VNAsymCryptLoadPrivKey( gmpCtx, &pubKey, &privKey );
	VN_PrintKey( gmpCtx );

	printf( "###### Try PrivEncrypt ######\n" );
	{
		ret = VNAsymCryptPrivEncrypt( orgCtx, srcPlain.i.iov_base, args->mLength, &orgCipher );
		printf( "ORG %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( bnCtx, srcPlain.i.iov_base, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( gmpCtx, srcPlain.i.iov_base, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "ORG", &orgCipher );
		VNIovecPrint( "BN ", &bnCipher );
		VNIovecPrint( "GMP", &gmpCipher );
	}

	printf( "###### Try PubDecrypt ######\n" );
	{
		ret = VNAsymCryptPubDecrypt( orgCtx, orgCipher.i.iov_base, orgCipher.i.iov_len,
			&orgPlain, args->mLength );
		printf( "ORG %d\n", ret );

		ret = VNAsymCryptPubDecrypt( bnCtx, bnCipher.i.iov_base, bnCipher.i.iov_len,
			&bnPlain, args->mLength );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPubDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "ORG", &orgPlain );
		VNIovecPrint( "BN ", &bnPlain );
		VNIovecPrint( "GMP", &gmpPlain );
	}

	VNIovecFreeBufferAndTail( &orgPlain );
	VNIovecFreeBufferAndTail( &orgCipher );
	VNIovecFreeBufferAndTail( &gmpPlain );
	VNIovecFreeBufferAndTail( &gmpCipher );
	VNIovecFreeBufferAndTail( &bnPlain );
	VNIovecFreeBufferAndTail( &bnCipher );

	printf( "###### Try PubEncrypt ######\n" );
	{
		ret = VNAsymCryptPubEncrypt( orgCtx, srcPlain.i.iov_base, args->mLength, &orgCipher );
		printf( "ORG %d\n", ret );

		ret = VNAsymCryptPubEncrypt( bnCtx, srcPlain.i.iov_base, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPubEncrypt( gmpCtx, srcPlain.i.iov_base, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "ORG", &orgCipher );
		VNIovecPrint( "BN ", &bnCipher );
		VNIovecPrint( "GMP", &gmpCipher );
	}

	printf( "###### Try PrivDecrypt ######\n" );
	{
		ret = VNAsymCryptPrivDecrypt( orgCtx, orgCipher.i.iov_base, orgCipher.i.iov_len,
			&orgPlain, args->mLength );
		printf( "ORG %d\n", ret );

		ret = VNAsymCryptPrivDecrypt( bnCtx, bnCipher.i.iov_base, bnCipher.i.iov_len,
			&bnPlain, args->mLength );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPrivDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "ORG", &orgPlain );
		VNIovecPrint( "BN ", &bnPlain );
		VNIovecPrint( "GMP", &gmpPlain );
	}

	VNAsymCryptCtxFree( orgCtx );
	VNAsymCryptCtxFree( bnCtx );
	VNAsymCryptCtxFree( gmpCtx );

	VNIovecFreeBufferAndTail( &srcPlain );
	VNIovecFreeBufferAndTail( &orgPlain );
	VNIovecFreeBufferAndTail( &orgCipher );
	VNIovecFreeBufferAndTail( &gmpPlain );
	VNIovecFreeBufferAndTail( &gmpCipher );
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

