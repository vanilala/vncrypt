
#include "vnmodrabin_bn.h"
#include "vnmodrabin_gc.h"
#include "vnmodrabin_lip.h"

#include "vnrabinenc_bn.h"
#include "vnrabinenc_gmp.h"

#include "vnasymcrypt.h"

#include "testcomm.h"

#include <gcrypt.h>

void TestSign( VNTestArgs_t * args )
{
	int ret = 0;

	struct vn_iovec pubKey, privKey;
	struct vn_iovec srcPlain, gcPlain, gcCipher, bnPlain, bnCipher, lipPlain, lipCipher;

	VN_GenSrc( args, &srcPlain );

	VNIovecPrint( "SrcText ", &srcPlain, 1 );

	VNAsymCryptCtx_t * bnCtx = VNModRabinSign_BN_CtxNew();
	VNAsymCryptCtx_t * gcCtx = VNModRabinSign_GC_CtxNew();
	VNAsymCryptCtx_t * lipCtx = VNModRabinSign_LIP_CtxNew();

	printf( "###### GenKeys from BN ######\n" );
	VNAsymCryptGenKeys( bnCtx, args->mKeyBits );
	VN_PrintKey( bnCtx );

	VNAsymCryptDumpPrivKey( bnCtx, &pubKey, &privKey );

	printf( "###### LoadKeys to GC ######\n" );
	VNAsymCryptLoadPrivKey( gcCtx, &pubKey, &privKey );
	VN_PrintKey( gcCtx );

	printf( "###### LoadKeys to LIP ######\n" );
	VNAsymCryptLoadPrivKey( lipCtx, &pubKey, &privKey );
	VN_PrintKey( lipCtx );

	printf( "###### Try PrivEncrypt ######\n" );
	{
		ret = VNAsymCryptPrivEncrypt( bnCtx, srcPlain.i.iov_base, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( gcCtx, srcPlain.i.iov_base, args->mLength, &gcCipher );
		printf( "GC %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( lipCtx, srcPlain.i.iov_base, args->mLength, &lipCipher );
		printf( "LIP %d\n", ret );

		VNIovecPrint( "BN ", &bnCipher, 1 );
		VNIovecPrint( "GC", &gcCipher, 1 );
		VNIovecPrint( "LIP ", &lipCipher, 1 );
	}

	printf( "###### Try PubDecrypt ######\n" );
	{
		ret = VNAsymCryptPubDecrypt( bnCtx, bnCipher.i.iov_base, bnCipher.i.iov_len,
			&bnPlain, args->mLength );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPubDecrypt( gcCtx, gcCipher.i.iov_base, gcCipher.i.iov_len,
			&gcPlain, args->mLength );
		printf( "GC %d\n", ret );

		ret = VNAsymCryptPubDecrypt( lipCtx, lipCipher.i.iov_base, lipCipher.i.iov_len,
			&lipPlain, args->mLength );
		printf( "LIP %d\n", ret );

		VNIovecPrint( "BN ", &bnPlain, 1 );
		VNIovecPrint( "GC", &gcPlain, 1 );
		VNIovecPrint( "LIP", &lipPlain, 1 );
	}

	VNIovecFreeBufferAndTail( &srcPlain );
	VNIovecFreeBufferAndTail( &bnPlain );
	VNIovecFreeBufferAndTail( &bnCipher );
	VNIovecFreeBufferAndTail( &gcPlain );
	VNIovecFreeBufferAndTail( &gcCipher );
	VNIovecFreeBufferAndTail( &lipPlain );
	VNIovecFreeBufferAndTail( &lipCipher );

	VNAsymCryptCtxFree( bnCtx );
	VNAsymCryptCtxFree( gcCtx );
	VNAsymCryptCtxFree( lipCtx );

	VNIovecFreeBufferAndTail( &pubKey );
	VNIovecFreeBufferAndTail( &privKey );
}

void TestEnc( VNTestArgs_t * args )
{
	int ret = 0;

	struct vn_iovec pubKey, privKey;
	struct vn_iovec srcPlain, bnPlain, bnCipher, gmpPlain, gmpCipher;

	VN_GenSrc( args, &srcPlain );

	VNIovecPrint( "SrcText ", &srcPlain, 1 );

	VNAsymCryptCtx_t * bnCtx = VNRabinEnc_BN_CtxNew();
	VNAsymCryptCtx_t * gmpCtx = VNRabinEnc_GMP_CtxNew();

	printf( "###### GenKeys from BN ######\n" );
	VNAsymCryptGenKeys( bnCtx, args->mKeyBits );
	VN_PrintKey( bnCtx );

	VNAsymCryptDumpPrivKey( bnCtx, &pubKey, &privKey );

	printf( "###### LoadKeys to GMP ######\n" );
	VNAsymCryptLoadPrivKey( gmpCtx, &pubKey, &privKey );
	VN_PrintKey( gmpCtx );

	printf( "###### Try PubEncrypt ######\n" );
	{
		ret = VNAsymCryptPubEncrypt( bnCtx, srcPlain.i.iov_base, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPubEncrypt( gmpCtx, srcPlain.i.iov_base, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "BN ", &bnCipher, 1 );
		VNIovecPrint( "GMP", &gmpCipher, 1 );
	}

	printf( "###### Try PrivDecrypt ######\n" );
	{
		ret = VNAsymCryptPrivDecrypt( bnCtx, bnCipher.i.iov_base, bnCipher.i.iov_len,
			&bnPlain, args->mLength );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPrivDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "BN ", &bnPlain, 1 );
		VNIovecPrint( "GMP", &gmpPlain, 1 );
	}

	VNAsymCryptCtxFree( bnCtx );
	VNAsymCryptCtxFree( gmpCtx );

	VNIovecFreeBufferAndTail( &srcPlain );
	VNIovecFreeBufferAndTail( &gmpPlain );
	VNIovecFreeBufferAndTail( &gmpCipher );
	VNIovecFreeBufferAndTail( &bnPlain );
	VNIovecFreeBufferAndTail( &bnCipher );

	VNIovecFreeBufferAndTail( &pubKey );
	VNIovecFreeBufferAndTail( &privKey );
}

void test( VNTestArgs_t * args )
{
	const char * gcryVersion = gcry_check_version( NULL );
	printf( "libgcrypt Version: %s\n", gcryVersion );

	//gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
	gcry_control (GCRYCTL_DISABLE_SECMEM, 0);
	gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

	TestSign( args );

	printf( "\n" );

	TestEnc( args );
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

