
#include "vnrabin_bn.h"
#include "vnrabinenc_bn.h"
#include "vnrabinenc_gmp.h"
#include "vnrabin_gc.h"
#include "vnrabin_lip.h"

#include "vnasymcrypt.h"

#include "testcomm.h"

#include <gcrypt.h>

void TestSign( VNTestArgs_t * args )
{
	int i = 0, ret = 0;
	unsigned char text[ 4096 ];

	struct vn_iovec pubKey, privKey;
	struct vn_iovec gcPlain, gcCipher, bnPlain, bnCipher, lipPlain, lipCipher;

	for( i = 0; i < args->mLength; i++ ) text[i] = args->mInitValue + i;

	VNAsymCryptCtx_t * bnCtx = VNRabin_BN_CtxNew();
	VNAsymCryptCtx_t * gcCtx = VNRabin_GC_CtxNew();
	VNAsymCryptCtx_t * lipCtx = VNRabin_LIP_CtxNew();

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
		ret = VNAsymCryptPrivEncrypt( bnCtx, text, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( gcCtx, text, args->mLength, &gcCipher );
		printf( "GC %d\n", ret );

		ret = VNAsymCryptPrivEncrypt( lipCtx, text, args->mLength, &lipCipher );
		printf( "LIP %d\n", ret );

		VNIovecPrint( "BN ", &bnCipher );
		VNIovecPrint( "GC", &gcCipher );
		VNIovecPrint( "LIP ", &lipCipher );
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

		VNIovecPrint( "BN ", &bnPlain );
		VNIovecPrint( "GC", &gcPlain );
		VNIovecPrint( "LIP", &lipPlain );
	}

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
	int i = 0, ret = 0;
	unsigned char text[ 4096 ];

	struct vn_iovec pubKey, privKey;
	struct vn_iovec bnPlain, bnCipher, gmpPlain, gmpCipher;

	for( i = 0; i < args->mLength; i++ ) text[i] = args->mInitValue + i;

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
		ret = VNAsymCryptPubEncrypt( bnCtx, text, args->mLength, &bnCipher );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPubEncrypt( gmpCtx, text, args->mLength, &gmpCipher );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "BN ", &bnCipher );
		VNIovecPrint( "GMP", &gmpCipher );
	}

	printf( "###### Try PrivDecrypt ######\n" );
	{
		ret = VNAsymCryptPrivDecrypt( bnCtx, bnCipher.i.iov_base, bnCipher.i.iov_len,
			&bnPlain, args->mLength );
		printf( "BN %d\n", ret );

		ret = VNAsymCryptPrivDecrypt( gmpCtx, gmpCipher.i.iov_base, gmpCipher.i.iov_len,
			&gmpPlain, args->mLength );
		printf( "GMP %d\n", ret );

		VNIovecPrint( "BN ", &bnPlain );
		VNIovecPrint( "GMP", &gmpPlain );
	}

	VNAsymCryptCtxFree( bnCtx );
	VNAsymCryptCtxFree( gmpCtx );

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

