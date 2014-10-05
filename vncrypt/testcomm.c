
#include "testcomm.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>

void VN_Run( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args );
static void VN_Run_Sign( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args );
static void VN_Run_Enc( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args );

int VN_Test( int argc, const char * argv[], VNTestEnv_t * env )
{
	if( argc < 6 )
	{
		printf( "Usage: %s <key bits> <plain length> <base value> "
				"<encrypt count> <decrypt count>\n", argv[0] );
		printf( "\t%s 64 15 1 10 10\n", argv[0] );
		return -1;
	}

	VNTestArgs_t args;
	args.mArgc = argc;
	args.mArgv = argv;
	args.mKeyBits = atoi( argv[1] );
	args.mLength = atoi( argv[2] );
	args.mInitValue = atoi( argv[3] );
	args.mEncryptCount = atoi( argv[4] );
	args.mDecryptCount = atoi( argv[5] );

	if( NULL != env->mTestMain )
	{
		env->mTestMain( &args );
	} else {
		if( NULL != env->mSignCtxNew )
		{
			VNAsymCryptCtx_t * ctx = env->mSignCtxNew();
			VN_Run( ctx, &args );
			env->mSignCtxFree( ctx );
		}

		if( NULL != env->mEncCtxNew )
		{
			VNAsymCryptCtx_t * ctx = env->mEncCtxNew();
			VN_Run( ctx, &args );
			env->mEncCtxFree( ctx );
		}
	}

	return 0;
}

void VN_Run( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args )
{
	if( ctx->mType < 100 )
	{
		printf( "\nStart to run signature scheme ......\n\n" );
		VN_Run_Sign( ctx, args );
	} else {
		printf( "\nStart to run encryption scheme ......\n\n" );
		VN_Run_Enc( ctx, args );
	}
}

double VN_RunTime( unsigned long long prevUsec, unsigned long long * nowUsec )
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	unsigned long long r = tv.tv_sec;
	r *= 1000000;
	r += tv.tv_usec;

	prevUsec = r - prevUsec;
	* nowUsec = r;

	return prevUsec / 1000000.0;
}

void VN_PrintKey( VNAsymCryptCtx_t * ctx )
{
	struct vn_iovec pubKey, privKey, * iter = NULL;

	VNAsymCryptDumpPubKey( ctx, &pubKey );

	for( iter = &pubKey; NULL != iter; iter = iter->next )
	{
		printf( "PubKey : %4zd, %s\n", iter->i.iov_len, (char*)iter->i.iov_base );
	}

	VNIovecFreeBufferAndTail( &pubKey );

	VNAsymCryptDumpPrivKey( ctx, &pubKey, &privKey );

	for( iter = &privKey; NULL != iter; iter = iter->next )
	{
		printf( "PirvKey: %4zd, %s\n", iter->i.iov_len, (char*)iter->i.iov_base );
	}

	VNIovecFreeBufferAndTail( &pubKey );
	VNIovecFreeBufferAndTail( &privKey );
}

void VN_Run_Sign( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args )
{
	int i = 0, ret = 0;
	unsigned char text[ 4096 ], tmp;
	struct vn_iovec plainText, cipherText;

	struct vn_iovec hexPubKey, hexPrivKey;

	unsigned long long nowUsec = 0;
	double interval = 0;

	for( i = 0; i < args->mLength; i++ ) text[i] = args->mInitValue + i;

	// 1. generate keys
	VN_RunTime( 0, &nowUsec );

	VNAsymCryptGenKeys( ctx, args->mKeyBits );
	VN_PrintKey( ctx );

	interval = VN_RunTime( nowUsec, &nowUsec );
	printf( "GenKeys time %.6f\n", interval );

	// 2. save pub/priv key, clear ctx
	VNAsymCryptDumpPrivKey( ctx, &hexPubKey, &hexPrivKey );
	VNAsymCryptClearKeys( ctx );

	// 3. restore priv key, do PrivEncrypt
	printf( "Load PrivKey ......\n" );
	VNAsymCryptLoadPrivKey( ctx, &hexPubKey, &hexPrivKey );

	VN_PrintKey( ctx );

	for( i = 0; i < args->mEncryptCount && 0 == ret; i++ )
	{
		ret = VNAsymCryptPrivEncrypt( ctx, text, args->mLength, &cipherText );
		VNIovecFreeBufferAndTail( &cipherText );

		if( 0 != ret )
		{
			printf( "PrivEncrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	ret = VNAsymCryptPrivEncrypt( ctx, text, args->mLength, &cipherText );

	interval = VN_RunTime( nowUsec, &nowUsec );
	printf( "PrivEncrypt %d, time %.6f, ops %d/s\n",
		args->mEncryptCount, interval, (int)(args->mEncryptCount / interval ) );

	printf( "Cipher Text length: %zd\n", cipherText.i.iov_len );

	VNAsymCryptClearKeys( ctx );

	// 4. restore pub key, do PubDecrypt
	printf( "Load PubKey ......\n" );
	VNAsymCryptLoadPubKey( ctx, &hexPubKey );

	VN_PrintKey( ctx );

	for( i = 0; i < args->mDecryptCount; i++ )
	{
		ret = VNAsymCryptPubDecrypt( ctx, (unsigned char*)cipherText.i.iov_base,
			cipherText.i.iov_len, &plainText );
		VNIovecFreeBufferAndTail( &plainText );

		if( 0 != ret )
		{
			printf( "PubDecrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	interval = VN_RunTime( nowUsec, &nowUsec );
	printf( "PubDecrypt %d, time %.6f, ops %d/s\n",
		args->mDecryptCount, interval, (int)(args->mDecryptCount / interval ) );

	VNAsymCryptPubDecrypt( ctx, (unsigned char*)cipherText.i.iov_base, cipherText.i.iov_len, &plainText );

	printf( "Plain Text length: %zd\n", plainText.i.iov_len );

	if( args->mLength < plainText.i.iov_len )
	{
		VNIovecPrint( "Plain Text", &plainText );
	}

	assert( args->mLength >= plainText.i.iov_len );

	printf( "Verifing ......\n" );
	for( i = 0; i < args->mLength - plainText.i.iov_len; i++ )
	{
		if( 0 != text[i] ) printf( "%d %d\n", i, text[i] );
	}

	if( 0 != memcmp( text + args->mLength - plainText.i.iov_len, plainText.i.iov_base, plainText.i.iov_len ) )
	{
		printf( "FAIL\n" );
		for( i = args->mLength - plainText.i.iov_len; i < args->mLength; i++ )
		{
			tmp = ((unsigned char*)plainText.i.iov_base)[ i - args->mLength + plainText.i.iov_len ];
			if( text[ i ] != tmp )
			{
				printf( "%d %d %d\n", i, text[ i ], tmp );
			}
		}
	} else {
		printf( "OK\n" );
	}

	VNIovecFreeBufferAndTail( &plainText );
	VNIovecFreeBufferAndTail( &cipherText );
	VNIovecFreeBufferAndTail( &hexPubKey );
	VNIovecFreeBufferAndTail( &hexPrivKey );
}

static void VN_Run_Enc( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args )
{
	int i = 0, ret = 0;
	unsigned char text[ 4096 ], tmp;
	struct vn_iovec plainText, cipherText;

	struct vn_iovec hexPubKey, hexPrivKey;

	unsigned long long nowUsec = 0;
	double interval = 0;

	for( i = 0; i < args->mLength; i++ ) text[i] = args->mInitValue + i;

	// 1. generate keys
	VN_RunTime( 0, &nowUsec );

	VNAsymCryptGenKeys( ctx, args->mKeyBits );
	VN_PrintKey( ctx );

	interval = VN_RunTime( nowUsec, &nowUsec );
	printf( "GenKeys time %.6f\n", interval );

	// 2. save pub/priv key, clear ctx
	VNAsymCryptDumpPrivKey( ctx, &hexPubKey, &hexPrivKey );
	VNAsymCryptClearKeys( ctx );

	// 3. restore pub key, do PubEncrypt
	printf( "Load PubKey ......\n" );
	VNAsymCryptLoadPubKey( ctx, &hexPubKey );

	VN_PrintKey( ctx );

	for( i = 0; i < args->mEncryptCount && 0 == ret; i++ )
	{
		ret = VNAsymCryptPubEncrypt( ctx, text, args->mLength, &cipherText );
		VNIovecFreeBufferAndTail( &cipherText );

		if( 0 != ret )
		{
			printf( "PubEncrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	ret = VNAsymCryptPubEncrypt( ctx, text, args->mLength, &cipherText );

	interval = VN_RunTime( nowUsec, &nowUsec );
	printf( "PubEncrypt %d, time %.6f, ops %d/s\n",
		args->mEncryptCount, interval, (int)(args->mEncryptCount / interval ) );

	printf( "Cipher Text length: %zd\n", cipherText.i.iov_len );

	VNAsymCryptClearKeys( ctx );

	// 4. restore priv key, do PrivDecrypt
	printf( "Load PrivKey ......\n" );
	VNAsymCryptLoadPrivKey( ctx, &hexPubKey, &hexPrivKey );

	VN_PrintKey( ctx );

	for( i = 0; i < args->mDecryptCount; i++ )
	{
		ret = VNAsymCryptPrivDecrypt( ctx, (unsigned char*)cipherText.i.iov_base,
			cipherText.i.iov_len, &plainText );
		VNIovecFreeBufferAndTail( &plainText );

		if( 0 != ret )
		{
			printf( "PrivEncrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	interval = VN_RunTime( nowUsec, &nowUsec );
	printf( "PrivDecrypt %d, time %.6f, ops %d/s\n",
		args->mDecryptCount, interval, (int)(args->mDecryptCount / interval ) );

	VNAsymCryptPrivDecrypt( ctx, (unsigned char*)cipherText.i.iov_base, cipherText.i.iov_len, &plainText );

	printf( "Plain Text length: %zd\n", plainText.i.iov_len );

	assert( args->mLength >= plainText.i.iov_len );

	printf( "Verifing ......\n" );
	for( i = 0; i < args->mLength - plainText.i.iov_len; i++ )
	{
		if( 0 != text[i] ) printf( "%d %d\n", i, text[i] );
	}

	if( 0 != memcmp( text + args->mLength - plainText.i.iov_len, plainText.i.iov_base, plainText.i.iov_len ) )
	{
		printf( "FAIL\n" );
		for( i = args->mLength - plainText.i.iov_len; i < args->mLength; i++ )
		{
			tmp = ((unsigned char*)plainText.i.iov_base)[ i - args->mLength + plainText.i.iov_len ];
			if( text[ i ] != tmp )
			{
				printf( "%d %d %d\n", i, text[ i ], tmp );
			}
		}
	} else {
		printf( "OK\n" );
	}

	VNIovecFreeBufferAndTail( &plainText );
	VNIovecFreeBufferAndTail( &cipherText );
	VNIovecFreeBufferAndTail( &hexPubKey );
	VNIovecFreeBufferAndTail( &hexPrivKey );
}

