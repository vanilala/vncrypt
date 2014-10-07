
#include "testcomm.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>

#include <signal.h>
#include <unistd.h>

static int gRunning = 0;

void sigHandle( int sig )
{
	signal( SIGALRM, sigHandle );

	gRunning = 0;
}

static void VN_Usage( const char * program )
{
	printf( "\n" );
	printf( "Usage: %s [-k <key bits>] [-l <plain length>] [-i <init value>]\n"
			"\t\t[-r <run seconds>] [-s <silent>]\n", program );
	printf( "\n" );
	printf( "\tdefault: %s -k 64 -l 15 -i 1 -r 1 -s 1\n", program );
	printf( "\n" );

	exit( 0 );
}

int VN_Test( int argc, const char * argv[], VNTestEnv_t * env )
{
	int i = 0;

	VNTestArgs_t args = {
		.mArgc = argc,
		.mArgv = argv,
		.mSilent = 1,
		.mKeyBits = 64,
		.mLength = 15,
		.mInitValue = 1,
		.mRunSeconds = 1,
	};

	for( i = 1; i < argc; i += 2 )
	{
		if( 0 == strcmp( argv[ i ], "-v" ) ) VN_Usage( argv[0] );

		if( i == ( argc - 1 ) ) break;

		if( 0 == strcmp( argv[ i ], "-k" ) ) args.mKeyBits = atoi( argv[ i + 1 ] );
		if( 0 == strcmp( argv[ i ], "-l" ) ) args.mLength = atoi( argv[ i + 1 ] );
		if( 0 == strcmp( argv[ i ], "-i" ) ) args.mInitValue = atoi( argv[ i + 1 ] );
		if( 0 == strcmp( argv[ i ], "-r" ) ) args.mRunSeconds = atoi( argv[ i + 1 ] );
		if( 0 == strcmp( argv[ i ], "-s" ) ) args.mSilent = atoi( argv[ i + 1 ] );
	}

	printf( "\ncmd: %s -k %d -l %d -i %d -r %d -s %d\n", argv[0], args.mKeyBits,
		args.mLength, args.mInitValue, args.mRunSeconds, args.mSilent );
	printf( "run [%s -v] to see detail usage\n", argv[0] );

	if( NULL != env->mTestMain )
	{
		env->mTestMain( &args );
	} else {
		if( NULL != env->mSignCtxNew )
		{
			VNAsymCryptCtx_t * ctx = env->mSignCtxNew();
			VN_Run( ctx, &args );
			VNAsymCryptCtxFree( ctx );
		}

		if( NULL != env->mEncCtxNew )
		{
			VNAsymCryptCtx_t * ctx = env->mEncCtxNew();
			VN_Run( ctx, &args );
			VNAsymCryptCtxFree( ctx );
		}
	}

	return 0;
}

void VN_Run( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args )
{
	if( ctx->mType < VN_TYPE_VNMaxSign )
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
	struct vn_iovec srcText, plainText, cipherText;

	struct vn_iovec hexPubKey, hexPrivKey;

	int opCount = 0;

	signal( SIGALRM, sigHandle );

	for( i = 0; i < args->mLength; i++ ) text[i] = args->mInitValue + i;
	srcText.i.iov_len = args->mLength;
	srcText.i.iov_base = text;
	srcText.next = NULL;

	if( ! args->mSilent ) VNIovecPrint( "SrcText", &srcText );

	// 1. generate keys
	if( ! args->mSilent ) printf( "GenKeys ......\n" );

	VNAsymCryptGenKeys( ctx, args->mKeyBits );

	if( ! args->mSilent ) VN_PrintKey( ctx );

	// 2. save pub/priv key, clear ctx
	VNAsymCryptDumpPrivKey( ctx, &hexPubKey, &hexPrivKey );
	VNAsymCryptClearKeys( ctx );

	// 3. restore priv key, do PrivEncrypt
	if( ! args->mSilent ) printf( "Load PrivKey ......\n" );
	VNAsymCryptLoadPrivKey( ctx, &hexPubKey, &hexPrivKey );
	if( ! args->mSilent ) VN_PrintKey( ctx );

	alarm( args->mRunSeconds );
	for( opCount = 0, gRunning = 1; 1 == gRunning; ++opCount )
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

	printf( "PrivEncrypt %d, ops %d/s\n", opCount, opCount / args->mRunSeconds );

	if( ! args->mSilent ) VNIovecPrint( "CipherText", &cipherText );

	VNAsymCryptClearKeys( ctx );

	// 4. restore pub key, do PubDecrypt
	if( ! args->mSilent ) printf( "Load PubKey ......\n" );
	VNAsymCryptLoadPubKey( ctx, &hexPubKey );

	if( ! args->mSilent ) VN_PrintKey( ctx );

	alarm( args->mRunSeconds );
	for( opCount = 0, gRunning = 1; 1 == gRunning; ++opCount )
	{
		ret = VNAsymCryptPubDecrypt( ctx, (unsigned char*)cipherText.i.iov_base,
			cipherText.i.iov_len, &plainText, 0 );
		VNIovecFreeBufferAndTail( &plainText );

		if( 0 != ret )
		{
			printf( "PubDecrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	printf( "PubDecrypt  %d, ops %d/s\n", opCount, opCount / args->mRunSeconds );

	VNAsymCryptPubDecrypt( ctx, (unsigned char*)cipherText.i.iov_base,
		cipherText.i.iov_len, &plainText, args->mLength );

	if( ! args->mSilent ) VNIovecPrint( "PlainText", &plainText );

	assert( args->mLength == plainText.i.iov_len );

	printf( "Verifing ...... " );

	if( 0 != memcmp( text, plainText.i.iov_base, args->mLength ) )
	{
		printf( "FAIL\n" );
		for( i = 0; i < args->mLength; i++ )
		{
			tmp = ((unsigned char*)plainText.i.iov_base)[ i ];
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

void VN_Run_Enc( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args )
{
	int i = 0, ret = 0;
	unsigned char text[ 4096 ], tmp;
	struct vn_iovec srcText, plainText, cipherText, * result = NULL;
	struct vn_iovec hexPubKey, hexPrivKey;

	int opCount = 0;

	signal( SIGALRM, sigHandle );

	for( i = 0; i < args->mLength; i++ ) text[i] = args->mInitValue + i;
	srcText.i.iov_len = args->mLength;
	srcText.i.iov_base = text;
	srcText.next = NULL;

	if( ! args->mSilent ) VNIovecPrint( "SrcText", &srcText );

	// 1. generate keys
	if( ! args->mSilent ) printf( "GenKeys ......\n" );

	VNAsymCryptGenKeys( ctx, args->mKeyBits );

	if( ! args->mSilent ) VN_PrintKey( ctx );

	// 2. save pub/priv key, clear ctx
	VNAsymCryptDumpPrivKey( ctx, &hexPubKey, &hexPrivKey );
	VNAsymCryptClearKeys( ctx );

	// 3. restore pub key, do PubEncrypt
	if( ! args->mSilent ) printf( "Load PubKey ......\n" );
	VNAsymCryptLoadPubKey( ctx, &hexPubKey );
	if( ! args->mSilent ) VN_PrintKey( ctx );

	alarm( args->mRunSeconds );
	for( opCount = 0, gRunning = 1; 1 == gRunning; opCount++ )
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

	printf( "PubEncrypt  %d, ops %d/s\n", opCount, opCount / args->mRunSeconds );

	if( ! args->mSilent ) VNIovecPrint( "CipherText", &cipherText );

	VNAsymCryptClearKeys( ctx );

	// 4. restore priv key, do PrivDecrypt
	if( ! args->mSilent ) printf( "Load PrivKey ......\n" );
	VNAsymCryptLoadPrivKey( ctx, &hexPubKey, &hexPrivKey );

	if( ! args->mSilent ) VN_PrintKey( ctx );

	alarm( args->mRunSeconds );
	for( opCount = 0, gRunning = 1; 1 == gRunning; opCount++ )
	{
		ret = VNAsymCryptPrivDecrypt( ctx, (unsigned char*)cipherText.i.iov_base,
			cipherText.i.iov_len, &plainText, 0 );
		VNIovecFreeBufferAndTail( &plainText );

		if( 0 != ret )
		{
			printf( "PrivEncrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	printf( "PrivDecrypt %d, ops %d/s\n", opCount, opCount / args->mRunSeconds );

	VNAsymCryptPrivDecrypt( ctx, (unsigned char*)cipherText.i.iov_base,
		cipherText.i.iov_len, &plainText, args->mLength );

	result = &plainText;

	if( ! args->mSilent ) VNIovecPrint( "PlainText", result );

	if( NULL != result->next )
	{
		// rabin encryption scheme will return 4 results, find the real result
		// here use a simple way, but should use a more trusty way in the real world
		for( ; NULL != result; result = result->next )
		{
			tmp = ((unsigned char*)result->i.iov_base)[ args->mLength - 1 ];
			if( tmp == text[ args->mLength - 1 ] )
			{
				break;
			}
		}
		assert( NULL != result );
	}

	assert( args->mLength == result->i.iov_len );

	printf( "Verifing ...... " );

	if( 0 != memcmp( text, result->i.iov_base, args->mLength ) )
	{
		printf( "FAIL\n" );
		for( i = 0; i < args->mLength; i++ )
		{
			tmp = ((unsigned char*)result->i.iov_base)[ i ];
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

