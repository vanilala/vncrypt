
#include "testcomm.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>
#include <assert.h>

void VN_Test_Sign( VNAsymCryptCtx_t * ctx, int keyBits, long length, int value, int encryptCount, int decryptCount );
void VN_Test_Enc( VNAsymCryptCtx_t * ctx, int keyBits, long length, int value, int encryptCount, int decryptCount );

void VN_Test( VNAsymCryptCtx_t * ctx, int keyBits, long length, int value, int encryptCount, int decryptCount )
{
	if( ctx->mType < 100 )
	{
		printf( "\nStart to run signature scheme ......\n\n" );
		VN_Test_Sign( ctx, keyBits, length, value, encryptCount, decryptCount );
	} else {
		printf( "\nStart to run encryption scheme ......\n\n" );
		VN_Test_Enc( ctx, keyBits, length, value, encryptCount, decryptCount );
	}
}

static double RunTime( unsigned long long prevUsec, unsigned long long * nowUsec )
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

static void PrintKey( VNAsymCryptCtx_t * ctx )
{
	struct iovec pubKey, privKey;

	ctx->mMethod.mDumpPubKey( ctx, &pubKey );
	printf( "PubKey: %zd, %s\n", pubKey.iov_len, (char*)pubKey.iov_base );

	free( pubKey.iov_base );

	ctx->mMethod.mDumpPrivKey( ctx, &pubKey, &privKey );

	printf( "PirvKey: %zd, %s\n", privKey.iov_len, (char*)privKey.iov_base );

	free( pubKey.iov_base );
	free( privKey.iov_base );
}

void VN_Test_Sign( VNAsymCryptCtx_t * ctx, int keyBits, long length, int value, int encryptCount, int decryptCount )
{
	int i = 0, ret = 0;
	unsigned char text[ 4096 ], tmp;
	struct iovec plainText, cipherText;

	struct iovec hexPubKey, hexPrivKey;

	unsigned long long nowUsec = 0;
	double interval = 0;

	for( i = 0; i < length; i++ ) text[i] = value + i;

	// 1. generate keys
	RunTime( 0, &nowUsec );

	ctx->mMethod.mGenKeys( ctx, keyBits );
	PrintKey( ctx );

	interval = RunTime( nowUsec, &nowUsec );
	printf( "GenKeys time %.6f\n", interval );

	// 2. save pub/priv key, clear ctx
	ctx->mMethod.mDumpPrivKey( ctx, &hexPubKey, &hexPrivKey );
	ctx->mMethod.mClearKeys( ctx );

	// 3. restore priv key, do PrivEncrypt
	printf( "Load PrivKey ......\n" );
	ctx->mMethod.mLoadPrivKey( ctx, &hexPubKey, &hexPrivKey );

	PrintKey( ctx );

	for( i = 0; i < encryptCount && 0 == ret; i++ )
	{
		ret = ctx->mMethod.mPrivEncrypt( ctx, text, length, &cipherText );
		free( cipherText.iov_base );

		if( 0 != ret )
		{
			printf( "PrivEncrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	ret = ctx->mMethod.mPrivEncrypt( ctx, text, length, &cipherText );

	interval = RunTime( nowUsec, &nowUsec );
	printf( "PrivEncrypt %d, time %.6f, ops %d/s\n",
		encryptCount, interval, (int)(encryptCount / interval ) );

	printf( "Cipher Text length: %zd\n", cipherText.iov_len );

	ctx->mMethod.mClearKeys( ctx );

	// 4. restore pub key, do PubDecrypt
	printf( "Load PubKey ......\n" );
	ctx->mMethod.mLoadPubKey( ctx, &hexPubKey );

	PrintKey( ctx );

	for( i = 0; i < decryptCount; i++ )
	{
		ctx->mMethod.mPubDecrypt( ctx, (unsigned char*)cipherText.iov_base, cipherText.iov_len, &plainText );
		free( plainText.iov_base );
	}

	interval = RunTime( nowUsec, &nowUsec );
	printf( "PubDecrypt %d, time %.6f, ops %d/s\n",
		decryptCount, interval, (int)(decryptCount / interval ) );

	ctx->mMethod.mPubDecrypt( ctx, (unsigned char*)cipherText.iov_base, cipherText.iov_len, &plainText );

	assert( length >= plainText.iov_len );

	printf( "Plain Text length: %zd\n", plainText.iov_len );

	printf( "Verifing ......\n" );
	for( i = 0; i < length - plainText.iov_len; i++ )
	{
		if( 0 != text[i] ) printf( "%d %d\n", i, text[i] );
	}

	if( 0 != memcmp( text + length - plainText.iov_len, plainText.iov_base, plainText.iov_len ) )
	{
		printf( "FAIL\n" );
		for( i = length - plainText.iov_len; i < length; i++ )
		{
			tmp = ((unsigned char*)plainText.iov_base)[ i - length + plainText.iov_len ];
			if( text[ i ] != tmp )
			{
				printf( "%d %d %d\n", i, text[ i ], tmp );
			}
		}
	} else {
		printf( "OK\n" );
	}

	free( plainText.iov_base );
	free( cipherText.iov_base );

	free( hexPubKey.iov_base );
	free( hexPrivKey.iov_base );
}

void VN_Test_Enc( VNAsymCryptCtx_t * ctx, int keyBits, long length, int value, int encryptCount, int decryptCount )
{
	int i = 0, ret = 0;
	unsigned char text[ 4096 ], tmp;
	struct iovec plainText, cipherText;

	struct iovec hexPubKey, hexPrivKey;

	unsigned long long nowUsec = 0;
	double interval = 0;

	for( i = 0; i < length; i++ ) text[i] = value + i;

	// 1. generate keys
	RunTime( 0, &nowUsec );

	ctx->mMethod.mGenKeys( ctx, keyBits );
	PrintKey( ctx );

	interval = RunTime( nowUsec, &nowUsec );
	printf( "GenKeys time %.6f\n", interval );

	// 2. save pub/priv key, clear ctx
	ctx->mMethod.mDumpPrivKey( ctx, &hexPubKey, &hexPrivKey );
	ctx->mMethod.mClearKeys( ctx );

	// 3. restore pub key, do PubEncrypt
	printf( "Load PubKey ......\n" );
	ctx->mMethod.mLoadPubKey( ctx, &hexPubKey );

	PrintKey( ctx );

	for( i = 0; i < encryptCount && 0 == ret; i++ )
	{
		ret = ctx->mMethod.mPubEncrypt( ctx, text, length, &cipherText );
		free( cipherText.iov_base );

		if( 0 != ret )
		{
			printf( "PubEncrypt Fail, ret %d\n", ret );
			exit( -1 );
		}
	}

	ret = ctx->mMethod.mPubEncrypt( ctx, text, length, &cipherText );

	interval = RunTime( nowUsec, &nowUsec );
	printf( "PubEncrypt %d, time %.6f, ops %d/s\n",
		encryptCount, interval, (int)(encryptCount / interval ) );

	printf( "Cipher Text length: %zd\n", cipherText.iov_len );

	ctx->mMethod.mClearKeys( ctx );

	// 4. restore priv key, do PrivDecrypt
	printf( "Load PrivKey ......\n" );
	ctx->mMethod.mLoadPrivKey( ctx, &hexPubKey, &hexPrivKey );

	PrintKey( ctx );

	for( i = 0; i < decryptCount; i++ )
	{
		ctx->mMethod.mPrivDecrypt( ctx, (unsigned char*)cipherText.iov_base, cipherText.iov_len, &plainText );
		free( plainText.iov_base );
	}

	interval = RunTime( nowUsec, &nowUsec );
	printf( "PrivDecrypt %d, time %.6f, ops %d/s\n",
		decryptCount, interval, (int)(decryptCount / interval ) );

	ctx->mMethod.mPrivDecrypt( ctx, (unsigned char*)cipherText.iov_base, cipherText.iov_len, &plainText );

	assert( length >= plainText.iov_len );

	printf( "Plain Text length: %zd\n", plainText.iov_len );

	printf( "Verifing ......\n" );
	for( i = 0; i < length - plainText.iov_len; i++ )
	{
		if( 0 != text[i] ) printf( "%d %d\n", i, text[i] );
	}

	if( 0 != memcmp( text + length - plainText.iov_len, plainText.iov_base, plainText.iov_len ) )
	{
		printf( "FAIL\n" );
		for( i = length - plainText.iov_len; i < length; i++ )
		{
			tmp = ((unsigned char*)plainText.iov_base)[ i - length + plainText.iov_len ];
			if( text[ i ] != tmp )
			{
				printf( "%d %d %d\n", i, text[ i ], tmp );
			}
		}
	} else {
		printf( "OK\n" );
	}

	free( plainText.iov_base );
	free( cipherText.iov_base );

	free( hexPubKey.iov_base );
	free( hexPrivKey.iov_base );
}

