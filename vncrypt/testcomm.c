
#include "testcomm.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

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

void PrintKey( VNAsymCryptCtx_t * ctx )
{
	struct iovec pubKey, privKey;

	ctx->mMethod.mDumpPrivKey( ctx, &pubKey, &privKey );

	printf( "PubKey: %zd, %s\n", pubKey.iov_len, (char*)pubKey.iov_base );
	printf( "PirvKey: %zd, %s\n", privKey.iov_len, (char*)privKey.iov_base );

	free( pubKey.iov_base );
	free( privKey.iov_base );
}

void VN_Test( VNAsymCryptCtx_t * ctx, int keyBits, long length, int value, int encryptCount, int decryptCount )
{
	int i = 0;
	unsigned char text[ 4096 ], tmp;
	struct iovec plainText, cipherText;

	unsigned long long nowUsec = 0;
	double interval = 0;

	RunTime( 0, &nowUsec );

	ctx->mMethod.mGenKeys( ctx, keyBits );
	PrintKey( ctx );

	interval = RunTime( nowUsec, &nowUsec );
	printf( "GenKeys time %.6f\n", interval );

	for( i = 0; i < length; i++ ) text[i] = value + i;

	for( i = 0; i < encryptCount; i++ )
	{
		ctx->mMethod.mPrivEncrypt( ctx, text, length, &cipherText );
		free( cipherText.iov_base );
	}

	ctx->mMethod.mPrivEncrypt( ctx, text, length, &cipherText );

	interval = RunTime( nowUsec, &nowUsec );
	printf( "PrivEncrypt %d, time %.6f, ops %d/s\n",
		encryptCount, interval, (int)(encryptCount / interval ) );

	printf( "Cipher Text length: %zd\n", cipherText.iov_len );

	for( i = 0; i < decryptCount; i++ )
	{
		ctx->mMethod.mPubDecrypt( ctx, (unsigned char*)cipherText.iov_base, cipherText.iov_len, &plainText );
		free( plainText.iov_base );
	}

	interval = RunTime( nowUsec, &nowUsec );
	printf( "PubDecrypt %d, time %.6f, ops %d/s\n",
		decryptCount, interval, (int)(decryptCount / interval ) );

	ctx->mMethod.mPubDecrypt( ctx, (unsigned char*)cipherText.iov_base, cipherText.iov_len, &plainText );

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
}

