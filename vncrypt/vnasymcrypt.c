
#include "vnasymcrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

void VNAsymCryptCtxFree( VNAsymCryptCtx_t * ctx )
{
	ctx->mMethod.mCtxFree( ctx );
}

int VNAsymCryptGenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	return ctx->mMethod.mGenKeys( ctx, keyBits );
}

void VNAsymCryptClearKeys( VNAsymCryptCtx_t * ctx )
{
	ctx->mMethod.mClearKeys( ctx );
}

int VNAsymCryptDumpPubKey( const VNAsymCryptCtx_t * ctx,
		struct vn_iovec * hexPubKey )
{
	memset( hexPubKey, 0, sizeof( struct vn_iovec ) );
	return ctx->mMethod.mDumpPubKey( ctx, hexPubKey );
}

int VNAsymCryptDumpPrivKey( const VNAsymCryptCtx_t * ctx,
		struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	memset( hexPubKey, 0, sizeof( struct vn_iovec ) );
	memset( hexPrivKey, 0, sizeof( struct vn_iovec ) );

	return ctx->mMethod.mDumpPrivKey( ctx, hexPubKey, hexPrivKey );
}

int VNAsymCryptLoadPubKey( VNAsymCryptCtx_t * ctx,
		const struct vn_iovec * hexPubKey )
{
	return ctx->mMethod.mLoadPubKey( ctx, hexPubKey );
}

int VNAsymCryptLoadPrivKey( VNAsymCryptCtx_t * ctx,
		const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	return ctx->mMethod.mLoadPrivKey( ctx, hexPubKey, hexPrivKey );
}

int VNAsymCryptPrivEncrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText )
{
	cipherText->next = NULL;
	cipherText->i.iov_base = NULL;

	return ctx->mMethod.mPrivEncrypt( ctx, plainText, length, cipherText );
}

int VNAsymCryptPubDecrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, const int length,
		struct vn_iovec * plainText, const int fillUpLength )
{
	int ret = 0;
	struct vn_iovec * iter = NULL;

	plainText->next = NULL;
	plainText->i.iov_base = NULL;

	ret = ctx->mMethod.mPubDecrypt( ctx, cipherText, length, plainText );

	if( fillUpLength > 0 )
	{
		for( iter = plainText; NULL != iter; iter = iter->next )
		{
			if( fillUpLength > iter->i.iov_len )
			{
				iter->i.iov_base = realloc( iter->i.iov_base, fillUpLength );
				memmove( ((char*)iter->i.iov_base) + fillUpLength - iter->i.iov_len,
					iter->i.iov_base, iter->i.iov_len );
				memset( iter->i.iov_base, 0, fillUpLength - iter->i.iov_len );

				iter->i.iov_len = fillUpLength;
			}
		}
	}

	return ret;
}

int VNAsymCryptPubEncrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText )
{
	cipherText->next = NULL;
	cipherText->i.iov_base = NULL;

	return ctx->mMethod.mPubEncrypt( ctx, plainText, length, cipherText );
}

int VNAsymCryptPrivDecrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, const int length,
		struct vn_iovec * plainText, const int fillUpLength )
{
	int ret = 0;
	struct vn_iovec * iter = NULL;

	plainText->next = NULL;
	plainText->i.iov_base = NULL;

	ret = ctx->mMethod.mPrivDecrypt( ctx, cipherText, length, plainText );

	if( fillUpLength > 0 )
	{
		for( iter = plainText; NULL != iter; iter = iter->next )
		{
			if( fillUpLength > iter->i.iov_len )
			{
				iter->i.iov_base = realloc( iter->i.iov_base, fillUpLength );
				memmove( ((char*)iter->i.iov_base) + fillUpLength - iter->i.iov_len,
					iter->i.iov_base, iter->i.iov_len );
				memset( iter->i.iov_base, 0, fillUpLength - iter->i.iov_len );

				iter->i.iov_len = fillUpLength;
			}
		}
	}

	return ret;
}

int VNAsymCryptSign( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * signText )
{
	signText->next = NULL;
	signText->i.iov_base = NULL;

	return ctx->mMethod.mSign( ctx, plainText, length, signText );
}

int VNAsymCryptVerify( const VNAsymCryptCtx_t * ctx,
		const unsigned char * signText, const int length,
		const struct vn_iovec * plainText )
{
	return ctx->mMethod.mVerify( ctx, signText, length, plainText );
}

/* helper function */

void VNIovecPrint( const char * prompt, const struct vn_iovec * head, int toHex )
{
	size_t i = 0;
	const struct vn_iovec * next = NULL;

	for( next = head; NULL != next; next = next->next )
	{
		printf( "%s: %zd, ", prompt, next->i.iov_len );

		if( toHex )
		{
			for( i = 0; i < next->i.iov_len; i++ )
			{
				printf( "%02x", ((unsigned char*)next->i.iov_base)[i] );
			}
		} else {
			printf( "%s", (char*)next->i.iov_base );
		}

		printf( "\n" );
	}
}

void VNIovecFreeBufferAndTail( struct vn_iovec * head )
{
	struct vn_iovec * next = NULL;

	for( next = head->next; NULL != next; next = head->next )
	{
		head->next = next->next;

		free( next->i.iov_base );
		free( next );
	}

	free( head->i.iov_base );
	memset( head, 0, sizeof( struct vn_iovec ) );
}

void VNIovecGetRandomBuffer( struct vn_iovec * head, int length )
{
	int i = 0;

	memset( head, 0, sizeof( struct vn_iovec ) );

	if( 0 == access( "/dev/urandom", F_OK ) )
	{
		FILE * fp = fopen( "/dev/urandom", "r" );
		if( NULL != fp )
		{
			head->i.iov_base = calloc( 1, length + 1 );
			head->i.iov_len = length;

			fread( head->i.iov_base, 1, head->i.iov_len, fp );
			fclose( fp );
		}
	}

	if( NULL == head->i.iov_base )
	{
		head->i.iov_len = length;
		head->i.iov_base = calloc( 1, length + 4 );

		struct timeval tv;
		gettimeofday(&tv, NULL);

		unsigned int * pos = (unsigned int*)head->i.iov_base;

		for( i = 0; i < ( length + 4 ) / 4; i++ )
		{
			if( 0 == ( i % 2 ) )
			{
				*pos = tv.tv_sec * tv.tv_usec;
			} else {
				*pos = tv.tv_sec | tv.tv_usec;
			}

			if( i > 0 )
			{
				*pos = ( *pos ) ^ ( *( pos - 1 ) );
			}
		}
	}
}

