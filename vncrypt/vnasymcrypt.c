
#include "vnasymcrypt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText )
{
	plainText->next = NULL;
	plainText->i.iov_base = NULL;

	return ctx->mMethod.mPubDecrypt( ctx, cipherText, length, plainText );
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
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText )
{
	plainText->next = NULL;
	plainText->i.iov_base = NULL;

	return ctx->mMethod.mPrivDecrypt( ctx, cipherText, length, plainText );
}

/* helper function */

void vn_iovec_print( const char * prompt, struct vn_iovec * head )
{
	size_t i = 0;
	struct vn_iovec * next = NULL;

	for( next = head; NULL != next; next = next->next )
	{
		printf( "%s: %zd, ", prompt, next->i.iov_len );

		for( i = 0; i < next->i.iov_len; i++ )
		{
			printf( "%02x", ((unsigned char*)next->i.iov_base)[i] );
		}

		printf( "\n" );
	}
}

void vn_iovec_free_buffer_and_tail( struct vn_iovec * head )
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

