/**
 *
 * OpenSSL RSA
 *
 */

#include "vnrsa_org.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNRsa_ORG_Ctx {
	VNAsymCryptCtx_t mCtx;

	unsigned long mE;

	RSA * mRSA;
} VNRsa_ORG_Ctx_t;

static VNAsymCryptCtx_t * VNRsa_ORG_CtxNewImpl( unsigned long e )
{
	VNRsa_ORG_Ctx_t * bnCtx = (VNRsa_ORG_Ctx_t *)calloc( sizeof( VNRsa_ORG_Ctx_t ), 1 );

	bnCtx->mCtx.mMethod.mCtxFree = VNRsa_ORG_CtxFree;
	bnCtx->mCtx.mMethod.mGenKeys = VNRsa_ORG_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNRsa_ORG_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNRsa_ORG_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNRsa_ORG_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNRsa_ORG_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNRsa_ORG_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPrivEncrypt = VNRsa_ORG_PrivEncrypt;
	bnCtx->mCtx.mMethod.mPubDecrypt = VNRsa_ORG_PubDecrypt;
	bnCtx->mCtx.mMethod.mPubEncrypt = VNRsa_ORG_PubEncrypt;
	bnCtx->mCtx.mMethod.mPrivDecrypt = VNRsa_ORG_PrivDecrypt;

	bnCtx->mE = e;
	bnCtx->mRSA = RSA_new();

	return &( bnCtx->mCtx );
}

VNAsymCryptCtx_t * VNRsaSign_ORG_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_ORG_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNRsaSign_ORG;

	return ctx;
}

VNAsymCryptCtx_t * VNRsaEnc_ORG_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_ORG_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNRsaEnc_ORG;

	return ctx;
}

void VNRsa_ORG_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	if( NULL != bnCtx->mRSA ) RSA_free( bnCtx->mRSA );

	free( bnCtx );
}

int VNRsa_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM ze;

	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	BN_init( &ze );
	BN_set_word( &ze, bnCtx->mE );

	RSA_generate_key_ex( bnCtx->mRSA, keyBits * 2, &ze, NULL );

	BN_free( &ze );

	return 0;
}

void VNRsa_ORG_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	BN_clear( bnCtx->mRSA->n );
	BN_clear( bnCtx->mRSA->e );
	BN_clear( bnCtx->mRSA->d );
}

int VNRsa_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_dump_hex( bnCtx->mRSA->n, hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_BN_dump_hex( bnCtx->mRSA->e, hexPubKey->next );

	return 0;
}

int VNRsa_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_dump_hex( bnCtx->mRSA->n, hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_BN_dump_hex( bnCtx->mRSA->e, hexPubKey->next );

	VN_BN_dump_hex( bnCtx->mRSA->d, hexPrivKey );

	return 0;
}

int VNRsa_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_load_hex( hexPubKey, bnCtx->mRSA->n );
	VN_BN_load_hex( hexPubKey->next, bnCtx->mRSA->e );

	return 0;
}

int VNRsa_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_load_hex( hexPubKey, bnCtx->mRSA->n );
	VN_BN_load_hex( hexPubKey->next, bnCtx->mRSA->e );

	VN_BN_load_hex( hexPrivKey, bnCtx->mRSA->d );

	return 0;
}

int VNRsa_ORG_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0;

	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	cipherText->i.iov_len = RSA_size( bnCtx->mRSA );
	cipherText->i.iov_base = calloc( 1, cipherText->i.iov_len + 1 );

	if( length > cipherText->i.iov_len )
	{
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	memcpy( ((char*)cipherText->i.iov_base) + cipherText->i.iov_len - length, plainText, length );

	ret = RSA_private_encrypt( cipherText->i.iov_len, (unsigned char*)cipherText->i.iov_base,
		(unsigned char*)cipherText->i.iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		cipherText->i.iov_len = ret;
		ret = 0;
	}

	return ret;
}

int VNRsa_ORG_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0;
	unsigned char * pos = NULL;

	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	plainText->i.iov_len = RSA_size( bnCtx->mRSA );
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );

	ret = RSA_public_decrypt( length, cipherText,
		(unsigned char*)plainText->i.iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		plainText->i.iov_len = ret;
		ret = 0;

		pos = (unsigned char *)plainText->i.iov_base;
		if( 0 == *pos )
		{
			for( ; 0 == *pos; )  pos++;
			plainText->i.iov_len -= pos - ((unsigned char*)plainText->i.iov_base);
			memmove( plainText->i.iov_base, pos, plainText->i.iov_len );
		}
	}

	return ret;
}

int VNRsa_ORG_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0;

	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	cipherText->i.iov_len = RSA_size( bnCtx->mRSA );
	cipherText->i.iov_base = calloc( 1, cipherText->i.iov_len + 1 );

	if( length > cipherText->i.iov_len )
	{
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	memcpy( ((char*)cipherText->i.iov_base) + cipherText->i.iov_len - length, plainText, length );

	ret = RSA_public_encrypt( cipherText->i.iov_len, (unsigned char*)cipherText->i.iov_base,
		(unsigned char*)cipherText->i.iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		cipherText->i.iov_len = ret;
		ret = 0;
	}

	return ret;
}

int VNRsa_ORG_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0;
	unsigned char * pos = NULL;

	VNRsa_ORG_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	plainText->i.iov_len = RSA_size( bnCtx->mRSA );
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );

	ret = RSA_private_decrypt( length, cipherText,
		(unsigned char*)plainText->i.iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		plainText->i.iov_len = ret;
		ret = 0;

		pos = (unsigned char *)plainText->i.iov_base;
		if( 0 == *pos )
		{
			for( ; 0 == *pos; )  pos++;
			plainText->i.iov_len -= pos - ((unsigned char*)plainText->i.iov_base);
			memmove( plainText->i.iov_base, pos, plainText->i.iov_len );
		}
	}

	return 0;
}

