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

typedef struct tagVNRsa_ORGCtx {
	VNAsymCryptCtx_t mCtx;

	unsigned long mE;

	RSA * mRSA;
} VNRsa_ORGCtx_t;

static VNAsymCryptCtx_t * VNRsa_ORGCtx_New_Impl( unsigned long e )
{
	VNRsa_ORGCtx_t * bnCtx = (VNRsa_ORGCtx_t *)calloc( sizeof( VNRsa_ORGCtx_t ), 1 );

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

VNAsymCryptCtx_t * VNRsaSign_ORGCtx_New( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_ORGCtx_New_Impl( e );
	ctx->mType = VN_TYPE_VNRsaSign_ORG;

	return ctx;
}

VNAsymCryptCtx_t * VNRsaEnc_ORGCtx_New( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_ORGCtx_New_Impl( e );
	ctx->mType = VN_TYPE_VNRsaEnc_ORG;

	return ctx;
}

void VNRsa_ORGCtx_Free( VNAsymCryptCtx_t * ctx )
{
	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	if( NULL != bnCtx->mRSA ) RSA_free( bnCtx->mRSA );

	free( bnCtx );
}

int VNRsa_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM ze;

	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	BN_init( &ze );
	BN_set_word( &ze, bnCtx->mE );

	RSA_generate_key_ex( bnCtx->mRSA, keyBits * 2, &ze, NULL );

	BN_free( &ze );

	return 0;
}

void VNRsa_ORG_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	//VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	//assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	//BN_clear( bnCtx->mRSA->n );
	//BN_clear( bnCtx->mRSA->d );
}

int VNRsa_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey )
{
	const VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_dump_hex( bnCtx->mRSA->n, hexPubKey );

	return 0;
}

int VNRsa_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey )
{
	const VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_dump_hex( bnCtx->mRSA->n, hexPubKey );
	VN_BN_dump_hex( bnCtx->mRSA->d, hexPrivKey );

	return 0;
}

int VNRsa_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey )
{
	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_load_hex( hexPubKey, bnCtx->mRSA->n );

	return 0;
}

int VNRsa_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey )
{
	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	VN_BN_load_hex( hexPubKey, bnCtx->mRSA->n );
	VN_BN_load_hex( hexPrivKey, bnCtx->mRSA->d );

	return 0;
}

int VNRsa_ORG_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText )
{
	int ret = 0;

	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	cipherText->iov_len = RSA_size( bnCtx->mRSA );
	cipherText->iov_base = calloc( 1, cipherText->iov_len + 1 );

	if( length > cipherText->iov_len )
	{
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	memcpy( ((char*)cipherText->iov_base) + cipherText->iov_len - length, plainText, length );

	ret = RSA_private_encrypt( cipherText->iov_len, (unsigned char*)cipherText->iov_base,
		(unsigned char*)cipherText->iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		cipherText->iov_len = ret;
		ret = 0;
	}

	return ret;
}

int VNRsa_ORG_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText )
{
	int ret = 0;
	unsigned char * pos = NULL;

	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	plainText->iov_len = RSA_size( bnCtx->mRSA );
	plainText->iov_base = malloc( plainText->iov_len + 1 );

	ret = RSA_public_decrypt( length, cipherText,
		(unsigned char*)plainText->iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		plainText->iov_len = ret;
		ret = 0;

		pos = (unsigned char *)plainText->iov_base;
		if( 0 == *pos )
		{
			for( ; 0 == *pos; )  pos++;
			plainText->iov_len -= pos - ((unsigned char*)plainText->iov_base);
			memmove( plainText->iov_base, pos, plainText->iov_len );
		}
	}

	return ret;
}

int VNRsa_ORG_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText )
{
	int ret = 0;

	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	cipherText->iov_len = RSA_size( bnCtx->mRSA );
	cipherText->iov_base = calloc( 1, cipherText->iov_len + 1 );

	if( length > cipherText->iov_len )
	{
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	memcpy( ((char*)cipherText->iov_base) + cipherText->iov_len - length, plainText, length );

	ret = RSA_public_encrypt( cipherText->iov_len, (unsigned char*)cipherText->iov_base,
		(unsigned char*)cipherText->iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		cipherText->iov_len = ret;
		ret = 0;
	}

	return ret;
}

int VNRsa_ORG_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText )
{
	int ret = 0;
	unsigned char * pos = NULL;

	VNRsa_ORGCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_ORGCtx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_ORG == ctx->mType || VN_TYPE_VNRsaEnc_ORG == ctx->mType );

	plainText->iov_len = RSA_size( bnCtx->mRSA );
	plainText->iov_base = malloc( plainText->iov_len + 1 );

	ret = RSA_private_decrypt( length, cipherText,
		(unsigned char*)plainText->iov_base, bnCtx->mRSA, RSA_NO_PADDING );

	if( ret >= 0 )
	{
		plainText->iov_len = ret;
		ret = 0;

		pos = (unsigned char *)plainText->iov_base;
		if( 0 == *pos )
		{
			for( ; 0 == *pos; )  pos++;
			plainText->iov_len -= pos - ((unsigned char*)plainText->iov_base);
			memmove( plainText->iov_base, pos, plainText->iov_len );
		}
	}

	return 0;
}

