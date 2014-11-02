
#include "vnmqq_org.h"

#include "mqqsign/mqqsig.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

extern int crypto_sign_keypair(unsigned char* pk, unsigned char *sk);

extern int sign(unsigned char *hash, const unsigned char *sk, uint8_t result[N/8]);

extern int verify(const uint8_t Signature[N/8],
	const uint8_t publicKey[PUBLICKEY_SIZE_L][PUBLICKEY_SIZE_S], uint8_t hash[PUBLICKEY_SIZE_S]);

typedef struct tagVNMqq_ORG_Ctx {
	VNAsymCryptCtx_t mCtx;

	unsigned char mPK[ PUBLIC_KEY_SIZE_BYTES ];
	unsigned char mSK[ PRIVATE_KEY_SIZE_BYTES ];
} VNMqq_ORG_Ctx_t;

VNAsymCryptCtx_t * VNMqqSign_ORG_CtxNew()
{
	VNMqq_ORG_Ctx_t * orgCtx = (VNMqq_ORG_Ctx_t*)malloc( sizeof( VNMqq_ORG_Ctx_t ) );

	orgCtx->mCtx.mType = VN_TYPE_VNMqqSign_ORG;

	orgCtx->mCtx.mMethod.mCtxFree = VNMqq_ORG_CtxFree;
	orgCtx->mCtx.mMethod.mGenKeys = VNMqq_ORG_GenKeys;
	orgCtx->mCtx.mMethod.mClearKeys = VNMqq_ORG_ClearKeys;
	orgCtx->mCtx.mMethod.mDumpPubKey = VNMqq_ORG_DumpPubKey;
	orgCtx->mCtx.mMethod.mDumpPrivKey = VNMqq_ORG_DumpPrivKey;
	orgCtx->mCtx.mMethod.mLoadPubKey = VNMqq_ORG_LoadPubKey;
	orgCtx->mCtx.mMethod.mLoadPrivKey = VNMqq_ORG_LoadPrivKey;
	orgCtx->mCtx.mMethod.mSign = VNMqq_ORG_Sign;
	orgCtx->mCtx.mMethod.mVerify = VNMqq_ORG_Verify;

	return &( orgCtx->mCtx );
}

void VNMqq_ORG_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	VNMqq_ORG_ClearKeys( ctx );

	free( orgCtx );
}

int VNMqq_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	return crypto_sign_keypair( orgCtx->mPK, orgCtx->mSK );
}

void VNMqq_ORG_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	memset( orgCtx->mPK, 0, sizeof( orgCtx->mPK ) );
	memset( orgCtx->mSK, 0, sizeof( orgCtx->mSK ) );
}

int VNMqq_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	int i = 0;

	const VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	hexPubKey->i.iov_len = 2 * sizeof( orgCtx->mPK );
	hexPubKey->i.iov_base = malloc( hexPubKey->i.iov_len + 1 );

	for( i = 0; i < sizeof( orgCtx->mPK ); i++ )
	{
		snprintf( ((char*)hexPubKey->i.iov_base) + i * 2, 3, "%02X", orgCtx->mPK[i] );
	}

	return 0;
}

int VNMqq_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	int i = 0;

	const VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	VNMqq_ORG_DumpPubKey( ctx, hexPubKey );

	hexPrivKey->i.iov_len = 2 * sizeof( orgCtx->mSK );
	hexPrivKey->i.iov_base = malloc( hexPrivKey->i.iov_len + 1 );

	for( i = 0; i < sizeof( orgCtx->mSK ); i++ )
	{
		snprintf( ((char*)hexPrivKey->i.iov_base) + i * 2, 3, "%02X", orgCtx->mSK[i] );
	}

	return 0;
}

int VNMqq_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	int i = 0;

	VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	for( i = 0; i < hexPubKey->i.iov_len; i += 2 )
	{
		unsigned char c0 = ((unsigned char*)hexPubKey->i.iov_base)[ i ];
		unsigned char c1 = ((unsigned char*)hexPubKey->i.iov_base)[ i + 1 ];

		c0 = ( c0 >= 'A' ) ? ( c0 - 'A' ) : ( c0 - '1' );
		c1 = ( c1 >= 'A' ) ? ( c1 - 'A' ) : ( c1 - '1' );

		orgCtx->mPK[ i / 2 ] = ( ( c0 & 0xFF ) << 4 ) | ( c1 & 0xFF );
	}

	return 0;
}

int VNMqq_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	int i = 0;

	VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	VNMqq_ORG_LoadPubKey( ctx, hexPubKey );

	for( i = 0; i < hexPrivKey->i.iov_len; i += 2 )
	{
		unsigned char c0 = ((unsigned char*)hexPrivKey->i.iov_base)[ i ];
		unsigned char c1 = ((unsigned char*)hexPrivKey->i.iov_base)[ i + 1 ];

		c0 = ( c0 >= 'A' ) ? ( c0 - 'A' ) : ( c0 - '1' );
		c1 = ( c1 >= 'A' ) ? ( c1 - 'A' ) : ( c1 - '1' );

		orgCtx->mSK[ i / 2 ] = ( ( c0 & 0xFF ) << 4 ) | ( c1 & 0xFF );
	}

	return 0;
}

int VNMqq_ORG_Sign( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	unsigned char hash[ PUBLICKEY_SIZE_S ] = { 0 };

	const VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	cipherText->i.iov_len = N / 8;
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );

	memcpy( hash, plainText, length > sizeof( hash ) ? sizeof( hash ) : length );

	return sign( hash, orgCtx->mSK, cipherText->i.iov_base );
}

int VNMqq_ORG_Verify( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	const struct vn_iovec * plainText )
{
	unsigned char hash[ PUBLICKEY_SIZE_S ] = { 0 };

	const VNMqq_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNMqq_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNMqqSign_ORG == ctx->mType );

	memcpy( hash, plainText->i.iov_base,
		plainText->i.iov_len > sizeof( hash ) ? sizeof( hash ) : plainText->i.iov_len );

	return verify( cipherText, (const uint8_t (*)[PUBLICKEY_SIZE_S])orgCtx->mPK, hash );
}

