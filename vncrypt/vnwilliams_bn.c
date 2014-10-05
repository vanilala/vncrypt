/**
 *
 * Williams Encryption scheme
 *
 * See "A modification of the RSA Public-Key Encryption Procedure" by H. C. Williams
 *
 */

#include "vnwilliams_bn.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNWilliamsEnc_BN_Ctx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mD;
} VNWilliamsEnc_BN_Ctx_t;

VNAsymCryptCtx_t * VNWilliamsEnc_BN_CtxNew()
{
	VNWilliamsEnc_BN_Ctx_t * bnCtx = (VNWilliamsEnc_BN_Ctx_t *)calloc( sizeof( VNWilliamsEnc_BN_Ctx_t ), 1 );

	bnCtx->mCtx.mType = VN_TYPE_VNWilliamsEnc_BN;

	bnCtx->mCtx.mMethod.mGenKeys = VNWilliamsEnc_BN_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNWilliamsEnc_BN_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNWilliamsEnc_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNWilliamsEnc_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNWilliamsEnc_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNWilliamsEnc_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPubEncrypt = VNWilliamsEnc_BN_PubEncrypt;
	bnCtx->mCtx.mMethod.mPrivDecrypt = VNWilliamsEnc_BN_PrivDecrypt;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mD ) );

	return &( bnCtx->mCtx );
}

void VNWilliamsEnc_BN_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

int VNWilliamsEnc_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM zp, zq;

	VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	BN_init( &zp );
	BN_init( &zq );

	/* choose a prime p such that p mod 8 == 3 */
	do
		BN_generate_prime_ex( &zp, keyBits, 0, NULL, NULL, NULL);
	while ( BN_mod_word( &zp, 8 ) != 3 );

	/* choose a prime q such that q mod 8 == 7 */
	do
		BN_generate_prime_ex( &zq, keyBits, 0, NULL, NULL, NULL);
	while ( BN_mod_word( &zq, 8 ) != 7 );

	/* compute public key n*/
	BN_mul( &( bnCtx->mN ), &zp, &zq, bnCtx->mBNCtx );

	BN_sub_word( &zp, 1 );
	BN_sub_word( &zq, 1 );

	BN_mul( &( bnCtx->mD ), &zp, &zq, bnCtx->mBNCtx );
	BN_rshift( &( bnCtx->mD ), &( bnCtx->mD ), 2 );
	BN_add_word( &( bnCtx->mD ), 1 );
	BN_rshift1( &( bnCtx->mD ), &( bnCtx->mD ) );

	BN_free( &zp );
	BN_free( &zq );

	return 0;
}

void VNWilliamsEnc_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	BN_clear( &( bnCtx->mD ) );
}

int VNWilliamsEnc_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	return 0;
}

int VNWilliamsEnc_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );
	VN_BN_dump_hex( &( bnCtx->mD ), hexPrivKey );

	return 0;
}

int VNWilliamsEnc_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	return 0;
}

int VNWilliamsEnc_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );
	VN_BN_load_hex( hexPrivKey, &( bnCtx->mD ) );

	return 0;
}

int VNWilliamsEnc_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0, jacobi = 0;

	BIGNUM zm, zc;

	const VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( ( BN_num_bits( &( bnCtx->mN ) ) - BN_num_bits( &( zm ) ) ) < 4 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	BN_init( &zc );

	BN_mul_word( &zm, 2 );
	BN_add_word( &zm, 1 );

	ret = VN_BN_jacobi( &zm, &( bnCtx->mN ), &jacobi, bnCtx->mBNCtx );

	if( 1 == jacobi )
	{
		BN_mul_word( &zm, 4 );
	} else if( -1 == jacobi ) {
		BN_mul_word( &zm, 2 );
	} else {
		ret = -1;
	}

	BN_mod_mul( &zc, &zm, &zm, &( bnCtx->mN ), bnCtx->mBNCtx );

	cipherText->i.iov_len = BN_num_bytes( &zc );
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1);
	BN_bn2bin( &zc, cipherText->i.iov_base );

	BN_free( &zm );
	BN_free( &zc );

	return ret;
}


int VNWilliamsEnc_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	BIGNUM zm, zc;
	int mod = 0;

	const VNWilliamsEnc_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsEnc_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNWilliamsEnc_BN == ctx->mType );

	BN_init( &zm );
	BN_init( &zc );

	BN_bin2bn( cipherText, length, &zc );

	BN_mod_exp( &zm, &zc, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx );

	mod = BN_mod_word( &zm, 4 );

	if( 0 == mod )
	{
		BN_rshift( &zm, &zm, 2 );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	} else if( 1 == mod ) {
		BN_sub( &zm, &( bnCtx->mN ), &zm );
		BN_rshift( &zm, &zm, 2 );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	} else if( 2 == mod ) {
		BN_rshift1( &zm, &zm );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	} else if( 3 == mod ) {
		BN_sub( &zm, &( bnCtx->mN ), &zm );
		BN_rshift1( &zm, &zm );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	}

	plainText->i.iov_len = BN_num_bytes( &zm );
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1);
	BN_bn2bin( &zm, plainText->i.iov_base );

	BN_free( &zm );
	BN_free( &zc );

	return 0;
}

