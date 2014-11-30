/**
 *
 * Williams Encryption scheme
 *
 * See "A modification of the RSA Public-Key Encryption Procedure" by H. C. Williams
 *
 */

#include "vnrw_bn.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNRW_BN_Ctx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mP;
	BIGNUM mQ;
	BIGNUM mD;
} VNRW_BN_Ctx_t;

VNAsymCryptCtx_t * VNRW_BN_CtxNew()
{
	VNRW_BN_Ctx_t * bnCtx = (VNRW_BN_Ctx_t *)calloc( sizeof( VNRW_BN_Ctx_t ), 1 );

	bnCtx->mCtx.mMethod.mCtxFree = VNRW_BN_CtxFree;
	bnCtx->mCtx.mMethod.mGenKeys = VNRW_BN_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNRW_BN_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNRW_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNRW_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNRW_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNRW_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPubEncrypt = VNRW_BN_PubEncrypt;
	bnCtx->mCtx.mMethod.mPrivDecrypt = VNRW_BN_PrivDecrypt;
	bnCtx->mCtx.mMethod.mPubDecrypt = VNRW_BN_PubDecrypt;
	bnCtx->mCtx.mMethod.mPrivEncrypt = VNRW_BN_PrivEncrypt;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mP ) );
	BN_init( &( bnCtx->mQ ) );
	BN_init( &( bnCtx->mD ) );

	return &( bnCtx->mCtx );
}

VNAsymCryptCtx_t * VNRWSign_BN_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNRW_BN_CtxNew();
	ctx->mType = VN_TYPE_VNRWSign_BN;

	return ctx;
}

VNAsymCryptCtx_t * VNRWEnc_BN_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNRW_BN_CtxNew();
	ctx->mType = VN_TYPE_VNRWEnc_BN;

	return ctx;
}

void VNRW_BN_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mP ) );
	BN_free( &( bnCtx->mQ ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

static int VNRW_BN_CalcD( VNAsymCryptCtx_t * ctx )
{
	BIGNUM zp, zq;

	VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_init( &zp );
	BN_init( &zq );

	BN_copy( &zp, &( bnCtx->mP ) );
	BN_copy( &zq, &( bnCtx->mQ ) );

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

int VNRW_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM zp, zq;

	VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	keyBits = ( keyBits + 1 ) / 2;

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

	BN_copy( &( bnCtx->mP ), &zp );
	BN_copy( &( bnCtx->mQ ), &zq );

	VNRW_BN_CalcD( ctx );

	BN_free( &zp );
	BN_free( &zq );

	return 0;
}

void VNRW_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	BN_clear( &( bnCtx->mP ) );
	BN_clear( &( bnCtx->mQ ) );
	BN_clear( &( bnCtx->mD ) );
}

int VNRW_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	return 0;
}

int VNRW_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	VN_BN_dump_hex( &( bnCtx->mP ), hexPrivKey );
	hexPrivKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_BN_dump_hex( &( bnCtx->mQ ), hexPrivKey->next );

	return 0;
}

int VNRW_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	return 0;
}

int VNRW_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	VN_BN_load_hex( hexPrivKey, &( bnCtx->mP ) );
	VN_BN_load_hex( hexPrivKey->next, &( bnCtx->mQ ) );

	VNRW_BN_CalcD( ctx );

	return 0;
}

static int VNRW_BN_E1( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	int ret = 0, jacobi = 0;

	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_mul_word( zm, 2 );
	BN_add_word( zm, 1 );

	ret = VN_BN_jacobi( zm, &( bnCtx->mN ), &jacobi, bnCtx->mBNCtx );

	if( 1 == jacobi )
	{
		BN_mul_word( zm, 4 );
	} else if( -1 == jacobi ) {
		BN_mul_word( zm, 2 );
	} else {
		ret = -1;
	}

	return ret;
}

static int VNRW_BN_E2( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_mod_mul( zm, zm, zm, &( bnCtx->mN ), bnCtx->mBNCtx );

	return 0;
}

static int VNRW_BN_D1( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	int mod = 0;

	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	mod = BN_mod_word( zm, 4 );

	if( 0 == mod )
	{
		BN_rshift( zm, zm, 2 );
		BN_sub_word( zm, 1 );
		BN_rshift1( zm, zm );
	} else if( 1 == mod ) {
		BN_sub( zm, &( bnCtx->mN ), zm );
		BN_rshift( zm, zm, 2 );
		BN_sub_word( zm, 1 );
		BN_rshift1( zm, zm );
	} else if( 2 == mod ) {
		BN_rshift1( zm, zm );
		BN_sub_word( zm, 1 );
		BN_rshift1( zm, zm );
	} else if( 3 == mod ) {
		BN_sub( zm, &( bnCtx->mN ), zm );
		BN_rshift1( zm, zm );
		BN_sub_word( zm, 1 );
		BN_rshift1( zm, zm );
	}

	return 0;
}

static int VNRW_BN_D2( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_mod_exp( zm, zm, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx );

	return 0;
}

int VNRW_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	BIGNUM zm;

	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( ( BN_num_bits( &( bnCtx->mN ) ) - BN_num_bits( &( zm ) ) ) < 4 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	VNRW_BN_E1( ctx, &zm );

	VNRW_BN_E2( ctx, &zm );

	VN_BN_dump_bin( &zm, cipherText );

	BN_free( &zm );

	return 0;
}

int VNRW_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	BIGNUM zm;

	BN_init( &zm );

	BN_bin2bn( cipherText, length, &zm );

	VNRW_BN_D2( ctx, &zm );

	VNRW_BN_D1( ctx, &zm );

	VN_BN_dump_bin( &zm, plainText );

	BN_free( &zm );

	return 0;
}

int VNRW_BN_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	BIGNUM zm;

	const VNRW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWEnc_BN == ctx->mType || VN_TYPE_VNRWSign_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( ( BN_num_bits( &( bnCtx->mN ) ) - BN_num_bits( &( zm ) ) ) < 4 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	VNRW_BN_E1( ctx, &zm );

	VNRW_BN_D2( ctx, &zm );

	VN_BN_dump_bin( &zm, cipherText );

	BN_free( &zm );

	return 0;
}

int VNRW_BN_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	BIGNUM zm;

	BN_init( &zm );

	BN_bin2bn( cipherText, length, &zm );

	VNRW_BN_E2( ctx, &zm );

	VNRW_BN_D1( ctx, &zm );

	VN_BN_dump_bin( &zm, plainText );

	BN_free( &zm );

	return 0;
}

