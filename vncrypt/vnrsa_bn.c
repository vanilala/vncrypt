/**
 *
 * Rsa
 *
 * See "Handbook of Applied Cryptography" by Alfred J. Menezes et al pages 432 - 434
 *
 */

#include "vnrsa_bn.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>

#include <assert.h>
#include <string.h>
#include <stdlib.h>

typedef struct tagVNRsa_BN_Ctx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mE;
	BIGNUM mD;
} VNRsa_BN_Ctx_t;

static VNAsymCryptCtx_t * VNRsa_BN_CtxNewImpl( unsigned long e )
{
	VNRsa_BN_Ctx_t * bnCtx = (VNRsa_BN_Ctx_t *)calloc( sizeof( VNRsa_BN_Ctx_t ), 1 );

	bnCtx->mCtx.mMethod.mCtxFree = VNRsa_BN_CtxFree;
	bnCtx->mCtx.mMethod.mGenKeys = VNRsa_BN_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNRsa_BN_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNRsa_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNRsa_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNRsa_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNRsa_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPrivEncrypt = VNRsa_BN_PrivProcess;
	bnCtx->mCtx.mMethod.mPubDecrypt = VNRsa_BN_PubProcess;
	bnCtx->mCtx.mMethod.mPubEncrypt = VNRsa_BN_PubProcess;
	bnCtx->mCtx.mMethod.mPrivDecrypt = VNRsa_BN_PrivProcess;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mE ) );
	BN_init( &( bnCtx->mD ) );

	BN_set_word( &( bnCtx->mE ), e );

	return &( bnCtx->mCtx );
}

VNAsymCryptCtx_t * VNRsaSign_BN_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_BN_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNRsaSign_BN;

	return ctx;
}

VNAsymCryptCtx_t * VNRsaEnc_BN_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_BN_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNRsaEnc_BN;

	return ctx;
}

void VNRsa_BN_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mE ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

int VNRsa_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM zp, zq, zr;

	VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	BN_init( &zp );
	BN_init( &zq );
	BN_init( &zr );

	do {
		BN_generate_prime_ex( &zp, keyBits, 0, NULL, NULL, NULL);
		BN_sub( &zr, &zp, BN_value_one() );
	} while( !BN_gcd( &zr, &zr, &( bnCtx->mE ), bnCtx->mBNCtx ) );

	do {
		BN_generate_prime_ex( &zq, keyBits, 0, NULL, NULL, NULL);
		BN_sub( &zr, &zq, BN_value_one() );
	} while( !BN_gcd( &zr, &zr, &( bnCtx->mE ), bnCtx->mBNCtx ) );

	/* compute public key n */
	BN_mul( &( bnCtx->mN ), &zp, &zq, bnCtx->mBNCtx );

	/* compute private key ( e * d ) = 1 ( mod (p-1)(q-1) ) */
	BN_sub_word( &zp, 1 );
	BN_sub_word( &zq, 1 );
	BN_mul( &zr, &zp, &zq, bnCtx->mBNCtx );
	BN_mod_inverse( &( bnCtx->mD ), &( bnCtx->mE ), &zr, bnCtx->mBNCtx );

	BN_free( &zp );
	BN_free( &zq );
	BN_free( &zr );

	return 0;
}

void VNRsa_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	BN_clear( &( bnCtx->mE ) );
	BN_clear( &( bnCtx->mD ) );
}

int VNRsa_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_BN_dump_hex( &( bnCtx->mE ), hexPubKey->next );

	return 0;
}

int VNRsa_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );
	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_BN_dump_hex( &( bnCtx->mE ), hexPubKey->next );

	VN_BN_dump_hex( &( bnCtx->mD ), hexPrivKey );

	return 0;
}

int VNRsa_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );
	VN_BN_load_hex( hexPubKey->next, &( bnCtx->mE ) );

	return 0;
}

int VNRsa_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );
	VN_BN_load_hex( hexPubKey->next, &( bnCtx->mE ) );

	VN_BN_load_hex( hexPrivKey, &( bnCtx->mD ) );

	return 0;
}

int VNRsa_BN_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	BIGNUM zm, zs;

	const VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( BN_cmp( &zm, &( bnCtx->mN ) ) >= 0 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	BN_init( &zs );

	BN_mod_exp_mont( &zs, &zm, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx, NULL );

	cipherText->i.iov_len = BN_num_bytes( &zs );
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1);
	BN_bn2bin( &zs, cipherText->i.iov_base );

	BN_free( &zm );
	BN_free( &zs );

	return 0;
}

int VNRsa_BN_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	BIGNUM zm, zs;

	const VNRsa_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_BN == ctx->mType || VN_TYPE_VNRsaEnc_BN == ctx->mType );

	BN_init( &zm );
	BN_init( &zs );

	BN_bin2bn( cipherText, length, &zs );

	BN_mod_exp_mont( &zm, &zs, &( bnCtx->mE ), &( bnCtx->mN ), bnCtx->mBNCtx, NULL );

	plainText->i.iov_len = BN_num_bytes( &zm );
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1);
	BN_bn2bin( &zm, plainText->i.iov_base );

	BN_free( &zm );
	BN_free( &zs );

	return 0;
}

