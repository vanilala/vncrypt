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

typedef struct tagVNRsa_BNCtx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mE;
	BIGNUM mD;
} VNRsa_BNCtx_t;

static VNAsymCryptCtx_t * VNRsa_BNCtx_New_Impl( unsigned long e )
{
	VNRsa_BNCtx_t * bnCtx = (VNRsa_BNCtx_t *)calloc( sizeof( VNRsa_BNCtx_t ), 1 );

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

VNAsymCryptCtx_t * VNRsa_BNCtx_New( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_BNCtx_New_Impl( e );
	ctx->mType = VN_TYPE_VNRsa_BN;

	return ctx;
}

VNAsymCryptCtx_t * VNRsaPK_BNCtx_New( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_BNCtx_New_Impl( e );
	ctx->mType = VN_TYPE_VNRsaPK_BN;

	return ctx;
}

void VNRsa_BNCtx_Free( VNAsymCryptCtx_t * ctx )
{
	VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mE ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

int VNRsa_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM zp, zq, zr;

	VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

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

	BN_sub_word( &zp, 1 );
	BN_sub_word( &zq, 1 );
	BN_mul( &zr, &zp, &zq, bnCtx->mBNCtx );

	/* compute private key d */
	BN_mod_inverse( &( bnCtx->mD ), &( bnCtx->mE ), &zr, bnCtx->mBNCtx );

	BN_free( &zp );
	BN_free( &zq );
	BN_free( &zr );

	return 0;
}

void VNRsa_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	//BN_clear( &( bnCtx->mE ) );
	BN_clear( &( bnCtx->mD ) );
}

int VNRsa_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey )
{
	const VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	return 0;
}

int VNRsa_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey )
{
	const VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );
	VN_BN_dump_hex( &( bnCtx->mD ), hexPrivKey );

	return 0;
}

int VNRsa_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey )
{
	VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	return 0;
}

int VNRsa_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey )
{
	VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );
	VN_BN_load_hex( hexPrivKey, &( bnCtx->mD ) );

	return 0;
}

int VNRsa_BN_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText )
{
	BIGNUM zm, zs;

	const VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( BN_cmp( &zm, &( bnCtx->mN ) ) >= 0 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	BN_init( &zs );

	BN_mod_exp( &zs, &zm, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx );

	cipherText->iov_len = BN_num_bytes( &zs );
	cipherText->iov_base = malloc( cipherText->iov_len + 1);
	BN_bn2bin( &zs, cipherText->iov_base );

	BN_free( &zm );
	BN_free( &zs );

	return 0;
}

int VNRsa_BN_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText )
{
	BIGNUM zm, zs;

	const VNRsa_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRsa_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRsa_BN == ctx->mType || VN_TYPE_VNRsaPK_BN == ctx->mType );

	BN_init( &zm );
	BN_init( &zs );

	BN_bin2bn( cipherText, length, &zs );

	BN_mod_exp( &zm, &zs, &( bnCtx->mE ), &( bnCtx->mN ), bnCtx->mBNCtx );

	plainText->iov_len = BN_num_bytes( &zm );
	plainText->iov_base = malloc( plainText->iov_len + 1);
	BN_bn2bin( &zm, plainText->iov_base );

	BN_free( &zm );
	BN_free( &zs );

	return 0;
}

