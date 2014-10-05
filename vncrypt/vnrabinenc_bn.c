
#include "vnrabinenc_bn.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNRabinEnc_BNCtx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;

	BIGNUM mP;
	BIGNUM mQ;

	BIGNUM mP14;
	BIGNUM mQ14;

	BIGNUM mAP;
	BIGNUM mBQ;
} VNRabinEnc_BNCtx_t;


static void VNRabinEnc_BN_CalcPrivAuxKey( VNRabinEnc_BNCtx_t * bnCtx )
{
	BIGNUM za, zb, zd;

	BN_init( &za );
	BN_init( &zb );
	BN_init( &zd );

	VN_BN_gcdext( &( bnCtx->mP ), &( bnCtx->mQ ), &za, &zb, &zd, bnCtx->mBNCtx );

	BN_mul( &( bnCtx->mAP ), &za, &( bnCtx->mP ), bnCtx->mBNCtx );
	BN_mul( &( bnCtx->mBQ ), &zb, &( bnCtx->mQ ), bnCtx->mBNCtx );

	BN_copy( &bnCtx->mP14, &( bnCtx->mP ) );
	BN_add_word( &bnCtx->mP14, 1 );
	BN_div_word( &bnCtx->mP14, 4 );

	BN_copy( &bnCtx->mQ14, &( bnCtx->mQ ) );
	BN_add_word( &bnCtx->mQ14, 1 );
	BN_div_word( &bnCtx->mQ14, 4 );

	BN_free( &za );
	BN_free( &zb );
	BN_free( &zd );
}

VNAsymCryptCtx_t * VNRabinEnc_BN_CtxNew()
{
	VNRabinEnc_BNCtx_t * bnCtx = (VNRabinEnc_BNCtx_t *)calloc( sizeof( VNRabinEnc_BNCtx_t ), 1 );

	bnCtx->mCtx.mType = VN_TYPE_VNRabinEnc_BN;

	bnCtx->mCtx.mMethod.mGenKeys = VNRabinEnc_BN_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNRabinEnc_BN_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNRabinEnc_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNRabinEnc_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNRabinEnc_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNRabinEnc_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPubEncrypt = VNRabinEnc_BN_PubEncrypt;
	bnCtx->mCtx.mMethod.mPrivDecrypt = VNRabinEnc_BN_PrivDecrypt;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mP ) );
	BN_init( &( bnCtx->mQ ) );

	BN_init( &( bnCtx->mP14 ) );
	BN_init( &( bnCtx->mQ14 ) );
	BN_init( &( bnCtx->mAP ) );
	BN_init( &( bnCtx->mBQ ) );

	return &( bnCtx->mCtx );
}

void VNRabinEnc_BN_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mP ) );
	BN_free( &( bnCtx->mQ ) );

	BN_free( &( bnCtx->mP14 ) );
	BN_free( &( bnCtx->mQ14 ) );
	BN_free( &( bnCtx->mAP ) );
	BN_free( &( bnCtx->mBQ ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

int VNRabinEnc_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	/* choose a prime p such that p mod 4 == 3 */
	do
		BN_generate_prime_ex( &( bnCtx->mP ), keyBits, 0, NULL, NULL, NULL);
	while ( BN_mod_word( &( bnCtx->mP ), 4 ) != 3 );

	/* choose a prime q such that q mod 4 == 3 */
	do
		BN_generate_prime_ex( &( bnCtx->mQ ), keyBits, 0, NULL, NULL, NULL);
	while ( BN_mod_word( &( bnCtx->mQ ), 4 ) != 3 );

	/* compute public key n*/
	BN_mul( &( bnCtx->mN ), &( bnCtx->mP ), &( bnCtx->mQ ), bnCtx->mBNCtx );

	VNRabinEnc_BN_CalcPrivAuxKey( bnCtx );

	return 0;
}

void VNRabinEnc_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	BN_clear( &( bnCtx->mP ) );
	BN_clear( &( bnCtx->mQ ) );

	BN_clear( &( bnCtx->mP14 ) );
	BN_clear( &( bnCtx->mQ14 ) );
	BN_clear( &( bnCtx->mAP ) );
	BN_clear( &( bnCtx->mBQ ) );
}

int VNRabinEnc_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	return 0;
}

int VNRabinEnc_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	VN_BN_dump_hex( &( bnCtx->mP ), hexPrivKey );
	hexPrivKey->next = calloc( 1, sizeof( struct vn_iovec ) );
	VN_BN_dump_hex( &( bnCtx->mQ ), hexPrivKey->next );

	return 0;
}

int VNRabinEnc_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	return 0;
}

int VNRabinEnc_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	VN_BN_load_hex( hexPrivKey, &( bnCtx->mP ) );
	VN_BN_load_hex( hexPrivKey->next, &( bnCtx->mQ ) );

	VNRabinEnc_BN_CalcPrivAuxKey( bnCtx );

	return 0;
}

int VNRabinEnc_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	BIGNUM zm, zc;

	const VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( BN_cmp( &zm, &( bnCtx->mN ) ) >= 0 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	BN_init( &zc );

	BN_mod_mul( &zc, &zm, &zm, &( bnCtx->mN ), bnCtx->mBNCtx );

	VN_BN_dump_bin( &zc, cipherText );

	BN_free( &zm );
	BN_free( &zc );

	return 0;
}

int VNRabinEnc_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	BIGNUM zc, zr, zs, zm;

	const VNRabinEnc_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_BNCtx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_BN == ctx->mType );

	BN_init( &zc );
	BN_init( &zr );
	BN_init( &zs );
	BN_init( &zm );

	BN_bin2bn( cipherText, length, &zc );

	BN_mod_exp( &zr, &zc, &( bnCtx->mP14 ), &( bnCtx->mP ), bnCtx->mBNCtx );

	BN_mod_exp( &zs, &zc, &( bnCtx->mQ14 ), &( bnCtx->mQ ), bnCtx->mBNCtx );

	BN_mul( &zs, &( bnCtx->mAP ), &zs, bnCtx->mBNCtx );

	BN_mul( &zr, &( bnCtx->mBQ ), &zr, bnCtx->mBNCtx );

	BN_mod_add( &zm, &zs, &zr, &( bnCtx->mN ), bnCtx->mBNCtx );
	{
		VN_BN_dump_bin( &zm, plainText );
	}

	BN_sub( &zm, &( bnCtx->mN ), &zm );
	{
		plainText->next = malloc( sizeof( struct vn_iovec ) );
		plainText = plainText->next;
		VN_BN_dump_bin( &zm, plainText );
	}

	BN_mod_sub( &zm, &zs, &zr, &( bnCtx->mN ), bnCtx->mBNCtx );
	{
		plainText->next = malloc( sizeof( struct vn_iovec ) );
		plainText = plainText->next;
		VN_BN_dump_bin( &zm, plainText );
	}

	BN_sub( &zm, &( bnCtx->mN ), &zm );
	{
		plainText->next = malloc( sizeof( struct vn_iovec ) );
		plainText = plainText->next;
		VN_BN_dump_bin( &zm, plainText );

		plainText->next = NULL;
	}

	BN_free( &zc );
	BN_free( &zr );
	BN_free( &zs );
	BN_free( &zm );

	return 0;
}

