/**
 *
 * Modified-Rabin signature scheme
 *
 * See "Handbook of Applied Cryptography" by Alfred J. Menezes et al pages 440 - 441.
 *
 */

#include "vnmodrabin_bn.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNModRabin_BN_Ctx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mD;
} VNModRabin_BN_Ctx_t;

VNAsymCryptCtx_t * VNModRabin_BN_CtxNewImpl()
{
	VNModRabin_BN_Ctx_t * bnCtx = (VNModRabin_BN_Ctx_t *)calloc( sizeof( VNModRabin_BN_Ctx_t ), 1 );

	bnCtx->mCtx.mMethod.mCtxFree = VNModRabin_BN_CtxFree;
	bnCtx->mCtx.mMethod.mGenKeys = VNModRabin_BN_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNModRabin_BN_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNModRabin_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNModRabin_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNModRabin_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNModRabin_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPrivEncrypt = VNModRabin_BN_PrivProcess;
	bnCtx->mCtx.mMethod.mPubDecrypt = VNModRabin_BN_PubProcess;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mD ) );

	return &( bnCtx->mCtx );
}

VNAsymCryptCtx_t * VNModRabinSign_BN_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNModRabin_BN_CtxNewImpl();

	ctx->mType = VN_TYPE_VNModRabinSign_BN;

	return ctx;
}

void VNModRabin_BN_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

int VNModRabin_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM za, zb, zp, zq;

	BN_init( &za );
	BN_init( &zb );
	BN_init( &zp );
	BN_init( &zq );

	VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	keyBits = ( keyBits + 1 ) / 2;

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

	/* compute private key d = (n - p - q + 5) / 8 */
	BN_add( &za, &zp, &zq );
	BN_sub( &zb, &( bnCtx->mN ), &za );
	BN_add_word( &zb, 5 );
	BN_rshift( &( bnCtx->mD ), &zb, 3 );

	BN_free( &za );
	BN_free( &zb );
	BN_free( &zp );
	BN_free( &zq );

	return 0;
}

void VNModRabin_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	BN_clear( &( bnCtx->mD ) );
}

int VNModRabin_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	return 0;
}

int VNModRabin_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );
	VN_BN_dump_hex( &( bnCtx->mD ), hexPrivKey );

	return 0;
}

int VNModRabin_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	return 0;
}

int VNModRabin_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );
	VN_BN_load_hex( hexPrivKey, &( bnCtx->mD ) );

	return 0;
}

int VNModRabin_BN_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0, jacobi = 0;
	BIGNUM zm, zs;

	const VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( BN_cmp( &zm, &( bnCtx->mN ) ) >= 0 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	BN_init( &zs );

	BN_mul_word( &zm, 16 );
	BN_add_word( &zm, 6 );

	ret = VN_BN_jacobi( &zm, &( bnCtx->mN ), &jacobi, bnCtx->mBNCtx );

	if( jacobi == 1 )
	{
		BN_mod_exp( &zs, &zm, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx );
	} else if( jacobi == -1 ) {
		BN_div_word( &zm, 2 );
		BN_mod_exp( &zs, &zm, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx );
	}

	VN_BN_dump_bin( &zs, cipherText );

	BN_free( &zm );
	BN_free( &zs );

	return ret;
}

int VNModRabin_BN_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0, mod = 0;
	BIGNUM zm, zm1, zs;

	const VNModRabin_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNModRabin_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_BN == ctx->mType );

	BN_init( &zm );
	BN_init( &zm1 );
	BN_init( &zs );

	BN_bin2bn( cipherText, length, &zs );

	BN_mod_mul( &zm1, &zs, &zs, &( bnCtx->mN ), bnCtx->mBNCtx );
	mod = BN_mod_word( &zm1, 8 );

	if( mod == 6 )
	{
		BN_copy( &zm, &zm1 );
	} else if( mod == 3 ) {
		BN_lshift1( &zm, &zm1 );
	} else if( mod == 7 ) {
		BN_sub( &zm, &( bnCtx->mN ), &zm1 );
	} else if( mod == 2 ) {
		BN_sub( &zm, &( bnCtx->mN ), &zm1 );
		BN_mul_word( &zm, 2 );
	}

	if( BN_mod_word( &zm, 16 ) == 6 )
	{
		ret = 0;

		BN_sub_word( &zm, 6 );
		BN_div_word( &zm, 16 );

		VN_BN_dump_bin( &zm, plainText );
	} else {
		ret = -1;
	}

	BN_free( &zm );
	BN_free( &zm1 );
	BN_free( &zs );

	return ret;
}
