/**
 *
 * RW
 *
 * See "IEEE Std 1363-2000"
 *
 */

#include "vnp1363rw_bn.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNP1363RW_BN_Ctx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mE;

	BIGNUM mP;
	BIGNUM mQ;
	BIGNUM mD;
} VNP1363RW_BN_Ctx_t;

VNAsymCryptCtx_t * VNP1363RW_BN_CtxNew( unsigned long e )
{
	VNP1363RW_BN_Ctx_t * bnCtx = (VNP1363RW_BN_Ctx_t *)calloc( sizeof( VNP1363RW_BN_Ctx_t ), 1 );

	bnCtx->mCtx.mMethod.mCtxFree = VNP1363RW_BN_CtxFree;
	bnCtx->mCtx.mMethod.mGenKeys = VNP1363RW_BN_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNP1363RW_BN_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNP1363RW_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNP1363RW_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNP1363RW_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNP1363RW_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPubDecrypt = VNP1363RW_BN_PubDecrypt;
	bnCtx->mCtx.mMethod.mPrivEncrypt = VNP1363RW_BN_PrivEncrypt;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mE ) );
	BN_init( &( bnCtx->mP ) );
	BN_init( &( bnCtx->mQ ) );
	BN_init( &( bnCtx->mD ) );

	BN_set_word( &( bnCtx->mE ), e );

	return &( bnCtx->mCtx );
}

VNAsymCryptCtx_t * VNP1363RWSign_BN_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNP1363RW_BN_CtxNew( e );
	ctx->mType = VN_TYPE_VNP1363RWSign_BN;

	return ctx;
}

void VNP1363RW_BN_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mE ) );

	BN_free( &( bnCtx->mP ) );
	BN_free( &( bnCtx->mQ ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

static int VNP1363RW_BN_CalcD( VNAsymCryptCtx_t * ctx )
{
	// d e = 1 ( mod LCM( p - 1, q - 1 ) / 2 )

	BIGNUM zp, zq, tmp;

	VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	BN_init( &zp );
	BN_init( &zq );
	BN_init( &tmp );

	BN_copy( &zp, &( bnCtx->mP ) );
	BN_copy( &zq, &( bnCtx->mQ ) );

	BN_sub_word( &zp, 1 );
	BN_sub_word( &zq, 1 );

	VN_BN_lcm( &tmp, &zp, &zq, bnCtx->mBNCtx );
	BN_rshift1( &tmp, &tmp );

	BN_mod_inverse( &( bnCtx->mD ), &( bnCtx->mE ), &tmp, bnCtx->mBNCtx );

	BN_free( &tmp );
	BN_free( &zp );
	BN_free( &zq );

	return 0;
}

int VNP1363RW_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM zp, zq;

	VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

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

	VNP1363RW_BN_CalcD( ctx );

	BN_free( &zp );
	BN_free( &zq );

	return 0;
}

void VNP1363RW_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	BN_clear( &( bnCtx->mE ) );
	BN_clear( &( bnCtx->mP ) );
	BN_clear( &( bnCtx->mQ ) );
	BN_clear( &( bnCtx->mD ) );
}

int VNP1363RW_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPubKey = hexPubKey->next;
	VN_BN_dump_hex( &( bnCtx->mE ), hexPubKey );

	return 0;
}

int VNP1363RW_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	VNP1363RW_BN_DumpPubKey( ctx, hexPubKey );

	VN_BN_dump_hex( &( bnCtx->mP ), hexPrivKey );
	hexPrivKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_BN_dump_hex( &( bnCtx->mQ ), hexPrivKey->next );

	return 0;
}

int VNP1363RW_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	if( NULL != hexPubKey->next )
	{
		VN_BN_load_hex( hexPubKey->next, &( bnCtx->mE ) );
	} else {
		BN_set_word( &( bnCtx->mE ), 2 );
	}

	return 0;
}

int VNP1363RW_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	VNP1363RW_BN_LoadPubKey( ctx, hexPubKey );

	VN_BN_load_hex( hexPrivKey, &( bnCtx->mP ) );
	VN_BN_load_hex( hexPrivKey->next, &( bnCtx->mQ ) );

	VNP1363RW_BN_CalcD( ctx );

	return 0;
}

static int VNP1363RW_BN_E1( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	int ret = 0, jacobi = 0;

	const VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	ret = VN_BN_jacobi( zm, &( bnCtx->mN ), &jacobi, bnCtx->mBNCtx );

	if( -1 == jacobi ) BN_rshift1( zm, zm );

	return ret;
}

static int VNP1363RW_BN_E2( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	const VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	BN_mod_exp( zm, zm, &( bnCtx->mE ), &( bnCtx->mN ), bnCtx->mBNCtx );

	return 0;
}

static int VNP1363RW_BN_D1( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	int mod = 0;

	const VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	mod = BN_mod_word( zm, 16 );
	if( 12 == mod ) return 0;

	mod = BN_mod_word( zm, 8 );
	if( 6 == mod )
	{
		BN_mul_word( zm, 2 );
		return 0;
	}

	BN_sub( zm, &( bnCtx->mN ), zm );

	mod = BN_mod_word( zm, 16 );
	if( 12 == mod ) return 0;

	mod = BN_mod_word( zm, 8 );
	if( 6 == mod )
	{
		BN_mul_word( zm, 2 );
		return 0;
	}

	return -1;
}

static int VNP1363RW_BN_D2( const VNAsymCryptCtx_t * ctx, BIGNUM * zm )
{
	BIGNUM tmp;

	const VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	BN_init( &tmp );

	BN_mod_exp( zm, zm, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx );

	BN_sub( &tmp, &( bnCtx->mN ), zm );

	if( BN_cmp( zm, &tmp ) > 0 ) BN_copy( zm, &tmp );

	BN_free( &tmp );

	return 0;
}

int VNP1363RW_BN_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0;

	BIGNUM zm;

	const VNP1363RW_BN_Ctx_t * bnCtx = VN_CONTAINER_OF( ctx, VNP1363RW_BN_Ctx_t, mCtx );
	assert( VN_TYPE_VNP1363RWSign_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	BN_mul_word( &zm, 16 );
	BN_add_word( &zm, 12 );

	if( BN_cmp( &zm, &( bnCtx->mN ) ) >= 0 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	ret = VNP1363RW_BN_E1( ctx, &zm );
	if( 0 == ret ) ret = VNP1363RW_BN_D2( ctx, &zm );

	VN_BN_dump_bin( &zm, cipherText );

	BN_free( &zm );

	return 0;
}

int VNP1363RW_BN_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0;

	BIGNUM zm;

	BN_init( &zm );

	BN_bin2bn( cipherText, length, &zm );

	ret = VNP1363RW_BN_E2( ctx, &zm );
	if( 0 == ret ) ret = VNP1363RW_BN_D1( ctx, &zm );

	BN_sub_word( &zm, 12 );
	BN_div_word( &zm, 16 );

	VN_BN_dump_bin( &zm, plainText );

	BN_free( &zm );

	return ret;
}

