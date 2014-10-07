/**
 *
 * Rabin public-key encryption
 *
 * See "Handbook of Applied Cryptography" by Alfred J. Menezes et al pages 292
 *
 */

#include "vnrabinenc_gmp.h"
#include "vncrypt_gmp.h"

#include <gmp.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

typedef struct tagVNRabinEnc_GMP_Ctx {
	VNAsymCryptCtx_t mCtx;

	mpz_t mN;

	mpz_t mP;
	mpz_t mQ;

	mpz_t mP14;
	mpz_t mQ14;

	mpz_t mAP;
	mpz_t mBQ;
} VNRabinEnc_GMP_Ctx_t;

static void VNRabinEnc_GMP_CalcPrivAuxKey( VNRabinEnc_GMP_Ctx_t * gmpCtx )
{
	mpz_t za, zb, zd;

	mpz_init( za );
	mpz_init( zb );
	mpz_init( zd );

	mpz_gcdext( zd, za, zb, gmpCtx->mP, gmpCtx->mQ );

	mpz_mul( gmpCtx->mAP, za, gmpCtx->mP );
	mpz_mul( gmpCtx->mBQ, zb, gmpCtx->mQ );

	mpz_set( gmpCtx->mP14, gmpCtx->mP );
	mpz_add_ui( gmpCtx->mP14, gmpCtx->mP14, 1 );
	mpz_fdiv_q_ui( gmpCtx->mP14, gmpCtx->mP14, 4 );

	mpz_set( gmpCtx->mQ14, gmpCtx->mQ );
	mpz_add_ui( gmpCtx->mQ14, gmpCtx->mQ14, 1 );
	mpz_fdiv_q_ui( gmpCtx->mQ14, gmpCtx->mQ14, 4 );

	mpz_clear( za );
	mpz_clear( zb );
	mpz_clear( zd );
}

VNAsymCryptCtx_t * VNRabinEnc_GMP_CtxNew()
{
	VNRabinEnc_GMP_Ctx_t * gmpCtx = (VNRabinEnc_GMP_Ctx_t *)calloc( sizeof( VNRabinEnc_GMP_Ctx_t ), 1 );

	gmpCtx->mCtx.mType = VN_TYPE_VNRabinEnc_GMP;

	gmpCtx->mCtx.mMethod.mCtxFree = VNRabinEnc_GMP_CtxFree;
	gmpCtx->mCtx.mMethod.mGenKeys = VNRabinEnc_GMP_GenKeys;
	gmpCtx->mCtx.mMethod.mClearKeys = VNRabinEnc_GMP_ClearKeys;
	gmpCtx->mCtx.mMethod.mDumpPubKey = VNRabinEnc_GMP_DumpPubKey;
	gmpCtx->mCtx.mMethod.mDumpPrivKey = VNRabinEnc_GMP_DumpPrivKey;
	gmpCtx->mCtx.mMethod.mLoadPubKey = VNRabinEnc_GMP_LoadPubKey;
	gmpCtx->mCtx.mMethod.mLoadPrivKey = VNRabinEnc_GMP_LoadPrivKey;
	gmpCtx->mCtx.mMethod.mPubEncrypt = VNRabinEnc_GMP_PubEncrypt;
	gmpCtx->mCtx.mMethod.mPrivDecrypt = VNRabinEnc_GMP_PrivDecrypt;

	mpz_init( ( gmpCtx->mN ) );
	mpz_init( ( gmpCtx->mP ) );
	mpz_init( ( gmpCtx->mQ ) );

	mpz_init( ( gmpCtx->mP14 ) );
	mpz_init( ( gmpCtx->mQ14 ) );
	mpz_init( ( gmpCtx->mAP ) );
	mpz_init( ( gmpCtx->mBQ ) );

	return &( gmpCtx->mCtx );
}

void VNRabinEnc_GMP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	mpz_clear( ( gmpCtx->mN ) );
	mpz_clear( ( gmpCtx->mP ) );
	mpz_clear( ( gmpCtx->mQ ) );

	mpz_clear( ( gmpCtx->mP14 ) );
	mpz_clear( ( gmpCtx->mQ14 ) );
	mpz_clear( ( gmpCtx->mAP ) );
	mpz_clear( ( gmpCtx->mBQ ) );

	free( gmpCtx );
}

int VNRabinEnc_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	mpz_t zrand;
	gmp_randstate_t state;
	struct vn_iovec seed;

	VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	mpz_init( zrand );

	VNIovecGetRandomBuffer( &seed, ( keyBits / 8 + 1 ) );
	mpz_import( zrand, seed.i.iov_len, 1, 1, 0, 0, seed.i.iov_base );

	gmp_randinit_default( state );
	gmp_randseed( state, zrand );

	do {
		mpz_urandomb( zrand, state, keyBits );
	} while( keyBits != mpz_sizeinbase( zrand, 2 ) );

	/* choose a prime p such that p mod 4 == 3 */
	mpz_set( gmpCtx->mP, zrand );
	do
		mpz_nextprime( gmpCtx->mP, gmpCtx->mP );
	while ( mpz_fdiv_ui( gmpCtx->mP, 4 ) != 3 );

	/* choose a prime q such that q mod 4 == 3 */
	mpz_set( gmpCtx->mQ, gmpCtx->mP );
	do
		mpz_nextprime( gmpCtx->mP, gmpCtx->mP );
	while ( mpz_fdiv_ui( gmpCtx->mP, 4 ) != 3 );

	/* compute public key n*/
	mpz_mul( gmpCtx->mN, gmpCtx->mP, gmpCtx->mQ );

	VNRabinEnc_GMP_CalcPrivAuxKey( gmpCtx );

	mpz_clear( zrand );

	gmp_randclear( state );
	VNIovecFreeBufferAndTail( &seed );

	return 0;
}

void VNRabinEnc_GMP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	mpz_set_ui( gmpCtx->mN, 0 );
	mpz_set_ui( gmpCtx->mP, 0 );
	mpz_set_ui( gmpCtx->mQ, 0 );

	mpz_set_ui( gmpCtx->mP14, 0 );
	mpz_set_ui( gmpCtx->mQ14, 0 );
	mpz_set_ui( gmpCtx->mAP, 0 );
	mpz_set_ui( gmpCtx->mBQ, 0 );
}

int VNRabinEnc_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	VN_GMP_dump_hex( ( gmpCtx->mN ), hexPubKey );

	return 0;
}

int VNRabinEnc_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	VN_GMP_dump_hex( ( gmpCtx->mN ), hexPubKey );

	VN_GMP_dump_hex( ( gmpCtx->mP ), hexPrivKey );
	hexPrivKey->next = calloc( 1, sizeof( struct vn_iovec ) );
	VN_GMP_dump_hex( ( gmpCtx->mQ ), hexPrivKey->next );

	return 0;
}

int VNRabinEnc_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	VN_GMP_load_hex( hexPubKey, ( gmpCtx->mN ) );

	return 0;
}

int VNRabinEnc_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	VN_GMP_load_hex( hexPubKey, ( gmpCtx->mN ) );

	VN_GMP_load_hex( hexPrivKey, ( gmpCtx->mP ) );
	VN_GMP_load_hex( hexPrivKey->next, ( gmpCtx->mQ ) );

	VNRabinEnc_GMP_CalcPrivAuxKey( gmpCtx );

	return 0;
}

int VNRabinEnc_GMP_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	mpz_t zm, zc;

	const VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	mpz_init( zm );
	mpz_import( zm, length, 1, 1, 0, 0, plainText );

	if( mpz_cmp( zm, ( gmpCtx->mN ) ) >= 0 )
	{
		mpz_clear( zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	mpz_init( zc );

	mpz_powm_ui( zc, zm, 2, gmpCtx->mN );

	VN_GMP_dump_bin( zc, cipherText );

	mpz_clear( zm );
	mpz_clear( zc );

	return 0;
}

int VNRabinEnc_GMP_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	mpz_t zc, zr, zs, zm;

	const VNRabinEnc_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRabinEnc_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinEnc_GMP == ctx->mType );

	mpz_init( zc );
	mpz_init( zr );
	mpz_init( zs );
	mpz_init( zm );

	mpz_import( zc, length, 1, 1, 0, 0, cipherText );

	mpz_powm( zr, zc, gmpCtx->mP14, gmpCtx->mP );

	mpz_powm( zs, zc, gmpCtx->mQ14, gmpCtx->mQ );

	mpz_mul( zs, gmpCtx->mAP, zs );

	mpz_mul( zr, gmpCtx->mBQ, zr );

	mpz_add( zm, zs, zr );
	mpz_mod( zm, zm, gmpCtx->mN );
	{
		VN_GMP_dump_bin( zm, plainText );
	}

	mpz_sub( zm, gmpCtx->mN, zm );
	{
		plainText->next = malloc( sizeof( struct vn_iovec ) );
		plainText = plainText->next;
		VN_GMP_dump_bin( zm, plainText );
	}

	mpz_sub( zm, zs, zr );
	mpz_mod( zm, zm, gmpCtx->mN );
	{
		plainText->next = malloc( sizeof( struct vn_iovec ) );
		plainText = plainText->next;
		VN_GMP_dump_bin( zm, plainText );
	}

	mpz_sub( zm, ( gmpCtx->mN ), zm );
	{
		plainText->next = malloc( sizeof( struct vn_iovec ) );
		plainText = plainText->next;
		VN_GMP_dump_bin( zm, plainText );

		plainText->next = NULL;
	}

	mpz_clear( zc );
	mpz_clear( zr );
	mpz_clear( zs );
	mpz_clear( zm );

	return 0;
}

