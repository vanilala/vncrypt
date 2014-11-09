/**
 *
 * RW
 *
 * See "IEEE Std 1363-2000"
 *
 */

#include "vncrypt_gmp.h"

#include "vnrw_gmp.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

typedef struct tagVNRW_GMP_Ctx {
	VNAsymCryptCtx_t mCtx;

	mpz_t mN;
	mpz_t mP;
	mpz_t mQ;
	mpz_t mD;
} VNRW_GMP_Ctx_t;

static VNAsymCryptCtx_t * VNRW_GMP_CtxNewImpl()
{
	VNRW_GMP_Ctx_t * gmpCtx = (VNRW_GMP_Ctx_t *)calloc( sizeof( VNRW_GMP_Ctx_t ), 1 );

	gmpCtx->mCtx.mMethod.mCtxFree = VNRW_GMP_CtxFree;
	gmpCtx->mCtx.mMethod.mGenKeys = VNRW_GMP_GenKeys;
	gmpCtx->mCtx.mMethod.mClearKeys = VNRW_GMP_ClearKeys;
	gmpCtx->mCtx.mMethod.mDumpPubKey = VNRW_GMP_DumpPubKey;
	gmpCtx->mCtx.mMethod.mDumpPrivKey = VNRW_GMP_DumpPrivKey;
	gmpCtx->mCtx.mMethod.mLoadPubKey = VNRW_GMP_LoadPubKey;
	gmpCtx->mCtx.mMethod.mLoadPrivKey = VNRW_GMP_LoadPrivKey;
	gmpCtx->mCtx.mMethod.mPrivEncrypt = VNRW_GMP_PrivEncrypt;
	gmpCtx->mCtx.mMethod.mPubDecrypt = VNRW_GMP_PubDecrypt;
	gmpCtx->mCtx.mMethod.mPrivDecrypt = VNRW_GMP_PrivDecrypt;
	gmpCtx->mCtx.mMethod.mPubEncrypt = VNRW_GMP_PubEncrypt;

	mpz_init( gmpCtx->mN );
	mpz_init( gmpCtx->mP );
	mpz_init( gmpCtx->mQ );
	mpz_init( gmpCtx->mD );

	return &( gmpCtx->mCtx );
}

VNAsymCryptCtx_t * VNRWSign_GMP_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNRW_GMP_CtxNewImpl();
	ctx->mType = VN_TYPE_VNRWSign_GMP;

	return ctx;
}

VNAsymCryptCtx_t * VNRWEnc_GMP_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNRW_GMP_CtxNewImpl();
	ctx->mType = VN_TYPE_VNRWEnc_GMP;

	return ctx;
}

void VNRW_GMP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_clear( gmpCtx->mN );
	mpz_clear( gmpCtx->mP );
	mpz_clear( gmpCtx->mQ );
	mpz_clear( gmpCtx->mD );

	free( gmpCtx );
}

static int VNRW_CalcD( VNAsymCryptCtx_t * ctx )
{
	mpz_t zp, zq;

	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_init( zp );
	mpz_init( zq );

	mpz_set( zp, gmpCtx->mP );
	mpz_set( zq, gmpCtx->mQ );

	mpz_sub_ui( zp, zp, 1 );
	mpz_sub_ui( zq, zq, 1 );

	mpz_mul( gmpCtx->mD, zp, zq );
	mpz_cdiv_q_ui( gmpCtx->mD, gmpCtx->mD, 4 );
	mpz_add_ui( gmpCtx->mD, gmpCtx->mD, 1 );
	mpz_cdiv_q_ui( gmpCtx->mD, gmpCtx->mD, 2 );

	mpz_clear( zp );
	mpz_clear( zq );

	return 0;
}

int VNRW_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	mpz_t zrand;
	gmp_randstate_t state;
	struct vn_iovec seed;

	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	keyBits = ( keyBits + 1 ) / 2;

	mpz_init( zrand );

	VNIovecGetRandomBuffer( &seed, ( keyBits / 8 + 1 ) );
	mpz_import( zrand, seed.i.iov_len, 1, 1, 0, 0, seed.i.iov_base );

	gmp_randinit_default( state );
	gmp_randseed( state, zrand );

	do {
		mpz_urandomb( zrand, state, keyBits );
	} while( keyBits != mpz_sizeinbase( zrand, 2 ) );

	mpz_set( gmpCtx->mP, zrand );
	do {
		mpz_nextprime( gmpCtx->mP, gmpCtx->mP );
	} while ( mpz_fdiv_ui( gmpCtx->mP, 8 ) != 3 );

	mpz_set( gmpCtx->mQ, gmpCtx->mP );
	do {
		mpz_nextprime( gmpCtx->mQ, gmpCtx->mQ );
	} while ( mpz_fdiv_ui( gmpCtx->mQ, 8 ) != 7 );

	/* compute public key n */
	mpz_mul( gmpCtx->mN, gmpCtx->mP, gmpCtx->mQ );

	VNRW_CalcD( ctx );

	gmp_randclear( state );
	VNIovecFreeBufferAndTail( &seed );

	mpz_clear( zrand );

	return 0;
}

void VNRW_GMP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_set_ui( gmpCtx->mN, 0 );
	mpz_set_ui( gmpCtx->mP, 0 );
	mpz_set_ui( gmpCtx->mQ, 0 );
	mpz_set_ui( gmpCtx->mD, 0 );
}

int VNRW_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	VN_GMP_dump_hex( gmpCtx->mN, hexPubKey );

	return 0;
}

int VNRW_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	VNRW_GMP_DumpPubKey( ctx, hexPubKey );

	VN_GMP_dump_hex( gmpCtx->mP, hexPrivKey );

	hexPrivKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_GMP_dump_hex( gmpCtx->mQ, hexPrivKey->next );

	return 0;
}

int VNRW_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	VN_GMP_load_hex( hexPubKey, gmpCtx->mN );

	return 0;
}

int VNRW_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	VNRW_GMP_LoadPubKey( ctx, hexPubKey );

	VN_GMP_load_hex( hexPrivKey, gmpCtx->mP );
	VN_GMP_load_hex( hexPrivKey->next, gmpCtx->mQ );

	VNRW_CalcD( ctx );

	return 0;
}

static int VNRW_GMP_E1( const VNAsymCryptCtx_t * ctx, mpz_t zm )
{
	int ret = 0, jacobi = 0;

	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_mul_ui( zm, zm, 2 );
	mpz_add_ui( zm, zm, 1 );

	jacobi = mpz_jacobi( zm, gmpCtx->mN );

	if( 1 == jacobi )
	{
		mpz_mul_ui( zm, zm, 4 );
	} else if( -1 == jacobi ) {
		mpz_mul_ui( zm, zm, 2 );
	} else {
		ret = 0;
	}

	return ret;
}

static int VNRW_GMP_E2( const VNAsymCryptCtx_t * ctx, mpz_t zm )
{
	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_powm_ui( zm, zm, 2, gmpCtx->mN );

	return 0;
}

static int VNRW_GMP_D1( const VNAsymCryptCtx_t * ctx, mpz_t zm )
{
	int mod = 0;

	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mod = mpz_fdiv_ui( zm, 4 );

	if( 0 == mod )
	{
		mpz_cdiv_q_ui( zm, zm, 4 );
		mpz_sub_ui( zm, zm, 1 );
	} else if( 1 == mod ) {
		mpz_sub( zm, gmpCtx->mN, zm );
		mpz_cdiv_q_ui( zm, zm, 4 );
		mpz_sub_ui( zm, zm, 1 );
	} else if( 2 == mod ) {
		mpz_cdiv_q_ui( zm, zm, 2 );
		mpz_sub_ui( zm, zm, 1 );
	} else if( 3 == mod ) {
		mpz_sub( zm, gmpCtx->mN, zm );
		mpz_cdiv_q_ui( zm, zm, 2 );
		mpz_sub_ui( zm, zm, 1 );
	}

	mpz_cdiv_q_ui( zm, zm, 2 );

	return 0;
}

static int VNRW_GMP_D2( const VNAsymCryptCtx_t * ctx, mpz_t zm )
{
	VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_powm( zm, zm, gmpCtx->mD, gmpCtx->mN );

	return 0;
}

int VNRW_GMP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	mpz_t zm;

	const VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_init( zm );
	mpz_import( zm, length, 1, 1, 0, 0, plainText );

	if( ( mpz_sizeinbase( gmpCtx->mN, 2 ) - mpz_sizeinbase( zm, 2 ) ) < 4 )
	{
		mpz_clear( zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	VNRW_GMP_E1( ctx, zm );
	VNRW_GMP_D2( ctx, zm );

	VN_GMP_dump_bin( zm, cipherText );

	mpz_clear( zm );

	return 0;
}

int VNRW_GMP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	mpz_t zm;

	mpz_init( zm );
	mpz_import( zm, length, 1, 1, 0, 0, cipherText );

	VNRW_GMP_E2( ctx, zm );
	VNRW_GMP_D1( ctx, zm );

	VN_GMP_dump_bin( zm, plainText );

	mpz_clear( zm );

	return 0;
}

int VNRW_GMP_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	mpz_t zm;

	mpz_init( zm );
	mpz_import( zm, length, 1, 1, 0, 0, cipherText );

	VNRW_GMP_D2( ctx, zm );
	VNRW_GMP_D1( ctx, zm );

	VN_GMP_dump_bin( zm, plainText );

	mpz_clear( zm );

	return 0;
}

int VNRW_GMP_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	mpz_t zm;

	const VNRW_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRW_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_GMP == ctx->mType || VN_TYPE_VNRWEnc_GMP == ctx->mType );

	mpz_init( zm );
	mpz_import( zm, length, 1, 1, 0, 0, plainText );

	if( ( mpz_sizeinbase( gmpCtx->mN, 2 ) - mpz_sizeinbase( zm, 2 ) ) < 4 )
	{
		mpz_clear( zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	VNRW_GMP_E1( ctx, zm );
	VNRW_GMP_E2( ctx, zm );

	VN_GMP_dump_bin( zm, cipherText );

	mpz_clear( zm );

	return 0;
}

