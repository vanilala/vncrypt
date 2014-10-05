/**
 *
 * Rsa
 *
 * See "Handbook of Applied Cryptography" by Alfred J. Menezes et al pages 432 - 434
 *
 */

#include "vncrypt_gmp.h"

#include "vnrsa_gmp.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

typedef struct tagVNRsa_GMP_Ctx {
	VNAsymCryptCtx_t mCtx;

	mpz_t mN;
	mpz_t mE;
	mpz_t mD;
} VNRsa_GMP_Ctx_t;

static VNAsymCryptCtx_t * VNRsa_GMP_CtxNewImpl( unsigned long e )
{
	VNRsa_GMP_Ctx_t * gmpCtx = (VNRsa_GMP_Ctx_t *)calloc( sizeof( VNRsa_GMP_Ctx_t ), 1 );

	gmpCtx->mCtx.mMethod.mGenKeys = VNRsa_GMP_GenKeys;
	gmpCtx->mCtx.mMethod.mClearKeys = VNRsa_GMP_ClearKeys;
	gmpCtx->mCtx.mMethod.mDumpPubKey = VNRsa_GMP_DumpPubKey;
	gmpCtx->mCtx.mMethod.mDumpPrivKey = VNRsa_GMP_DumpPrivKey;
	gmpCtx->mCtx.mMethod.mLoadPubKey = VNRsa_GMP_LoadPubKey;
	gmpCtx->mCtx.mMethod.mLoadPrivKey = VNRsa_GMP_LoadPrivKey;
	gmpCtx->mCtx.mMethod.mPrivEncrypt = VNRsa_GMP_PrivProcess;
	gmpCtx->mCtx.mMethod.mPubDecrypt = VNRsa_GMP_PubProcess;
	gmpCtx->mCtx.mMethod.mPubEncrypt = VNRsa_GMP_PubProcess;
	gmpCtx->mCtx.mMethod.mPrivDecrypt = VNRsa_GMP_PrivProcess;

	mpz_init( gmpCtx->mN );
	mpz_init( gmpCtx->mE );
	mpz_init( gmpCtx->mD );

	mpz_set_ui( gmpCtx->mE, e );

	return &( gmpCtx->mCtx );
}

VNAsymCryptCtx_t * VNRsaSign_GMP_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_GMP_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNRsaSign_GMP;

	return ctx;
}

VNAsymCryptCtx_t * VNRsaEnc_GMP_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_GMP_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNRsaEnc_GMP;

	return ctx;
}

void VNRsa_GMP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	mpz_clear( gmpCtx->mN );
	mpz_clear( gmpCtx->mE );
	mpz_clear( gmpCtx->mD );

	free( gmpCtx );
}

int VNRsa_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	mpz_t zp, zq, zr, zrand;
	gmp_randstate_t state;

	VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	mpz_init( zp );
	mpz_init( zq );
	mpz_init( zr );
	mpz_init( zrand );

	gmp_randinit_default( state );
	gmp_randseed_ui( state, time( NULL ) );

	do {
		mpz_urandomb( zrand, state, keyBits );
	} while( keyBits != mpz_sizeinbase( zrand, 2 ) );

	mpz_set( zp, zrand );
	do {
		mpz_nextprime( zp, zp );
		mpz_sub_ui( zr, zp, 1 );
		mpz_gcd( zr, zr, gmpCtx->mE );
	} while( mpz_cmp_ui( zr, 1 ) != 0 );

	mpz_set( zq, zp );
	do {
		mpz_nextprime( zq, zq );
		mpz_sub_ui( zr, zq, 1 );
		mpz_gcd( zr, zr, gmpCtx->mE );
	} while( mpz_cmp_ui( zr, 1 ) != 0 );

	/* compute public key n */
	mpz_mul( gmpCtx->mN, zp, zq );

	/* compute private key ( e * d ) = 1 ( mod (p-1)(q-1) ) */
	mpz_sub_ui( zp, zp, 1 );
	mpz_sub_ui( zq, zq, 1 );
	mpz_mul( zr, zp, zq );
	mpz_invert( gmpCtx->mD, gmpCtx->mE, zr );

	mpz_clear( zp );
	mpz_clear( zq );
	mpz_clear( zr );
	mpz_clear( zrand );

	gmp_randclear( state );

	return 0;
}

void VNRsa_GMP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	mpz_set_ui( gmpCtx->mN, 0 );
	mpz_set_ui( gmpCtx->mE, 0 );
	mpz_set_ui( gmpCtx->mD, 0 );
}

int VNRsa_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	VN_GMP_dump_hex( gmpCtx->mN, hexPubKey );
	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_GMP_dump_hex( gmpCtx->mE, hexPubKey->next );

	return 0;
}

int VNRsa_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	VN_GMP_dump_hex( gmpCtx->mN, hexPubKey );
	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	VN_GMP_dump_hex( gmpCtx->mE, hexPubKey->next );

	VN_GMP_dump_hex( gmpCtx->mD, hexPrivKey );

	return 0;
}

int VNRsa_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	VN_GMP_load_hex( hexPubKey, gmpCtx->mN );
	VN_GMP_load_hex( hexPubKey->next, gmpCtx->mE );

	return 0;
}

int VNRsa_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	VN_GMP_load_hex( hexPubKey, gmpCtx->mN );
	VN_GMP_load_hex( hexPubKey->next, gmpCtx->mE );

	VN_GMP_load_hex( hexPrivKey, gmpCtx->mD );

	return 0;
}

int VNRsa_GMP_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	mpz_t zm, zs;

	const VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	mpz_init( zm );
	mpz_import( zm, length, 1, 1, 0, 0, plainText );

	if( mpz_cmp( zm, gmpCtx->mN ) >= 0 )
	{
		mpz_clear( zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}
	
	mpz_init( zs );

	mpz_powm( zs, zm, gmpCtx->mD, gmpCtx->mN );

	cipherText->i.iov_len = ( mpz_sizeinbase( zs, 2 ) + 7 ) / 8;
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );
	((char*)cipherText->i.iov_base)[ cipherText->i.iov_len ] = '\0';
	mpz_export( cipherText->i.iov_base, &cipherText->i.iov_len, 1, 1, 0, 0, zs );

	mpz_clear( zm );
	mpz_clear( zs );

	return 0;
}

int VNRsa_GMP_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	mpz_t zm, zs;

	const VNRsa_GMP_Ctx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNRsa_GMP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_GMP == ctx->mType || VN_TYPE_VNRsaEnc_GMP == ctx->mType );

	mpz_init( zm );
	mpz_init( zs );

	mpz_import( zs, length, 1, 1, 0, 0, cipherText );

	mpz_powm( zm, zs, gmpCtx->mE, gmpCtx->mN );

	plainText->i.iov_len = ( mpz_sizeinbase( zm, 2 ) + 7 ) / 8;
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );
	((char*)plainText->i.iov_base)[ plainText->i.iov_len ] = '\0';
	mpz_export( plainText->i.iov_base, &plainText->i.iov_len, 1, 1, 0, 0, zm );

	mpz_clear( zm );
	mpz_clear( zs );

	return 0;
}

