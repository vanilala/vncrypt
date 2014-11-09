
#include "vnmodrabin_gmp.h"

#include <gmp.h>

#include <stdlib.h>
#include <assert.h>
#include <time.h>

typedef struct tagVNModRabin_GMPCtx {
	VNAsymCryptCtx_t mCtx;

	mpz_t mN;
	mpz_t mD;
} VNModRabin_GMPCtx_t;

VNAsymCryptCtx_t * VNModRabinSign_GMP_CtxNew()
{
	VNModRabin_GMPCtx_t * gmpCtx = (VNModRabin_GMPCtx_t *)calloc( sizeof( VNModRabin_GMPCtx_t ), 1 );

	gmpCtx->mCtx.mType = VN_TYPE_VNModRabinSign_GMP;

	gmpCtx->mCtx.mMethod.mCtxFree = VNModRabin_GMP_CtxFree;
	gmpCtx->mCtx.mMethod.mGenKeys = VNModRabin_GMP_GenKeys;
	gmpCtx->mCtx.mMethod.mClearKeys = VNModRabin_GMP_ClearKeys;
	gmpCtx->mCtx.mMethod.mDumpPubKey = VNModRabin_GMP_DumpPubKey;
	gmpCtx->mCtx.mMethod.mDumpPrivKey = VNModRabin_GMP_DumpPrivKey;
	gmpCtx->mCtx.mMethod.mLoadPubKey = VNModRabin_GMP_LoadPubKey;
	gmpCtx->mCtx.mMethod.mLoadPrivKey = VNModRabin_GMP_LoadPrivKey;
	gmpCtx->mCtx.mMethod.mPrivEncrypt = VNModRabin_GMP_PrivEncrypt;
	gmpCtx->mCtx.mMethod.mPubDecrypt = VNModRabin_GMP_PubDecrypt;

	mpz_init( gmpCtx->mN );
	mpz_init( gmpCtx->mD );

	return &( gmpCtx->mCtx );
}

void VNModRabin_GMP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	mpz_clear( gmpCtx->mN );
	mpz_clear( gmpCtx->mD );

	free( gmpCtx );
}

int VNModRabin_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	mpz_t za, zb, zp, zq, rand;

	unsigned long int seed = (unsigned long int)time(NULL);

	VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	gmp_randstate_t r_state;

	mpz_init(za);
	mpz_init(zb);
	mpz_init(zp);
	mpz_init(zq);
	mpz_init(rand);

	gmp_randinit_default(r_state);
	gmp_randseed_ui(r_state, seed);

	keyBits = ( keyBits + 1 ) / 2;

	// gen rand
	size_t size = 0;
	while (size != keyBits)
	{
		mpz_urandomb(rand, r_state, keyBits);
		size = mpz_sizeinbase(rand, 2);
	}

	/* choose a prime p such that p mod 8 == 3 */
	mpz_set(zp, rand);
	do
	{
		mpz_nextprime(zp, zp);
	} while (mpz_fdiv_ui(zp, 8l) != 3l);

	/* choose a prime q such that q mod 8 == 7 */
	mpz_set(zq, rand);
	do
	{
		mpz_nextprime(zq, zq);
	} while (mpz_fdiv_ui(zq, 8l) != 7l);

	/* compute public key n*/
	mpz_mul( gmpCtx->mN, zp, zq);

	/* compute private key d = (n - p - q + 5) / 8 */
	mpz_add(za, zp, zq);
	mpz_sub(zb, gmpCtx->mN, za);
	mpz_add_ui(za, zb, 5l);
	mpz_cdiv_q_ui(gmpCtx->mD, za, 8l);

	mpz_clear(za);
	mpz_clear(zb);
	mpz_clear(zp);
	mpz_clear(zq);
	mpz_clear(rand);

	gmp_randclear(r_state);

	return 0;
}

void VNModRabin_GMP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	mpz_clear( gmpCtx->mN );
	mpz_init( gmpCtx->mN );

	mpz_clear( gmpCtx->mD );
	mpz_init( gmpCtx->mD );
}

int VNModRabin_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	hexPubKey->i.iov_len = ( mpz_sizeinbase( gmpCtx->mN, 2 ) + 7 ) / 8 * 2;
	hexPubKey->i.iov_base = calloc( 1, hexPubKey->i.iov_len + 1 );

	mpz_get_str( (char*)hexPubKey->i.iov_base, 16, gmpCtx->mN );

	return 0;
}

int VNModRabin_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	hexPubKey->i.iov_len = ( mpz_sizeinbase( gmpCtx->mN, 2 ) + 7 ) / 8 * 2;
	hexPubKey->i.iov_base = calloc( 1, hexPubKey->i.iov_len + 1 );

	mpz_get_str( (char*)hexPubKey->i.iov_base, 16, gmpCtx->mN );

	hexPrivKey->i.iov_len = ( mpz_sizeinbase( gmpCtx->mD, 2 ) + 7 ) / 8 * 2;
	hexPrivKey->i.iov_base = calloc( 1, hexPrivKey->i.iov_len + 1 );

	mpz_get_str( (char*)hexPrivKey->i.iov_base, 16, gmpCtx->mD );

	return 0;
}

int VNModRabin_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	mpz_set_str( gmpCtx->mN, (char*)hexPubKey->i.iov_base, 16 );

	return 0;
}

int VNModRabin_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	mpz_set_str( gmpCtx->mN, (char*)hexPubKey->i.iov_base, 16 );
	mpz_set_str( gmpCtx->mD, (char*)hexPrivKey->i.iov_base, 16 );

	return 0;
}

int VNModRabin_GMP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0, jacobi = 0;
	mpz_t zm, zs;

	const VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	mpz_init( zm );
	mpz_import( zm, length, 1, 1, 0, 0, plainText );

	if( mpz_cmp( zm, gmpCtx->mN ) >= 0 )
	{
		mpz_clear( zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	mpz_init( zs );

	mpz_mul_ui( zm, zm, 16 );
	mpz_add_ui( zm, zm, 6 );

	jacobi = mpz_jacobi( zm, gmpCtx->mN );

	if( jacobi == 1 )
	{
		mpz_powm( zs, zm, gmpCtx->mD, gmpCtx->mN );
	} else if( jacobi == -1 ) {
		mpz_cdiv_q_ui( zm, zm, 2 );
		mpz_powm( zs, zm, gmpCtx->mD, gmpCtx->mN );
	} else {
		ret = -1;
	}

	if( 0 == ret )
	{
		cipherText->i.iov_len = ( mpz_sizeinbase( zs, 2 ) + 7 ) / 8;
		cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );
		((char*)cipherText->i.iov_base)[ cipherText->i.iov_len ] = '\0';
		mpz_export( cipherText->i.iov_base, &cipherText->i.iov_len, 1, 1, 0, 0, zs);
	}

	mpz_clear( zm );
	mpz_clear( zs );

	return ret;
}

int VNModRabin_GMP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0, mod = 0;
	mpz_t zm, zm1, zs;

	const VNModRabin_GMPCtx_t * gmpCtx = VN_CONTAINER_OF( ctx, VNModRabin_GMPCtx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GMP == ctx->mType );

	mpz_init( zm );
	mpz_init( zm1 );
	mpz_init( zs );

	mpz_import( zs, length, 1, 1, 0, 0, cipherText );

	mpz_powm_ui( zm1, zs, 2, gmpCtx->mN );
	mod = mpz_fdiv_ui( zm1, 8 );

	if( mod == 6 )
	{
		mpz_swap( zm, zm1 );
	} else if( mod == 3 ) {
		mpz_mul_ui( zm, zm1, 2 );
	} else if( mod == 7 ) {
		mpz_sub( zm, gmpCtx->mN, zm1 );
	} else if( mod == 2 ) {
		mpz_sub( zm, gmpCtx->mN, zm1 );
		mpz_mul_ui( zm, zm, 2 );
	}

	if( mpz_fdiv_ui( zm, 16 ) == 6 ) 
	{
		mpz_sub_ui( zm, zm, 6 );
		mpz_cdiv_q_ui( zm, zm, 16 );

		plainText->i.iov_len = ( mpz_sizeinbase( zm, 2 ) + 7 ) / 8;
		plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );
		((char*)plainText->i.iov_base)[ plainText->i.iov_len ] = '\0';
		mpz_export( plainText->i.iov_base, &plainText->i.iov_len, 1, 1, 0, 0, zm);
	} else {
		ret = -1;
	}

	mpz_clear( zm );
	mpz_clear( zm1 );
	mpz_clear( zs );

	return ret;
}

