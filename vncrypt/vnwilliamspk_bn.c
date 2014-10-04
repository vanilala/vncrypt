/**
 * Algorithm source: "A modification of the RSA Public-Key Encryption Procedure"
 * H. C. Williams
 *
 */

#include "vnwilliamspk_bn.h"
#include "vncrypt_bn.h"

#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNWilliamsPK_BNCtx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mD;
} VNWilliamsPK_BNCtx_t;

VNAsymCryptCtx_t * VNWilliamsPK_BNCtx_New()
{
	VNWilliamsPK_BNCtx_t * bnCtx = (VNWilliamsPK_BNCtx_t *)calloc( sizeof( VNWilliamsPK_BNCtx_t ), 1 );

	bnCtx->mCtx.mType = VN_TYPE_VNWilliamsPK_BN;

	bnCtx->mCtx.mMethod.mGenKeys = VNWilliamsPK_BN_GenKeys;
	bnCtx->mCtx.mMethod.mClearKeys = VNWilliamsPK_BN_ClearKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNWilliamsPK_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNWilliamsPK_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNWilliamsPK_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNWilliamsPK_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPubEncrypt = VNWilliamsPK_BN_PubEncrypt;
	bnCtx->mCtx.mMethod.mPrivDecrypt = VNWilliamsPK_BN_PrivDecrypt;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mD ) );

	return &( bnCtx->mCtx );
}

void VNWilliamsPK_BNCtx_Free( VNAsymCryptCtx_t * ctx )
{
	VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

int VNWilliamsPK_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM zp, zq;

	VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

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

void VNWilliamsPK_BN_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	BN_clear( &( bnCtx->mN ) );
	BN_clear( &( bnCtx->mD ) );
}

int VNWilliamsPK_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey )
{
	const VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );

	return 0;
}

int VNWilliamsPK_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey )
{
	const VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	VN_BN_dump_hex( &( bnCtx->mN ), hexPubKey );
	VN_BN_dump_hex( &( bnCtx->mD ), hexPrivKey );

	return 0;
}

int VNWilliamsPK_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey )
{
	VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );

	return 0;
}

int VNWilliamsPK_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey )
{
	VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	VN_BN_load_hex( hexPubKey, &( bnCtx->mN ) );
	VN_BN_load_hex( hexPrivKey, &( bnCtx->mD ) );

	return 0;
}

int VNWilliamsPK_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText )
{
	int ret = 0, jacobi = 0;

	BIGNUM zm, zc;

	const VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	BN_init( &zm );
	BN_bin2bn( plainText, length, &zm );

	if( ( BN_num_bits( &( bnCtx->mN ) ) - BN_num_bits( &( zm ) ) ) < 4 )
	{
		BN_free( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	BN_init( &zc );

	BN_mul_word( &zm, 2 );
	BN_add_word( &zm, 1 );

	ret = VN_BN_jacobi( &zm, &( bnCtx->mN ), &jacobi, bnCtx->mBNCtx );

	if( 1 == jacobi )
	{
		BN_mul_word( &zm, 4 );
	} else if( -1 == jacobi ) {
		BN_mul_word( &zm, 2 );
	} else {
		ret = -1;
	}

	BN_mod_mul( &zc, &zm, &zm, &( bnCtx->mN ), bnCtx->mBNCtx );

	cipherText->iov_len = BN_num_bytes( &zc );
	cipherText->iov_base = malloc( cipherText->iov_len + 1);
	BN_bn2bin( &zc, cipherText->iov_base );

	BN_free( &zm );
	BN_free( &zc );

	return ret;
}


int VNWilliamsPK_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText )
{
	BIGNUM zm, zc;
	int mod = 0;

	const VNWilliamsPK_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNWilliamsPK_BNCtx_t, mCtx );
	assert( VN_TYPE_VNWilliamsPK_BN == ctx->mType );

	BN_init( &zm );
	BN_init( &zc );

	BN_bin2bn( cipherText, length, &zc );

	BN_mod_exp( &zm, &zc, &( bnCtx->mD ), &( bnCtx->mN ), bnCtx->mBNCtx );

	mod = BN_mod_word( &zm, 4 );

	if( 0 == mod )
	{
		BN_rshift( &zm, &zm, 2 );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	} else if( 1 == mod ) {
		BN_sub( &zm, &( bnCtx->mN ), &zm );
		BN_rshift( &zm, &zm, 2 );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	} else if( 2 == mod ) {
		BN_rshift1( &zm, &zm );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	} else if( 3 == mod ) {
		BN_sub( &zm, &( bnCtx->mN ), &zm );
		BN_rshift1( &zm, &zm );
		BN_sub_word( &zm, 1 );
		BN_rshift1( &zm, &zm );
	}

	plainText->iov_len = BN_num_bytes( &zm );
	plainText->iov_base = malloc( plainText->iov_len + 1);
	BN_bn2bin( &zm, plainText->iov_base );

	BN_free( &zm );
	BN_free( &zc );

	return 0;
}

