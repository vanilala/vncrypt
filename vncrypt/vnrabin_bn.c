
#include "vnrabin_bn.h"

#include <openssl/bn.h>
#include <assert.h>
#include <string.h>

int VN_BN_jacobi( const BIGNUM *za, const BIGNUM *zn, int *jacobi, BN_CTX *ctx );

typedef struct tagVNRabin_BNCtx {
	VNAsymCryptCtx_t mCtx;

	BN_CTX * mBNCtx;

	BIGNUM mN;
	BIGNUM mD;
} VNRabin_BNCtx_t;

VNAsymCryptCtx_t * VNRabin_BNCtx_New()
{
	VNRabin_BNCtx_t * bnCtx = (VNRabin_BNCtx_t *)calloc( sizeof( VNRabin_BNCtx_t ), 1 );

	bnCtx->mCtx.mType = TYPE_VNRabin_BN;

	bnCtx->mCtx.mMethod.mGenKeys = VNRabin_BN_GenKeys;
	bnCtx->mCtx.mMethod.mDumpPubKey = VNRabin_BN_DumpPubKey;
	bnCtx->mCtx.mMethod.mDumpPrivKey = VNRabin_BN_DumpPrivKey;
	bnCtx->mCtx.mMethod.mLoadPubKey = VNRabin_BN_LoadPubKey;
	bnCtx->mCtx.mMethod.mLoadPrivKey = VNRabin_BN_LoadPrivKey;
	bnCtx->mCtx.mMethod.mPrivEncrypt = VNRabin_BN_PrivEncrypt;
	bnCtx->mCtx.mMethod.mPubDecrypt = VNRabin_BN_PubDecrypt;

	bnCtx->mBNCtx = BN_CTX_new();

	BN_init( &( bnCtx->mN ) );
	BN_init( &( bnCtx->mD ) );

	return &( bnCtx->mCtx );
}

void VNRabin_BNCtx_Free( VNAsymCryptCtx_t * ctx )
{
	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );

	assert( TYPE_VNRabin_BN == ctx->mType );

	BN_free( &( bnCtx->mN ) );
	BN_free( &( bnCtx->mD ) );

	BN_CTX_free( bnCtx->mBNCtx );

	free( bnCtx );
}

int VNRabin_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	BIGNUM za, zb, zp, zq;

	BN_init( &za );
	BN_init( &zb );
	BN_init( &zp );
	BN_init( &zq );

	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );
	assert( TYPE_VNRabin_BN == ctx->mType );

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

int VNRabin_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey )
{
	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );
	assert( TYPE_VNRabin_BN == ctx->mType );

	char * tmp = BN_bn2hex( &( bnCtx->mN ) );

	hexPubKey->iov_len = strlen( tmp );
	hexPubKey->iov_base = strdup( tmp );

	OPENSSL_free( tmp );

	return 0;
}

int VNRabin_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey )
{
	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );
	assert( TYPE_VNRabin_BN == ctx->mType );

	char * tmp = BN_bn2hex( &( bnCtx->mN ) );

	hexPubKey->iov_len = strlen( tmp );
	hexPubKey->iov_base = strdup( tmp );

	OPENSSL_free( tmp );

	tmp = BN_bn2hex( &( bnCtx->mD ) );

	hexPrivKey->iov_len = strlen( tmp );
	hexPrivKey->iov_base = strdup( tmp );

	OPENSSL_free( tmp );

	return 0;
}

int VNRabin_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey )
{
	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );
	assert( TYPE_VNRabin_BN == ctx->mType );

	BIGNUM * tmp = NULL;

	BN_hex2bn( &tmp, hexPubKey->iov_base );
	BN_copy( &( bnCtx->mN ), tmp );

	BN_free( tmp );

	return 0;
}

int VNRabin_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey )
{
	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );
	assert( TYPE_VNRabin_BN == ctx->mType );

	BIGNUM * tmp = NULL;

	BN_hex2bn( &tmp, hexPubKey->iov_base );
	BN_copy( &( bnCtx->mN ), tmp );

	BN_free( tmp );

	tmp = NULL;

	BN_hex2bn( &tmp, hexPrivKey->iov_base );
	BN_copy( &( bnCtx->mD ), tmp );

	BN_free( tmp );

	return 0;
}

int VNRabin_BN_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	unsigned char * plainText, int length,
	struct iovec * cipherText )
{
	int ret = 0, jacobi = 0;
	BIGNUM zm, zs;

	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );
	assert( TYPE_VNRabin_BN == ctx->mType );

	BN_init( &zm );
	BN_init( &zs );

	BN_bin2bn( plainText, length, &zm );

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

	cipherText->iov_len = BN_num_bytes( &zs );
	cipherText->iov_base = malloc( cipherText->iov_len + 1);
	BN_bn2bin( &zs, cipherText->iov_base );

	BN_free( &zm );
	BN_free( &zs );

	return ret;
}

int VNRabin_BN_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	unsigned char * cipherText, int length,
	struct iovec * plainText )
{
	int ret = 0, mod = 0;
	BIGNUM zm, zm1, zs;

	VNRabin_BNCtx_t * bnCtx = VN_CONTAINER_OF( ctx, VNRabin_BNCtx_t, mCtx );
	assert( TYPE_VNRabin_BN == ctx->mType );

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

	if( BN_mod_word( &zm, 16 ) == 6 ) {
		ret = 0;

		BN_sub_word( &zm, 6 );
		BN_div_word( &zm, 16 );

		plainText->iov_len = BN_num_bytes( &zm );
		plainText->iov_base = malloc( plainText->iov_len + 1);
		BN_bn2bin( &zm, plainText->iov_base );
	} else {
		ret = -1;
	}

	BN_free( &zm );
	BN_free( &zm1 );
	BN_free( &zs );

	return ret;
}

int VN_BN_jacobi( const BIGNUM *za, const BIGNUM *zn, int *jacobi, BN_CTX *ctx )
{
	int ret = 0, e = 0, s = 0, mod = -1, amod = -1;

	BIGNUM zero, three, za1, zn1;

	BN_init( &zero );
	BN_init( &three );
	BN_init( &za1 );
	BN_init( &zn1 );

	BN_set_word( &zero, 0 );
	BN_set_word( &three, 3 );

	BN_copy( &za1, za );
	BN_copy( &zn1, zn );

	for( *jacobi = 1; 0 == ret; )
	{
		if( ! BN_is_odd( &zn1 ) ) { ret = -1; break; }
		if( BN_cmp( &zn1, &three ) < 0 ) { ret = -1; break; }
		if( ( BN_cmp( &za1, &zn1 ) > 0 ) || ( BN_cmp( za, &zero ) < 0 ) ) { ret = -1; break; }

		if( BN_is_zero( &za1 ) ) break;         // step1
		if( BN_is_one( &za1 ) ) break;          // step2

		for( e = 0; ; e++ )                     // step3
		{
			if( BN_is_odd( &za1 ) ) break;
			BN_rshift1( &za1, &za1 );
		 }

		if( 0 == ( e % 2 ) )                    // step4
		{
			s = 1;
		} else {
			mod = BN_mod_word( &zn1, 8 );

			if( 1 == mod || 7 == mod ) s = 1;
			if( 3 == mod || 5 == mod ) s = -1;
		}

		amod = BN_mod_word( &za1, 4 );          // step5
		mod =  BN_mod_word( &zn1, 4 );
		if( 3 == mod && 3 == amod ) s = - s;

		BN_mod( &zn1, &zn1, &za1, ctx );    // step6

		*jacobi = ( *jacobi ) * s;              // step7

		if( BN_is_one( &za1 ) ) break;
		BN_swap( &za1, &zn1 );
	}

	BN_free( &zero );
	BN_free( &three );
	BN_free( &za1 );
	BN_free( &zn1 );

	return ret;
}

