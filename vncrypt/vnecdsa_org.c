/**
 *
 * OpenSSL ECDSA
 *
 */

#include "vnecdsa_org.h"
#include "vncrypt_bn.h"

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/objects.h>
#include <openssl/err.h>
#include <openssl/ecdh.h>

#include <assert.h>
#include <string.h>

typedef struct tagVNEcdsa_ORG_Ctx {
	VNAsymCryptCtx_t mCtx;

	EC_KEY * mEcKey;
	int mNid;
} VNEcdsa_ORG_Ctx_t;

static VNAsymCryptCtx_t * VNEcdsa_ORG_CtxNewImpl()
{
	VNEcdsa_ORG_Ctx_t * orgCtx = (VNEcdsa_ORG_Ctx_t *)calloc( sizeof( VNEcdsa_ORG_Ctx_t ), 1 );

	orgCtx->mCtx.mMethod.mCtxFree = VNEcdsa_ORG_CtxFree;
	orgCtx->mCtx.mMethod.mGenKeys = VNEcdsa_ORG_GenKeys;
	orgCtx->mCtx.mMethod.mClearKeys = VNEcdsa_ORG_ClearKeys;
	orgCtx->mCtx.mMethod.mDumpPubKey = VNEcdsa_ORG_DumpPubKey;
	orgCtx->mCtx.mMethod.mDumpPrivKey = VNEcdsa_ORG_DumpPrivKey;
	orgCtx->mCtx.mMethod.mLoadPubKey = VNEcdsa_ORG_LoadPubKey;
	orgCtx->mCtx.mMethod.mLoadPrivKey = VNEcdsa_ORG_LoadPrivKey;
	orgCtx->mCtx.mMethod.mSign = VNEcdsa_ORG_Sign;
	orgCtx->mCtx.mMethod.mVerify = VNEcdsa_ORG_Verify;

	orgCtx->mEcKey = NULL;

	return &( orgCtx->mCtx );
}

VNAsymCryptCtx_t * VNEcdsaSign_ORG_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNEcdsa_ORG_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNEcdsaSign_ORG;

	return ctx;
}

void VNEcdsa_ORG_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	if( NULL != orgCtx->mEcKey ) EC_KEY_free( orgCtx->mEcKey );

	free( orgCtx );
}

int VNEcdsa_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	int ret = 0, index = -1, interval = 0, minInterval = 102400;
	size_t len = 0, i = 0;
	EC_builtin_curve * curves = NULL;
	const char * pos = NULL;

	VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	{
		len = EC_get_builtin_curves( NULL, 0 );
		curves = (EC_builtin_curve*)calloc( sizeof( EC_builtin_curve ), len );
		EC_get_builtin_curves( curves, len );

		for( i = 0; i < len; i++ )
		{
			pos = strstr( curves[i].comment, "over a" );
			if( NULL != pos )
			{
				interval = abs( atoi( pos + 6 ) - keyBits );
				if( interval >= 0 && interval < minInterval )
				{
					minInterval = interval;
					index = i;
				}
			}

			//printf( "%d, %s\n", curves[i].nid, curves[i].comment );
		}

		printf( "\n\tuse %d, %s\n\n", curves[ index ].nid, curves[ index ].comment );

		orgCtx->mNid = curves[ index ].nid;

		free( curves );
	}

	orgCtx->mEcKey = EC_KEY_new_by_curve_name( orgCtx->mNid );
	if( NULL != orgCtx->mEcKey )
	{
		if( ! EC_KEY_generate_key( orgCtx->mEcKey ) )
		{
			char buff[ 1024 ] = { 0 };
			printf( "EC_KEY_generate_key %d, %s\n", ret, ERR_error_string( ERR_get_error(), buff ) );
			ret = -1;
		}
	} else {
		char buff[ 1024 ] = { 0 };
		printf( "EC_KEY_new_by_curve_name %d, %s\n", ret, ERR_error_string( ERR_get_error(), buff ) );
		ret = -1;
	}

	return ret;
}

void VNEcdsa_ORG_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	if( NULL != orgCtx->mEcKey ) EC_KEY_free( orgCtx->mEcKey );

	orgCtx->mEcKey = EC_KEY_new_by_curve_name( orgCtx->mNid );
}

int VNEcdsa_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	char * tmp = NULL;
	const EC_POINT * point = NULL;

	const VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	point = EC_KEY_get0_public_key( orgCtx->mEcKey );
	tmp = EC_POINT_point2hex( EC_KEY_get0_group( orgCtx->mEcKey ),
			point, POINT_CONVERSION_UNCOMPRESSED, NULL );

	hexPubKey->i.iov_len = strlen( tmp );
	hexPubKey->i.iov_base = strdup( tmp );

	OPENSSL_free( tmp );

	return 0;
}

int VNEcdsa_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const BIGNUM * tmp = NULL;

	const VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	VNEcdsa_ORG_DumpPubKey( ctx, hexPubKey );

	tmp = EC_KEY_get0_private_key( orgCtx->mEcKey );

	if( NULL != tmp ) VN_BN_dump_hex( tmp, hexPrivKey );

	return 0;
}

int VNEcdsa_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	EC_POINT * point = NULL;

	VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	point = EC_POINT_new( EC_KEY_get0_group( orgCtx->mEcKey ) );

	EC_POINT_hex2point( EC_KEY_get0_group( orgCtx->mEcKey ), hexPubKey->i.iov_base,
		point, NULL );

	EC_KEY_set_public_key( orgCtx->mEcKey, point );

	EC_POINT_free( point );

	return 0;
}

int VNEcdsa_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	BIGNUM tmp;

	VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	BN_init( &tmp );

	VNEcdsa_ORG_LoadPubKey( ctx, hexPubKey );

	VN_BN_load_hex( hexPrivKey, &tmp );

	EC_KEY_set_private_key( orgCtx->mEcKey, &tmp );

	BN_free( &tmp );

	return 0;
}

int VNEcdsa_ORG_Sign( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * signText )
{
	int ret = 0;

	VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	signText->i.iov_len = ECDSA_size( orgCtx->mEcKey );
	signText->i.iov_base = malloc( signText->i.iov_len );

	ret = ECDSA_sign( 0, plainText, length, signText->i.iov_base,
		(unsigned int *)&( signText->i.iov_len ), orgCtx->mEcKey );

	if( 1 != ret )
	{
		char buff[ 1024 ] = { 0 };
		printf( "ECDSA_sign %d, %s\n", ret, ERR_error_string( ERR_get_error(), buff ) );
	}

	return 1 == ret ? 0 : -1;
}

int VNEcdsa_ORG_Verify( const VNAsymCryptCtx_t * ctx,
	const unsigned char * signText, int length,
	const struct vn_iovec * plainText )
{
	int ret = 0;

	VNEcdsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNEcdsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcdsaSign_ORG == ctx->mType );

	ret = ECDSA_verify( 0, plainText->i.iov_base, plainText->i.iov_len,
		signText, length, orgCtx->mEcKey );

	if( 1 != ret )
	{
		char buff[ 1024 ] = { 0 };
		printf( "ECDSA_sign %d, %s\n", ret, ERR_error_string( ERR_get_error(), buff ) );
	}

	return 1 == ret ? 0 : -1;
}

