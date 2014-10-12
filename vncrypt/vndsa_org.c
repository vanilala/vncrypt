/**
 *
 * OpenSSL DSA
 *
 */

#include "vndsa_org.h"

#include <openssl/bn.h>
#include <openssl/dsa.h>
#include <openssl/err.h>
#include <assert.h>
#include <string.h>

typedef struct tagVNDsa_ORG_Ctx {
	VNAsymCryptCtx_t mCtx;

	DSA * mDSA;
} VNDsa_ORG_Ctx_t;

static VNAsymCryptCtx_t * VNDsa_ORG_CtxNewImpl()
{
	VNDsa_ORG_Ctx_t * orgCtx = (VNDsa_ORG_Ctx_t *)calloc( sizeof( VNDsa_ORG_Ctx_t ), 1 );

	orgCtx->mCtx.mMethod.mCtxFree = VNDsa_ORG_CtxFree;
	orgCtx->mCtx.mMethod.mGenKeys = VNDsa_ORG_GenKeys;
	orgCtx->mCtx.mMethod.mClearKeys = VNDsa_ORG_ClearKeys;
	orgCtx->mCtx.mMethod.mDumpPubKey = VNDsa_ORG_DumpPubKey;
	orgCtx->mCtx.mMethod.mDumpPrivKey = VNDsa_ORG_DumpPrivKey;
	orgCtx->mCtx.mMethod.mLoadPubKey = VNDsa_ORG_LoadPubKey;
	orgCtx->mCtx.mMethod.mLoadPrivKey = VNDsa_ORG_LoadPrivKey;
	orgCtx->mCtx.mMethod.mSign = VNDsa_ORG_Sign;
	orgCtx->mCtx.mMethod.mVerify = VNDsa_ORG_Verify;

	orgCtx->mDSA = DSA_new();

	return &( orgCtx->mCtx );
}

VNAsymCryptCtx_t * VNDsaSign_ORG_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNDsa_ORG_CtxNewImpl( e );
	ctx->mType = VN_TYPE_VNDsaSign_ORG;

	return ctx;
}

void VNDsa_ORG_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	if( NULL != orgCtx->mDSA ) DSA_free( orgCtx->mDSA );

	free( orgCtx );
}

int VNDsa_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	int ret = 0;

	VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	struct vn_iovec seed;
	VNIovecGetRandomBuffer( &seed, keyBits / 8 + 1 );

	int counter = 0;
	unsigned long hRet;

	ret = DSA_generate_parameters_ex( orgCtx->mDSA, keyBits, (unsigned char*)seed.i.iov_base,
		seed.i.iov_len, &counter, &hRet, NULL );

	if( 1 != ret )
	{
		char buff[ 1024 ] = { 0 };
		printf( "DSA_generate_parameters_ex %d, %s\n", ret, ERR_error_string( ERR_get_error(), buff ) );
	}

	ret = DSA_generate_key( orgCtx->mDSA );

	if( 1 != ret )
	{
		char buff[ 1024 ] = { 0 };
		printf( "DSA_generate_key %d, %s\n", ret, ERR_error_string( ERR_get_error(), buff ) );
	}

	VNIovecFreeBufferAndTail( &seed );

	return 0;
}

void VNDsa_ORG_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	//VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	//assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );
}

int VNDsa_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	//const VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	//assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	return 0;
}

int VNDsa_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	//const VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	//assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	return 0;
}

int VNDsa_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	//VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	//assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	return 0;
}

int VNDsa_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	//VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	//assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	return 0;
}

int VNDsa_ORG_Sign( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * signText )
{
	int ret = 0;

	VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	signText->i.iov_len = DSA_size( orgCtx->mDSA );
	signText->i.iov_base = calloc( 1, signText->i.iov_len + 1 );

	if( length > signText->i.iov_len )
	{
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	ret = DSA_sign( 0, plainText, length,
		signText->i.iov_base, (unsigned int *)&( signText->i.iov_len ), orgCtx->mDSA );

	return 1 == ret ? 0 : -1;
}

int VNDsa_ORG_Verify( const VNAsymCryptCtx_t * ctx,
	const unsigned char * signText, int length,
	const struct vn_iovec * plainText )
{
	int ret = 0;

	VNDsa_ORG_Ctx_t * orgCtx = VN_CONTAINER_OF( ctx, VNDsa_ORG_Ctx_t, mCtx );
	assert( VN_TYPE_VNDsaSign_ORG == ctx->mType );

	ret = DSA_verify( 0, plainText->i.iov_base, plainText->i.iov_len,
			signText, length, orgCtx->mDSA );

	if( 1 != ret )
	{
		char buff[ 1024 ] = { 0 };
		printf( "Verify %p, %zd, %d, %s\n", plainText->i.iov_base, plainText->i.iov_len,
			ret, ERR_error_string( ERR_get_error(), buff ) );

		ERR_print_errors_fp( stdout );
	}

	return 1 == ret ? 0 : -1;
}

