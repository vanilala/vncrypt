/**
 *
 * Modified-Rabin signature scheme
 *
 * See "Handbook of Applied Cryptography" by Alfred J. Menezes et al pages 440 - 441.
 *
 */

#include "vncrypt_lip.h"
#include "vnrabin_lip.h"

#include "lip/lip.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef struct tagVNRabin_LIP_Ctx {
	VNAsymCryptCtx_t mCtx;

	verylong mN;
	verylong mD;
} VNRabin_LIP_Ctx_t;

VNAsymCryptCtx_t * VNRabin_LIP_CtxNew()
{
	VNRabin_LIP_Ctx_t * lipCtx = (VNRabin_LIP_Ctx_t *)calloc( sizeof( VNRabin_LIP_Ctx_t ), 1 );

	lipCtx->mCtx.mType = VN_TYPE_VNRabinSign_LIP;

	lipCtx->mCtx.mMethod.mCtxFree = VNRabin_LIP_CtxFree;
	lipCtx->mCtx.mMethod.mGenKeys = VNRabin_LIP_GenKeys;
	lipCtx->mCtx.mMethod.mClearKeys = VNRabin_LIP_ClearKeys;
	lipCtx->mCtx.mMethod.mDumpPubKey = VNRabin_LIP_DumpPubKey;
	lipCtx->mCtx.mMethod.mDumpPrivKey = VNRabin_LIP_DumpPrivKey;
	lipCtx->mCtx.mMethod.mLoadPubKey = VNRabin_LIP_LoadPubKey;
	lipCtx->mCtx.mMethod.mLoadPrivKey = VNRabin_LIP_LoadPrivKey;
	lipCtx->mCtx.mMethod.mPrivEncrypt = VNRabin_LIP_PrivEncrypt;
	lipCtx->mCtx.mMethod.mPubDecrypt = VNRabin_LIP_PubDecrypt;

	zzero( &( lipCtx->mN ) );
	zzero( &( lipCtx->mD ) );

	return &( lipCtx->mCtx );
}

void VNRabin_LIP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	zfree( &( lipCtx->mN ) );
	zfree( &( lipCtx->mD ) );

	free( lipCtx );
}

int VNRabin_LIP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	verylong za = 0, zp = 0, zq = 0;

	VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	zzero( &za );
	zzero( &zp );
	zzero( &zq );

	zrstarts( time( NULL ) );

	/* choose a prime q such that q mod 8 == 7 */
	do
		zrandomprime( keyBits, 5l, &zq, zrandomb );
	while (zsmod(zq, 8l) != 7l);

	/* choose a prime p such that p mod 8 == 3 */
	do
		zrandomprime( keyBits, 5l, &zp, zrandomb );
	while (zsmod(zp, 8l) != 3l);

	/* compute public key n*/
	zmul( zp, zq, &( lipCtx->mN ) );

	/* compute private key d = (n - p - q + 5) / 8 */
	zadd( zp, zq, &za );
	zsub( lipCtx->mN, za, &za );
	zsadd( za, 5, &za );
	zsdiv( za, 8, &( lipCtx->mD ) );

	zfree( &za );
	zfree( &zp );
	zfree( &zq );

	return 0;
}

void VNRabin_LIP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	zzero( &( lipCtx->mN ) );
	zzero( &( lipCtx->mD ) );
}

int VNRabin_LIP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	VN_LIP_dump_hex( lipCtx->mN, hexPubKey );

	return 0;
}

int VNRabin_LIP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	VN_LIP_dump_hex( lipCtx->mN, hexPubKey );
	VN_LIP_dump_hex( lipCtx->mD, hexPrivKey );

	return 0;
}

int VNRabin_LIP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	VN_LIP_load_hex( hexPubKey, &( lipCtx->mN ) );

	return 0;
}

int VNRabin_LIP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	VN_LIP_load_hex( hexPubKey, &( lipCtx->mN ) );
	VN_LIP_load_hex( hexPrivKey, &( lipCtx->mD ) );

	return 0;
}

int VNRabin_LIP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0, jacobi = 0;
	verylong zm = 0, zs = 0;

	const VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	zzero( &zm );

	VN_LIP_load_bin( plainText, length, &zm );

	if( zcompare( zm, lipCtx->mN ) >= 0 )
	{
		zfree( &zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	zzero( &zs );

	zsmul( zm, 16, &zm );
	zsadd( zm, 6, &zm );

	jacobi = zjacobi( zm, lipCtx->mN );

	if( 1 == jacobi )
	{
		zexpmod( zm, lipCtx->mD, lipCtx->mN, &zs );
	} else if( -1 == jacobi ) {
		zrshift( zm, 1, &zm );
		zexpmod( zm, lipCtx->mD, lipCtx->mN, &zs );
	} else {
		ret = -1;
	}

	VN_LIP_dump_bin( zs, cipherText );

	zfree( &zm );
	zfree( &zs );

	return ret;
}

int VNRabin_LIP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0, mod = 0;
	verylong zm = 0, zm1 = 0, zs = 0;

	const VNRabin_LIP_Ctx_t * lipCtx = VN_CONTAINER_OF( ctx, VNRabin_LIP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_LIP == ctx->mType );

	zzero( &zm );
	zzero( &zm1 );
	zzero( &zs );

	VN_LIP_load_bin( cipherText, length, &zs );

	zmulmod( zs, zs, lipCtx->mN, &zm1 );

	mod = zsmod(zm1, 8l);

	if( mod == 6 )
	{
		zcopy( zm1, &zm );
	} else if( mod == 3 ) {
		zlshift( zm1, 1, &zm );
	} else if( mod == 7 ) {
		zsub( lipCtx->mN, zm1, &zm );
	} else if( mod == 2 ) {
		zsub( lipCtx->mN, zm1, &zm );
		zlshift( zm, 1, &zm );
	}

	if( zsmod( zm, 16 ) == 6 ) {
		ret = 0;

		zsadd( zm, -6, &zm );
		zsdiv( zm, 16, &zm );

		VN_LIP_dump_bin( zm, plainText );
	} else {
		ret = -1;
	}

	zfree( &zm );
	zfree( &zm1 );
	zfree( &zs );

	return ret;
}

