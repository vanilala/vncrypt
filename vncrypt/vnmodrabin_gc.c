
#include "vnmodrabin_gc.h"
#include "vncrypt_gc.h"

#include <gcrypt.h>
#include <gpg-error.h>

#include <assert.h>
#include <unistd.h>
#include <stdio.h>

typedef struct tagVNModRabin_GC_Ctx {
	VNAsymCryptCtx_t mCtx;

	gcry_mpi_t mN;
	gcry_mpi_t mD;
} VNModRabin_GC_Ctx_t;

VNAsymCryptCtx_t * VNModRabin_GC_CtxNewImpl()
{
	VNModRabin_GC_Ctx_t * gcCtx = NULL;

	if( ! gcry_control( GCRYCTL_INITIALIZATION_FINISHED_P ) )
	{
		printf( "libgcrypt has not been initialized\n" );
		return NULL;
	}

	gcCtx = (VNModRabin_GC_Ctx_t *)calloc( sizeof( VNModRabin_GC_Ctx_t ), 1 );

	gcCtx->mCtx.mMethod.mCtxFree = VNModRabin_GC_CtxFree;
	gcCtx->mCtx.mMethod.mGenKeys = VNModRabin_GC_GenKeys;
	gcCtx->mCtx.mMethod.mClearKeys = VNModRabin_GC_ClearKeys;
	gcCtx->mCtx.mMethod.mDumpPubKey = VNModRabin_GC_DumpPubKey;
	gcCtx->mCtx.mMethod.mDumpPrivKey = VNModRabin_GC_DumpPrivKey;
	gcCtx->mCtx.mMethod.mLoadPubKey = VNModRabin_GC_LoadPubKey;
	gcCtx->mCtx.mMethod.mLoadPrivKey = VNModRabin_GC_LoadPrivKey;
	gcCtx->mCtx.mMethod.mPrivEncrypt = VNModRabin_GC_PrivEncrypt;
	gcCtx->mCtx.mMethod.mPubDecrypt = VNModRabin_GC_PubDecrypt;

	gcCtx->mN = gcry_mpi_new(128);
	gcCtx->mD = gcry_mpi_new(128);

	return &( gcCtx->mCtx );
}

VNAsymCryptCtx_t * VNModRabinSign_GC_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNModRabin_GC_CtxNewImpl();

	ctx->mType = VN_TYPE_VNModRabinSign_GC;

	return ctx;
}

void VNModRabin_GC_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	gcry_mpi_release( gcCtx->mN );
	gcry_mpi_release( gcCtx->mD );

	free( gcCtx );
}

int VNModRabin_GC_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	gcry_mpi_t za, zb, zp, zq;

	za = gcry_mpi_new( keyBits * 2 );
	zb = gcry_mpi_new( keyBits * 2 );
	zp = gcry_mpi_new( keyBits * 2 );
	zq = gcry_mpi_new( keyBits * 2 );

	VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	/* choose a prime p such that p mod 8 == 3 */
	do {
		gcry_mpi_release( zp );
		gcry_prime_generate( &zp, keyBits, 0, NULL, NULL, NULL, GCRY_STRONG_RANDOM, 0 );
	} while ( VN_gcry_mpi_mod_ui( zp, 8 ) != 3 || gcry_mpi_get_nbits( zp ) != keyBits );

	/* choose a prime q such that q mod 8 == 7 */
	do {
		gcry_mpi_release( zq );
		gcry_prime_generate ( &zq, keyBits, 0, NULL, NULL, NULL, GCRY_STRONG_RANDOM, 0 );
	} while ( VN_gcry_mpi_mod_ui( zq, 8 ) != 7 || gcry_mpi_get_nbits( zq ) != keyBits );

	/* compute public key n*/
	gcry_mpi_mul( gcCtx->mN, zp, zq );

	/* compute private key d = (n - p - q + 5) / 8 */
	gcry_mpi_add( za, zp, zq );
	gcry_mpi_sub( zb, gcCtx->mN, za );
	gcry_mpi_add_ui( za, zb, 5 );
	gcry_mpi_rshift( gcCtx->mD, za, 3 );

	gcry_mpi_release( za );
	gcry_mpi_release( zb );
	gcry_mpi_release( zp );
	gcry_mpi_release( zq );

	return 0;
}

void VNModRabin_GC_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	gcry_mpi_set_ui( gcCtx->mN, 0 );
	gcry_mpi_set_ui( gcCtx->mD, 0 );
}

int VNModRabin_GC_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	VN_GC_dump_hex( gcCtx->mN, hexPubKey );

	return 0;
}

int VNModRabin_GC_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	VN_GC_dump_hex( gcCtx->mN, hexPubKey );

	VN_GC_dump_hex( gcCtx->mD, hexPrivKey );

	return 0;
}

int VNModRabin_GC_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	gcry_mpi_release( gcCtx->mN );

	gcry_mpi_scan( &( gcCtx->mN ), GCRYMPI_FMT_HEX,
		(unsigned char*)hexPubKey->i.iov_base, 0, NULL );

	return 0;
}

int VNModRabin_GC_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	gcry_mpi_release( gcCtx->mN );

	gcry_mpi_scan( &( gcCtx->mN ), GCRYMPI_FMT_HEX,
		(unsigned char*)hexPubKey->i.iov_base, 0, NULL );

	gcry_mpi_release( gcCtx->mD );

	gcry_mpi_scan( &( gcCtx->mD ), GCRYMPI_FMT_HEX,
		(unsigned char*)hexPrivKey->i.iov_base, 0, NULL );

	return 0;
}

int VNModRabin_GC_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0, jacobi = 0;
	gcry_mpi_t zm, zs;

	const VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	gcry_mpi_scan( &zm, GCRYMPI_FMT_USG, plainText, length, NULL );

	if( gcry_mpi_cmp( zm, gcCtx->mN ) >= 0 )
	{
		gcry_mpi_release( zm );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	zs = gcry_mpi_new( length * 8 + 8 );

	gcry_mpi_mul_ui( zm, zm, 16 );
	gcry_mpi_add_ui( zm, zm, 6 );

	ret = VN_gcry_mpi_jacobi( zm, gcCtx->mN, &jacobi );

	if( jacobi == 1 )
	{
		gcry_mpi_powm( zs, zm, gcCtx->mD, gcCtx->mN );
	} else if( jacobi == -1 ) {
		gcry_mpi_rshift( zm, zm, 1 );
		gcry_mpi_powm( zs, zm, gcCtx->mD, gcCtx->mN );
	}

	VN_GC_dump_bin( zs, cipherText );

	gcry_mpi_release( zm );
	gcry_mpi_release( zs );

	return ret;
}

int VNModRabin_GC_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0, mod = 0;
	gcry_mpi_t zm, zm1, zs;

	const VNModRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNModRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_GC == ctx->mType );

	zm = gcry_mpi_new( length * 8 );
	zm1 = gcry_mpi_new( length * 8 );

	gcry_mpi_scan( &zs, GCRYMPI_FMT_USG, cipherText, length, NULL );

	gcry_mpi_mulm( zm1, zs, zs, gcCtx->mN );
	mod = VN_gcry_mpi_mod_ui( zm1, 8 );

	if( mod == 6 )
	{
		gcry_mpi_swap( zm, zm1 );
	} else if( mod == 3 ) {
		gcry_mpi_mul_ui( zm, zm1, 2 );
	} else if( mod == 7 ) {
		gcry_mpi_sub( zm, gcCtx->mN, zm1 );
	} else if( mod == 2 ) {
		gcry_mpi_sub( zm, gcCtx->mN, zm1 );
		gcry_mpi_mul_ui( zm, zm, 2 );
	}

	if( VN_gcry_mpi_mod_ui( zm, 16 ) == 6 ) {
		ret = 0;

		gcry_mpi_sub_ui( zm, zm, 6 );
		gcry_mpi_rshift( zm, zm, 4 );

		VN_GC_dump_bin( zm, plainText );
	} else {
		ret = -1;
	}

	gcry_mpi_release( zm );
	gcry_mpi_release( zm1 );
	gcry_mpi_release( zs );

	return ret;
}

