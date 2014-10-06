
#include "vnrabin_gc.h"

#include <gcrypt.h>
#include <gpg-error.h>

#include <assert.h>
#include <unistd.h>
#include <stdio.h>

extern void gcry_mpi_get_ui( gcry_mpi_t , unsigned long * );

int VN_gcry_mpi_jacobi( const gcry_mpi_t za, const gcry_mpi_t zn, int *jacobi );

inline unsigned long VN_gcry_mpi_mod_ui( const gcry_mpi_t za, unsigned long m )
{
	unsigned long ret = 0;

	if( m == 4 )
	{
		if( gcry_mpi_test_bit( za, 0 ) ) ret |= 0x1;
		if( gcry_mpi_test_bit( za, 1 ) ) ret |= 0x2;
	} else if( m == 8 ) {
		if( gcry_mpi_test_bit( za, 0 ) ) ret |= 0x1;
		if( gcry_mpi_test_bit( za, 1 ) ) ret |= 0x2;
		if( gcry_mpi_test_bit( za, 2 ) ) ret |= 0x4;
	} else if( m == 16 ) {
		if( gcry_mpi_test_bit( za, 0 ) ) ret |= 0x1;
		if( gcry_mpi_test_bit( za, 1 ) ) ret |= 0x2;
		if( gcry_mpi_test_bit( za, 2 ) ) ret |= 0x4;
		if( gcry_mpi_test_bit( za, 3 ) ) ret |= 0x8;
	} else {
		gcry_mpi_t r = gcry_mpi_new( 128 );
		gcry_mpi_t d = gcry_mpi_set_ui( NULL, m );

		gcry_mpi_mod( r, za, d );

		//memcpy( &ret, gcry_mpi_get_opaque( r, NULL ), sizeof( ret ) );
		//gcry_mpi_get_ui( r, &ret );
		gcry_mpi_print( GCRYMPI_FMT_USG, (unsigned char*)&ret, sizeof( ret ), NULL, r );

		gcry_mpi_release( r );
		gcry_mpi_release( d );
	}

	return ret;
}

typedef struct tagVNRabin_GC_Ctx {
	VNAsymCryptCtx_t mCtx;

	gcry_mpi_t mN;
	gcry_mpi_t mD;
} VNRabin_GC_Ctx_t;

VNAsymCryptCtx_t * VNRabin_GC_CtxNew()
{
	VNRabin_GC_Ctx_t * gcCtx = NULL;

	if( ! gcry_control( GCRYCTL_INITIALIZATION_FINISHED_P ) )
	{
		printf( "libgcrypt has not been initialized\n" );
		return NULL;
	}

	gcCtx = (VNRabin_GC_Ctx_t *)calloc( sizeof( VNRabin_GC_Ctx_t ), 1 );

	gcCtx->mCtx.mType = VN_TYPE_VNRabinSign_GC;

	gcCtx->mCtx.mMethod.mCtxFree = VNRabin_GC_CtxFree;
	gcCtx->mCtx.mMethod.mGenKeys = VNRabin_GC_GenKeys;
	gcCtx->mCtx.mMethod.mClearKeys = VNRabin_GC_ClearKeys;
	gcCtx->mCtx.mMethod.mDumpPubKey = VNRabin_GC_DumpPubKey;
	gcCtx->mCtx.mMethod.mDumpPrivKey = VNRabin_GC_DumpPrivKey;
	gcCtx->mCtx.mMethod.mLoadPubKey = VNRabin_GC_LoadPubKey;
	gcCtx->mCtx.mMethod.mLoadPrivKey = VNRabin_GC_LoadPrivKey;
	gcCtx->mCtx.mMethod.mPrivEncrypt = VNRabin_GC_PrivEncrypt;
	gcCtx->mCtx.mMethod.mPubDecrypt = VNRabin_GC_PubDecrypt;

	gcCtx->mN = gcry_mpi_new(128);
	gcCtx->mD = gcry_mpi_new(128);

	return &( gcCtx->mCtx );
}

void VNRabin_GC_CtxFree( VNAsymCryptCtx_t * ctx )
{
	VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

	gcry_mpi_release( gcCtx->mN );
	gcry_mpi_release( gcCtx->mD );

	free( gcCtx );
}

int VNRabin_GC_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	gcry_mpi_t za, zb, zp, zq;

	za = gcry_mpi_new( keyBits * 2 );
	zb = gcry_mpi_new( keyBits * 2 );
	zp = gcry_mpi_new( keyBits * 2 );
	zq = gcry_mpi_new( keyBits * 2 );

	VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

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

void VNRabin_GC_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

	gcry_mpi_release( gcCtx->mN );
	gcry_mpi_release( gcCtx->mD );

	gcCtx->mN = gcry_mpi_new(128);
	gcCtx->mD = gcry_mpi_new(128);
}

int VNRabin_GC_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

	hexPubKey->i.iov_len = ( gcry_mpi_get_nbits( gcCtx->mN ) + 7 ) / 8 * 4;
	hexPubKey->i.iov_base = calloc( 1, hexPubKey->i.iov_len + 1 );

	gcry_mpi_print( GCRYMPI_FMT_HEX, (unsigned char*)hexPubKey->i.iov_base,
		hexPubKey->i.iov_len, &( hexPubKey->i.iov_len ), gcCtx->mN );

	if( hexPubKey->i.iov_len > 0 ) hexPubKey->i.iov_len--;

	return 0;
}

int VNRabin_GC_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

	hexPubKey->i.iov_len = ( gcry_mpi_get_nbits( gcCtx->mN ) + 7 ) / 8 * 4;
	hexPubKey->i.iov_base = calloc( 1, hexPubKey->i.iov_len + 1 );

	gcry_mpi_print( GCRYMPI_FMT_HEX, (unsigned char*)hexPubKey->i.iov_base,
		hexPubKey->i.iov_len, &( hexPubKey->i.iov_len ), gcCtx->mN );
	if( hexPubKey->i.iov_len > 0 ) hexPubKey->i.iov_len--;

	hexPrivKey->i.iov_len = ( gcry_mpi_get_nbits( gcCtx->mD ) + 7 ) / 8 * 4;
	hexPrivKey->i.iov_base = calloc( 1, hexPrivKey->i.iov_len + 1 );

	gcry_mpi_print( GCRYMPI_FMT_HEX, (unsigned char*)hexPrivKey->i.iov_base,
		hexPrivKey->i.iov_len, &( hexPrivKey->i.iov_len ), gcCtx->mD );
	if( hexPrivKey->i.iov_len > 0 ) hexPrivKey->i.iov_len--;

	return 0;
}

int VNRabin_GC_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

	gcry_mpi_release( gcCtx->mN );

	gcry_mpi_scan( &( gcCtx->mN ), GCRYMPI_FMT_HEX,
		(unsigned char*)hexPubKey->i.iov_base, 0, NULL );

	return 0;
}

int VNRabin_GC_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

	gcry_mpi_release( gcCtx->mN );

	gcry_mpi_scan( &( gcCtx->mN ), GCRYMPI_FMT_HEX,
		(unsigned char*)hexPubKey->i.iov_base, 0, NULL );

	gcry_mpi_release( gcCtx->mD );

	gcry_mpi_scan( &( gcCtx->mD ), GCRYMPI_FMT_HEX,
		(unsigned char*)hexPrivKey->i.iov_base, 0, NULL );

	return 0;
}

int VNRabin_GC_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	int ret = 0, jacobi = 0;
	gcry_mpi_t zm, zs;

	const VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

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

	cipherText->i.iov_len = gcry_mpi_get_nbits( zs ) / 8 * 2;
	cipherText->i.iov_base = malloc( cipherText->i.iov_len );
	gcry_mpi_print( GCRYMPI_FMT_USG, (unsigned char*)cipherText->i.iov_base,
		cipherText->i.iov_len, &( cipherText->i.iov_len ), zs );

	gcry_mpi_release( zm );
	gcry_mpi_release( zs );

	return ret;
}

int VNRabin_GC_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	int ret = 0, mod = 0;
	gcry_mpi_t zm, zm1, zs;

	const VNRabin_GC_Ctx_t * gcCtx = VN_CONTAINER_OF( ctx, VNRabin_GC_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_GC == ctx->mType );

	zm = gcry_mpi_new( length * 8 );
	zm1 = gcry_mpi_new( length * 8 );

	gcry_mpi_scan( &zs, GCRYMPI_FMT_USG, cipherText, length, NULL );

	gcry_mpi_mulm( zm1, zs, zs, gcCtx->mN );
	mod = VN_gcry_mpi_mod_ui( zm1, 8 );

	if( mod == 6 )
	{
		gcry_mpi_swap( zm, zm1 );
	} else if( mod == 3 ) {
		gcry_mpi_lshift( zm, zm1, 1 );
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

		plainText->i.iov_len = gcry_mpi_get_nbits( zm ) / 8 * 2;
		plainText->i.iov_base = malloc( plainText->i.iov_len );

		gcry_mpi_print( GCRYMPI_FMT_USG, (unsigned char*)plainText->i.iov_base,
			plainText->i.iov_len, &( plainText->i.iov_len ), zm );
	} else {
		ret = -1;
	}

	gcry_mpi_release( zm );
	gcry_mpi_release( zm1 );
	gcry_mpi_release( zs );

	return ret;
}

int VN_gcry_mpi_jacobi( const gcry_mpi_t za, const gcry_mpi_t zn, int *jacobi )
{
	int ret = 0, e = 0, s = 0, mod = -1, amod = -1;

	gcry_mpi_t za1, zn1;

	za1 = gcry_mpi_copy( za );
	zn1 = gcry_mpi_copy( zn );

	for( *jacobi = 1; 0 == ret; )
	{
		if( ! gcry_mpi_test_bit( zn1, 0 ) ) { ret = -1; break; }
		if( gcry_mpi_cmp_ui( zn1, 3 ) < 0 ) { ret = -1; break; }
		if( ( gcry_mpi_cmp( za1, zn1 ) > 0 )
			|| ( gcry_mpi_cmp_ui( za1, 0 ) < 0 ) ) { ret = -1; break; }

		if( gcry_mpi_cmp_ui( za1, 0 ) == 0 ) break;      // step1
		if( gcry_mpi_cmp_ui( za1, 1 ) == 0 ) break;      // step2

		for( e = 0; ; e++ )                              // step3
		{
			if( gcry_mpi_test_bit( za1, 0 ) ) break;
			gcry_mpi_rshift( za1, za1, 1 );
		}

		if( 0 == ( e % 2 ) )                             // step4
		{
			s = 1;
		} else {
			mod = VN_gcry_mpi_mod_ui( zn1, 8 );

			if( 1 == mod || 7 == mod ) s = 1;
			if( 3 == mod || 5 == mod ) s = -1;
		}

		amod = VN_gcry_mpi_mod_ui( za1, 4 );             // step5
		mod = VN_gcry_mpi_mod_ui( zn1, 4 );
		if( 3 == mod && 3 == amod ) s = - s;

		gcry_mpi_mod( zn1, zn1, za1 );                   // step6

		*jacobi = ( *jacobi ) * s;                       // step7

		if( gcry_mpi_cmp_ui( za1, 1 ) == 0 ) break;
		gcry_mpi_swap( za1, zn1 );
	}

	gcry_mpi_release( za1 );
	gcry_mpi_release( zn1 );

	return ret;
}

