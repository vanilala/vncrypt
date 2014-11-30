
#include "vncrypt_botan.h"
#include "vnrw_botan.h"

#include <botan/rw.h>
#include <botan/botan.h>
#include <botan/numthry.h>

#include <assert.h>
#include <stdio.h>
#include <iostream>

using namespace Botan;
using namespace std;

typedef struct tagVNRW_Botan_Ctx {
	VNAsymCryptCtx_t mCtx;

	AutoSeeded_RNG mRng;

	RW_PrivateKey * mPrivKey;
	RW_PublicKey * mPubKey;

	unsigned long mE;

} VNRW_Botan_Ctx_t;

VNAsymCryptCtx_t * VNRWSign_Botan_CtxNew( unsigned long e )
{
	VNRW_Botan_Ctx_t * botanCtx = new VNRW_Botan_Ctx_t();

	botanCtx->mCtx.mType = VN_TYPE_VNRWSign_Botan;

	botanCtx->mCtx.mMethod.mCtxFree = VNRW_Botan_CtxFree;
	botanCtx->mCtx.mMethod.mGenKeys = VNRW_Botan_GenKeys;
	botanCtx->mCtx.mMethod.mClearKeys = VNRW_Botan_ClearKeys;
	botanCtx->mCtx.mMethod.mDumpPubKey = VNRW_Botan_DumpPubKey;
	botanCtx->mCtx.mMethod.mDumpPrivKey = VNRW_Botan_DumpPrivKey;
	botanCtx->mCtx.mMethod.mLoadPubKey = VNRW_Botan_LoadPubKey;
	botanCtx->mCtx.mMethod.mLoadPrivKey = VNRW_Botan_LoadPrivKey;
	botanCtx->mCtx.mMethod.mPrivEncrypt = VNRW_Botan_PrivEncrypt;
	botanCtx->mCtx.mMethod.mPubDecrypt = VNRW_Botan_PubDecrypt;

	botanCtx->mPrivKey = NULL;
	botanCtx->mPubKey = NULL;

	botanCtx->mE = e;

	return &( botanCtx->mCtx );
}

void VNRW_Botan_CtxFree( VNAsymCryptCtx_t * ctx )
{
	const VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	VNRW_Botan_ClearKeys( ctx );

	delete botanCtx;
}

int VNRW_Botan_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	botanCtx->mPrivKey = new RW_PrivateKey( botanCtx->mRng, keyBits, botanCtx->mE );
	botanCtx->mPubKey = new RW_PublicKey( botanCtx->mPrivKey->get_n(), botanCtx->mPrivKey->get_e() );

	return 0;
}

void VNRW_Botan_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	if( NULL != botanCtx->mPrivKey ) delete botanCtx->mPrivKey, botanCtx->mPrivKey = NULL;
	if( NULL != botanCtx->mPubKey ) delete botanCtx->mPubKey, botanCtx->mPubKey = NULL;
}

int VNRW_Botan_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	if( NULL == botanCtx->mPubKey ) return 0;

	VN_Botan_dump_hex( (void*)&( botanCtx->mPubKey->get_n() ), hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPubKey = hexPubKey->next;
	VN_Botan_dump_hex( (void*)&( botanCtx->mPubKey->get_e() ), hexPubKey );

	return 0;
}

int VNRW_Botan_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	VNRW_Botan_DumpPubKey( ctx, hexPubKey );

	if( NULL == botanCtx->mPrivKey ) return 0;

	VN_Botan_dump_hex( (void*)&( botanCtx->mPrivKey->get_p() ), hexPrivKey );

	hexPrivKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPrivKey = hexPrivKey->next;
	VN_Botan_dump_hex( (void*)&( botanCtx->mPrivKey->get_q() ), hexPrivKey );

	return 0;
}

int VNRW_Botan_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	BigInt n, e;

	VN_Botan_load_hex( hexPubKey, &n );
	if( NULL != hexPubKey->next )
	{
		VN_Botan_load_hex( hexPubKey->next, &e );
	} else {
		e = 2;
	}

	botanCtx->mPubKey = new RW_PublicKey( n, e );

	return 0;
}

int VNRW_Botan_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	BigInt n, e, p, q, d;

	VN_Botan_load_hex( hexPubKey, &n );
	if( NULL != hexPubKey->next )
	{
		VN_Botan_load_hex( hexPubKey->next, &e );
	} else {
		e = 2;
	}

	VN_Botan_load_hex( hexPrivKey, &p );
	VN_Botan_load_hex( hexPrivKey->next, &q );

	d = inverse_mod( e, lcm(p - 1, q - 1) >> 1 );

	//VN_Botan_load_hex( hexPrivKey->next->next, &d );

	botanCtx->mPubKey = new RW_PublicKey( n, e );
	botanCtx->mPrivKey = new RW_PrivateKey( botanCtx->mRng, p, q, e, d, n );

	return 0;
}

int VNRW_Botan_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	BigInt m( (const byte*)plainText, length );

	m = m * 16 + 12;

	if( m >= botanCtx->mPrivKey->get_n() )
	{
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	SecureVector<byte> tmp = BigInt::encode( m );

	SecureVector<byte> sig = botanCtx->mPrivKey->sign( tmp.begin(), tmp.size(), botanCtx->mRng );

	cipherText->i.iov_len = sig.size();
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );
	memcpy( cipherText->i.iov_base, sig.begin(), sig.size() );

	return 0;
}

int VNRW_Botan_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	VNRW_Botan_Ctx_t * botanCtx = VN_CONTAINER_OF( ctx, VNRW_Botan_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_Botan == ctx->mType );

	SecureVector<byte> tmp = botanCtx->mPubKey->verify( cipherText, length );

	BigInt m( (const byte*)tmp.begin(), tmp.size() );

	m = ( m - 12 ) / 16;

	VN_Botan_dump_bin( &m, plainText );

	return 0;
}

