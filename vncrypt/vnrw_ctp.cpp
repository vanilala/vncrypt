
#include "vnrw_ctp.h"
#include "vncrypt_ctp.h"

#include <crypto++/osrng.h>
#include <crypto++/rw.h>
#include <crypto++/hex.h>
#include <crypto++/pssr.h>

#include <stdio.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

typedef struct tagVNRW_CTP_Ctx {
	VNAsymCryptCtx_t mCtx;

	AutoSeededRandomPool mRng;

	RW::PublicKey * mPubKey;
	RW::PrivateKey * mPrivKey;

} VNRW_CTP_Ctx_t;

VNAsymCryptCtx_t * VNRWSign_CTP_CtxNew()
{
	VNRW_CTP_Ctx_t * ctpCtx = new VNRW_CTP_Ctx_t();

	ctpCtx->mCtx.mType = VN_TYPE_VNRWSign_CTP;

	ctpCtx->mCtx.mMethod.mCtxFree = VNRW_CTP_CtxFree;
	ctpCtx->mCtx.mMethod.mGenKeys = VNRW_CTP_GenKeys;
	ctpCtx->mCtx.mMethod.mClearKeys = VNRW_CTP_ClearKeys;
	ctpCtx->mCtx.mMethod.mDumpPubKey = VNRW_CTP_DumpPubKey;
	ctpCtx->mCtx.mMethod.mDumpPrivKey = VNRW_CTP_DumpPrivKey;
	ctpCtx->mCtx.mMethod.mLoadPubKey = VNRW_CTP_LoadPubKey;
	ctpCtx->mCtx.mMethod.mLoadPrivKey = VNRW_CTP_LoadPrivKey;
	ctpCtx->mCtx.mMethod.mPrivEncrypt = VNRW_CTP_PrivEncrypt;
	ctpCtx->mCtx.mMethod.mPubDecrypt = VNRW_CTP_PubDecrypt;

	ctpCtx->mPrivKey = NULL;
	ctpCtx->mPubKey = NULL;

	return &( ctpCtx->mCtx );
}

void VNRW_CTP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	const VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	VNRW_CTP_ClearKeys( ctx );

	delete ctpCtx;
}

int VNRW_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	ctpCtx->mPrivKey = new RW::PrivateKey();
	ctpCtx->mPubKey = new RW::PublicKey();

	ctpCtx->mPrivKey->Initialize( ctpCtx->mRng, keyBits );
	ctpCtx->mPubKey->Initialize( ctpCtx->mPrivKey->GetModulus() );

	return 0;
}

void VNRW_CTP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	if( NULL != ctpCtx->mPrivKey ) delete ctpCtx->mPrivKey, ctpCtx->mPrivKey = NULL;
	if( NULL != ctpCtx->mPubKey ) delete ctpCtx->mPubKey, ctpCtx->mPubKey = NULL;
}

int VNRW_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	if( NULL == ctpCtx->mPubKey ) return 0;

	VN_CTP_dump_hex( (void*)&( ctpCtx->mPubKey->GetModulus() ), hexPubKey );

	return 0;
}

int VNRW_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	VNRW_CTP_DumpPubKey( ctx, hexPubKey );

	if( NULL == ctpCtx->mPrivKey ) return 0;

	VN_CTP_dump_hex( (void*)&( ctpCtx->mPrivKey->GetPrime1() ), hexPrivKey );

	hexPrivKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPrivKey = hexPrivKey->next;
	VN_CTP_dump_hex( (void*)&( ctpCtx->mPrivKey->GetPrime2() ), hexPrivKey );

	return 0;
}

int VNRW_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	Integer n;
	VN_CTP_load_hex( hexPubKey, &n );

	ctpCtx->mPubKey = new RW::PublicKey();
	ctpCtx->mPubKey->Initialize( n );

	return 0;
}

int VNRW_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	Integer n, p, q, u;

	VN_CTP_load_hex( hexPubKey, &n );

	VN_CTP_load_hex( hexPrivKey, &p );
	VN_CTP_load_hex( hexPrivKey->next, &q );

	u = q.InverseMod( p );

	ctpCtx->mPrivKey = new RW::PrivateKey();
	ctpCtx->mPrivKey->Initialize( n, p, q, u );

	VNRW_CTP_LoadPubKey( ctx, hexPubKey );

	return 0;
}

int VNRW_CTP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	Integer m( (const byte*)plainText, length );

	m = m * 16 + 12;

	if( m >= ctpCtx->mPrivKey->GetModulus() )
	{
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	Integer c = ctpCtx->mPrivKey->CalculateInverse( ctpCtx->mRng, m );

	cipherText->i.iov_len = c.MinEncodedSize();
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );
	c.Encode( (byte *)cipherText->i.iov_base, cipherText->i.iov_len );

	return 0;
}

int VNRW_CTP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	VNRW_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRW_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRWSign_CTP == ctx->mType );

	Integer c( (const byte*)cipherText, length );

	Integer m = ctpCtx->mPubKey->ApplyFunction( c );

	m = ( m - 12 ) / 16;

	plainText->i.iov_len = m.MinEncodedSize();
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );
	m.Encode( (byte *)plainText->i.iov_base, plainText->i.iov_len );

	return 0;
}

