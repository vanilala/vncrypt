
#include "vnrsa_ctp.h"
#include "vncrypt_ctp.h"

#include <crypto++/osrng.h>
#include <crypto++/rsa.h>
#include <crypto++/hex.h>

#include <stdio.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

typedef struct tagVNRsa_CTP_Ctx {
	VNAsymCryptCtx_t mCtx;

	AutoSeededRandomPool mRng;

	RSA::PublicKey * mPubKey;
	RSA::PrivateKey * mPrivKey;

	unsigned long mE;
} VNRsa_CTP_Ctx_t;

VNAsymCryptCtx_t * VNRsa_CTP_CtxNewImpl( unsigned long e )
{
	VNRsa_CTP_Ctx_t * ctpCtx = new VNRsa_CTP_Ctx_t();

	ctpCtx->mCtx.mType = VN_TYPE_VNRsaSign_CTP;

	ctpCtx->mCtx.mMethod.mCtxFree = VNRsa_CTP_CtxFree;
	ctpCtx->mCtx.mMethod.mGenKeys = VNRsa_CTP_GenKeys;
	ctpCtx->mCtx.mMethod.mClearKeys = VNRsa_CTP_ClearKeys;
	ctpCtx->mCtx.mMethod.mDumpPubKey = VNRsa_CTP_DumpPubKey;
	ctpCtx->mCtx.mMethod.mDumpPrivKey = VNRsa_CTP_DumpPrivKey;
	ctpCtx->mCtx.mMethod.mLoadPubKey = VNRsa_CTP_LoadPubKey;
	ctpCtx->mCtx.mMethod.mLoadPrivKey = VNRsa_CTP_LoadPrivKey;
	ctpCtx->mCtx.mMethod.mPubEncrypt = VNRsa_CTP_PubProcess;
	ctpCtx->mCtx.mMethod.mPrivDecrypt = VNRsa_CTP_PrivProcess;
	ctpCtx->mCtx.mMethod.mPubDecrypt = VNRsa_CTP_PubProcess;
	ctpCtx->mCtx.mMethod.mPrivEncrypt = VNRsa_CTP_PrivProcess;

	ctpCtx->mPrivKey = NULL;
	ctpCtx->mPubKey = NULL;

	ctpCtx->mE = e;

	return &( ctpCtx->mCtx );
}

VNAsymCryptCtx_t * VNRsaSign_CTP_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_CTP_CtxNewImpl( e );

	ctx->mType = VN_TYPE_VNRsaSign_CTP;

	return ctx;
}

VNAsymCryptCtx_t * VNRsaEnc_CTP_CtxNew( unsigned long e )
{
	VNAsymCryptCtx_t * ctx = VNRsa_CTP_CtxNewImpl( e );

	ctx->mType = VN_TYPE_VNRsaEnc_CTP;

	return ctx;
}

void VNRsa_CTP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	const VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	VNRsa_CTP_ClearKeys( ctx );

	delete ctpCtx;
}

int VNRsa_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	ctpCtx->mPrivKey = new RSA::PrivateKey();
	ctpCtx->mPubKey = new RSA::PublicKey();

	ctpCtx->mPrivKey->Initialize( ctpCtx->mRng, keyBits, ctpCtx->mE );
	ctpCtx->mPubKey->Initialize( ctpCtx->mPrivKey->GetModulus(), ctpCtx->mE );

	return 0;
}

void VNRsa_CTP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	if( NULL != ctpCtx->mPrivKey ) delete ctpCtx->mPrivKey, ctpCtx->mPrivKey = NULL;
	if( NULL != ctpCtx->mPubKey ) delete ctpCtx->mPubKey, ctpCtx->mPubKey = NULL;
}

int VNRsa_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	if( NULL == ctpCtx->mPubKey ) return 0;

	VN_CTP_dump_hex( (void*)&( ctpCtx->mPubKey->GetModulus() ), hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPubKey = hexPubKey->next;
	VN_CTP_dump_hex( (void*)&( ctpCtx->mPubKey->GetPublicExponent() ), hexPubKey );

	return 0;
}

int VNRsa_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	VNRsa_CTP_DumpPubKey( ctx, hexPubKey );

	if( NULL == ctpCtx->mPrivKey ) return 0;

	VN_CTP_dump_hex( (void*)&( ctpCtx->mPrivKey->GetPrivateExponent() ), hexPrivKey );

	return 0;
}

int VNRsa_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	Integer n, e;
	VN_CTP_load_hex( hexPubKey, &n );
	VN_CTP_load_hex( hexPubKey->next, &e );

	ctpCtx->mPubKey = new RSA::PublicKey();
	ctpCtx->mPubKey->Initialize( n, e );

	return 0;
}

int VNRsa_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	VNRsa_CTP_LoadPubKey( ctx, hexPubKey );

	Integer d;

	VN_CTP_load_hex( hexPrivKey, &d );

	ctpCtx->mPrivKey = new RSA::PrivateKey();
	ctpCtx->mPrivKey->Initialize( ctpCtx->mPubKey->GetModulus(),
		ctpCtx->mPubKey->GetPublicExponent(), d );

	return 0;
}

int VNRsa_CTP_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	Integer m( (const byte*)plainText, length );

	Integer c = ctpCtx->mPubKey->ApplyFunction( m );
	
	cipherText->i.iov_len = c.MinEncodedSize();
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );

	c.Encode( (byte*)cipherText->i.iov_base, cipherText->i.iov_len );

	return 0;
}

int VNRsa_CTP_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	VNRsa_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRsa_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRsaSign_CTP == ctx->mType || VN_TYPE_VNRsaEnc_CTP == ctx->mType );

	Integer c( (const byte*)cipherText, length );

	Integer m = ctpCtx->mPrivKey->CalculateInverse( ctpCtx->mRng, c );

	plainText->i.iov_len = m.MinEncodedSize();
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );

	m.Encode( (byte*)plainText->i.iov_base, plainText->i.iov_len );

	return 0;
}

