
#include "vnrabin_ctp.h"
#include "vncrypt_ctp.h"

#include <crypto++/osrng.h>
#include <crypto++/rabin.h>

#include <stdio.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

typedef struct tagVNRabin_CTP_Ctx {
	VNAsymCryptCtx_t mCtx;

	AutoSeededRandomPool mRng;

	Rabin::PublicKey * mPubKey;
	Rabin::PrivateKey * mPrivKey;

} VNRabin_CTP_Ctx_t;

VNAsymCryptCtx_t * VNRabin_CTP_CtxNewImpl()
{
	VNRabin_CTP_Ctx_t * ctpCtx = new VNRabin_CTP_Ctx_t();

	ctpCtx->mCtx.mType = VN_TYPE_VNRabinSign_CTP;

	ctpCtx->mCtx.mMethod.mCtxFree = VNRabin_CTP_CtxFree;
	ctpCtx->mCtx.mMethod.mGenKeys = VNRabin_CTP_GenKeys;
	ctpCtx->mCtx.mMethod.mClearKeys = VNRabin_CTP_ClearKeys;
	ctpCtx->mCtx.mMethod.mDumpPubKey = VNRabin_CTP_DumpPubKey;
	ctpCtx->mCtx.mMethod.mDumpPrivKey = VNRabin_CTP_DumpPrivKey;
	ctpCtx->mCtx.mMethod.mLoadPubKey = VNRabin_CTP_LoadPubKey;
	ctpCtx->mCtx.mMethod.mLoadPrivKey = VNRabin_CTP_LoadPrivKey;
	ctpCtx->mCtx.mMethod.mPubEncrypt = VNRabin_CTP_PubProcess;
	ctpCtx->mCtx.mMethod.mPrivDecrypt = VNRabin_CTP_PrivProcess;
	ctpCtx->mCtx.mMethod.mPubDecrypt = VNRabin_CTP_PubProcess;
	ctpCtx->mCtx.mMethod.mPrivEncrypt = VNRabin_CTP_PrivProcess;

	ctpCtx->mPrivKey = NULL;
	ctpCtx->mPubKey = NULL;

	return &( ctpCtx->mCtx );
}

VNAsymCryptCtx_t * VNRabinSign_CTP_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNRabin_CTP_CtxNewImpl();

	ctx->mType = VN_TYPE_VNRabinSign_CTP;

	return ctx;
}

VNAsymCryptCtx_t * VNRabinEnc_CTP_CtxNew()
{
	VNAsymCryptCtx_t * ctx = VNRabin_CTP_CtxNewImpl();

	ctx->mType = VN_TYPE_VNRabinEnc_CTP;

	return ctx;
}

void VNRabin_CTP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	const VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	VNRabin_CTP_ClearKeys( ctx );

	delete ctpCtx;
}

int VNRabin_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	ctpCtx->mPrivKey = new Rabin::PrivateKey();
	ctpCtx->mPubKey = new Rabin::PublicKey();

	ctpCtx->mPrivKey->Initialize( ctpCtx->mRng, keyBits );
	ctpCtx->mPubKey->Initialize( ctpCtx->mPrivKey->GetModulus(),
		ctpCtx->mPrivKey->GetQuadraticResidueModPrime1(),
		ctpCtx->mPrivKey->GetQuadraticResidueModPrime2() );

	return 0;
}

void VNRabin_CTP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	if( NULL != ctpCtx->mPrivKey ) delete ctpCtx->mPrivKey, ctpCtx->mPrivKey = NULL;
	if( NULL != ctpCtx->mPubKey ) delete ctpCtx->mPubKey, ctpCtx->mPubKey = NULL;
}

int VNRabin_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	if( NULL == ctpCtx->mPubKey ) return 0;

	VN_CTP_dump_hex( (void*)&( ctpCtx->mPubKey->GetModulus() ), hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPubKey = hexPubKey->next;
	VN_CTP_dump_hex( (void*)&( ctpCtx->mPubKey->GetQuadraticResidueModPrime1() ), hexPubKey );

	hexPubKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPubKey = hexPubKey->next;
	VN_CTP_dump_hex( (void*)&( ctpCtx->mPubKey->GetQuadraticResidueModPrime2() ), hexPubKey );

	return 0;
}

int VNRabin_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	VNRabin_CTP_DumpPubKey( ctx, hexPubKey );

	if( NULL == ctpCtx->mPrivKey ) return 0;

	VN_CTP_dump_hex( (void*)&( ctpCtx->mPrivKey->GetPrime1() ), hexPrivKey );

	hexPrivKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPrivKey = hexPrivKey->next;
	VN_CTP_dump_hex( (void*)&( ctpCtx->mPrivKey->GetPrime2() ), hexPrivKey );

	hexPrivKey->next = (struct vn_iovec*)calloc( sizeof( struct vn_iovec ), 1 );
	hexPrivKey = hexPrivKey->next;
	VN_CTP_dump_hex( (void*)&( ctpCtx->mPrivKey->GetMultiplicativeInverseOfPrime2ModPrime1() ), hexPrivKey );

	return 0;
}

int VNRabin_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	Integer n, r, s;
	VN_CTP_load_hex( hexPubKey, &n );
	VN_CTP_load_hex( hexPubKey->next, &r );
	VN_CTP_load_hex( hexPubKey->next->next, &s );

	ctpCtx->mPubKey = new Rabin::PublicKey();
	ctpCtx->mPubKey->Initialize( n, r, s );

	return 0;
}

int VNRabin_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	VNRabin_CTP_LoadPubKey( ctx, hexPubKey );

	Integer p, q, u;

	VN_CTP_load_hex( hexPrivKey, &p );
	VN_CTP_load_hex( hexPrivKey->next, &q );
	VN_CTP_load_hex( hexPrivKey->next->next, &u );

	ctpCtx->mPrivKey = new Rabin::PrivateKey();
	ctpCtx->mPrivKey->Initialize( ctpCtx->mPubKey->GetModulus(),
		ctpCtx->mPubKey->GetQuadraticResidueModPrime1(),
		ctpCtx->mPubKey->GetQuadraticResidueModPrime2(),
		p, q, u );

	return 0;
}

int VNRabin_CTP_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	Integer m( (const byte*)plainText, length );

	Integer c = ctpCtx->mPubKey->ApplyFunction( m );
	
	cipherText->i.iov_len = c.MinEncodedSize();
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );

	c.Encode( (byte*)cipherText->i.iov_base, cipherText->i.iov_len );

	return 0;
}

int VNRabin_CTP_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	VNRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNRabinSign_CTP == ctx->mType || VN_TYPE_VNRabinEnc_CTP == ctx->mType );

	Integer c( (const byte*)cipherText, length );

	Integer m = ctpCtx->mPrivKey->CalculateInverse( ctpCtx->mRng, c );

	plainText->i.iov_len = m.MinEncodedSize();
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );

	m.Encode( (byte*)plainText->i.iov_base, plainText->i.iov_len );

	return 0;
}

