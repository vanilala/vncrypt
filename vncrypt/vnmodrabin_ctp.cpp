
#include "vnmodrabin_ctp.h"
#include "vncrypt_ctp.h"

#include <crypto++/osrng.h>
#include <crypto++/rw.h>
#include <crypto++/hex.h>
#include <crypto++/pssr.h>

#include <stdio.h>
#include <iostream>

using namespace CryptoPP;
using namespace std;

typedef struct tagVNModRabin_CTP_Ctx {
	VNAsymCryptCtx_t mCtx;

	AutoSeededRandomPool mRng;

	RW::PublicKey * mPubKey;
	RW::PrivateKey * mPrivKey;

	RWSS<PSSR, SHA>::Signer * mSigner;
	RWSS<PSSR, SHA>::Verifier * mVerifier;
} VNModRabin_CTP_Ctx_t;

VNAsymCryptCtx_t * VNModRabinSign_CTP_CtxNew()
{
	VNModRabin_CTP_Ctx_t * ctpCtx = new VNModRabin_CTP_Ctx_t();

	ctpCtx->mCtx.mType = VN_TYPE_VNModRabinSign_CTP;

	ctpCtx->mCtx.mMethod.mCtxFree = VNModRabin_CTP_CtxFree;
	ctpCtx->mCtx.mMethod.mGenKeys = VNModRabin_CTP_GenKeys;
	ctpCtx->mCtx.mMethod.mClearKeys = VNModRabin_CTP_ClearKeys;
	ctpCtx->mCtx.mMethod.mDumpPubKey = VNModRabin_CTP_DumpPubKey;
	ctpCtx->mCtx.mMethod.mDumpPrivKey = VNModRabin_CTP_DumpPrivKey;
	ctpCtx->mCtx.mMethod.mLoadPubKey = VNModRabin_CTP_LoadPubKey;
	ctpCtx->mCtx.mMethod.mLoadPrivKey = VNModRabin_CTP_LoadPrivKey;
	ctpCtx->mCtx.mMethod.mPrivEncrypt = VNModRabin_CTP_PrivEncrypt;
	ctpCtx->mCtx.mMethod.mPubDecrypt = VNModRabin_CTP_PubDecrypt;

	ctpCtx->mPrivKey = NULL;
	ctpCtx->mPubKey = NULL;

	ctpCtx->mVerifier = NULL;
	ctpCtx->mVerifier = NULL;

	return &( ctpCtx->mCtx );
}

void VNModRabin_CTP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	const VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	VNModRabin_CTP_ClearKeys( ctx );

	delete ctpCtx;
}

int VNModRabin_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	ctpCtx->mPrivKey = new RW::PrivateKey();
	ctpCtx->mPubKey = new RW::PublicKey();

	ctpCtx->mPrivKey->GenerateRandomWithKeySize( ctpCtx->mRng, keyBits );
	ctpCtx->mPubKey->Initialize( ctpCtx->mPrivKey->GetModulus() );

	ctpCtx->mSigner = new RWSS<PSSR, SHA>::Signer( *( ctpCtx->mPrivKey ) );
	ctpCtx->mVerifier = new RWSS<PSSR, SHA>::Verifier( *( ctpCtx->mPubKey ) );

	return 0;
}

void VNModRabin_CTP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	if( NULL != ctpCtx->mPrivKey ) delete ctpCtx->mPrivKey, ctpCtx->mPrivKey = NULL;
	if( NULL != ctpCtx->mPubKey ) delete ctpCtx->mPubKey, ctpCtx->mPubKey = NULL;

	if( NULL != ctpCtx->mSigner ) delete ctpCtx->mSigner, ctpCtx->mSigner = NULL;
	if( NULL != ctpCtx->mVerifier ) delete ctpCtx->mVerifier, ctpCtx->mVerifier = NULL;
}

int VNModRabin_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	if( NULL == ctpCtx->mPubKey ) return 0;

	VN_CTP_dump_hex( (void*)&( ctpCtx->mPubKey->GetModulus() ), hexPubKey );

	return 0;
}

int VNModRabin_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	VNModRabin_CTP_DumpPubKey( ctx, hexPubKey );

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

int VNModRabin_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	Integer n;
	VN_CTP_load_hex( hexPubKey, &n );

	ctpCtx->mPubKey = new RW::PublicKey();
	ctpCtx->mPubKey->Initialize( n );
	ctpCtx->mVerifier = new RWSS<PSSR, SHA>::Verifier( *( ctpCtx->mPubKey ) );

	return 0;
}

int VNModRabin_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	Integer n, p, q, u;

	VN_CTP_load_hex( hexPubKey, &n );

	VN_CTP_load_hex( hexPrivKey, &p );
	VN_CTP_load_hex( hexPrivKey->next, &q );
	VN_CTP_load_hex( hexPrivKey->next->next, &u );

	ctpCtx->mPrivKey = new RW::PrivateKey();
	ctpCtx->mPrivKey->Initialize( n, p, q, u );
	ctpCtx->mSigner = new RWSS<PSSR, SHA>::Signer( *( ctpCtx->mPrivKey ) );

	return 0;
}

int VNModRabin_CTP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	cipherText->i.iov_len = ctpCtx->mSigner->MaxSignatureLength();
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1);

	cipherText->i.iov_len = ctpCtx->mSigner->SignMessageWithRecovery( ctpCtx->mRng,
		(const byte*)plainText, (size_t)length, NULL, 0, (byte*)cipherText->i.iov_base );

	return 0;
}

int VNModRabin_CTP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	VNModRabin_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNModRabin_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNModRabinSign_CTP == ctx->mType );

	plainText->i.iov_len = ctpCtx->mVerifier->MaxRecoverableLengthFromSignatureLength( length );
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );

	DecodingResult result = ctpCtx->mVerifier->RecoverMessage(
		(byte *)plainText->i.iov_base, NULL, 0, cipherText, (size_t)length );
	plainText->i.iov_len = result.messageLength;

	return 0;
}

