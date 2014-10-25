
#include "vnelgamal_ctp.h"

#include <crypto++/osrng.h>
#include <crypto++/elgamal.h>
#include <crypto++/hex.h>

#include <stdio.h>

using namespace CryptoPP;

typedef struct tagVNElGamal_CTP_Ctx {
	VNAsymCryptCtx_t mCtx;

	AutoSeededRandomPool mRng;

	ElGamalKeys::PrivateKey * mPrivKey;
	ElGamalKeys::PublicKey * mPubKey;

	ElGamal::Encryptor * mEncryptor;
	ElGamal::Decryptor * mDecryptor;
} VNElGamal_CTP_Ctx_t;

VNAsymCryptCtx_t * VNElGamal_CTP_CtxNew()
{
	VNElGamal_CTP_Ctx_t * ctpCtx = new VNElGamal_CTP_Ctx_t();

	ctpCtx->mCtx.mType = VN_TYPE_VNElGamal_CTP;

	ctpCtx->mCtx.mMethod.mCtxFree = VNElGamal_CTP_CtxFree;
	ctpCtx->mCtx.mMethod.mGenKeys = VNElGamal_CTP_GenKeys;
	ctpCtx->mCtx.mMethod.mClearKeys = VNElGamal_CTP_ClearKeys;
	ctpCtx->mCtx.mMethod.mDumpPubKey = VNElGamal_CTP_DumpPubKey;
	ctpCtx->mCtx.mMethod.mDumpPrivKey = VNElGamal_CTP_DumpPrivKey;
	ctpCtx->mCtx.mMethod.mLoadPubKey = VNElGamal_CTP_LoadPubKey;
	ctpCtx->mCtx.mMethod.mLoadPrivKey = VNElGamal_CTP_LoadPrivKey;
	ctpCtx->mCtx.mMethod.mPubEncrypt = VNElGamal_CTP_PubEncrypt;
	ctpCtx->mCtx.mMethod.mPrivDecrypt = VNElGamal_CTP_PrivDecrypt;

	ctpCtx->mPrivKey = NULL;
	ctpCtx->mPubKey = NULL;

	ctpCtx->mDecryptor = NULL;
	ctpCtx->mDecryptor = NULL;

	return &( ctpCtx->mCtx );
}

void VNElGamal_CTP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	const VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	VNElGamal_CTP_ClearKeys( ctx );

	delete ctpCtx;
}

int VNElGamal_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	ctpCtx->mPrivKey = new ElGamalKeys::PrivateKey();
	ctpCtx->mPubKey = new ElGamalKeys::PublicKey();

	ctpCtx->mPrivKey->GenerateRandomWithKeySize( ctpCtx->mRng, keyBits );
	ctpCtx->mPrivKey->MakePublicKey( *( ctpCtx->mPubKey ) );

	ctpCtx->mEncryptor = new ElGamal::Encryptor( *( ctpCtx->mPubKey ) );
	ctpCtx->mDecryptor = new ElGamal::Decryptor( *( ctpCtx->mPrivKey ) );

	return 0;
}

void VNElGamal_CTP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	if( NULL != ctpCtx->mPrivKey ) delete ctpCtx->mPrivKey, ctpCtx->mPrivKey = NULL;
	if( NULL != ctpCtx->mPubKey ) delete ctpCtx->mPubKey, ctpCtx->mPubKey = NULL;

	if( NULL != ctpCtx->mEncryptor ) delete ctpCtx->mEncryptor, ctpCtx->mEncryptor = NULL;
	if( NULL != ctpCtx->mDecryptor ) delete ctpCtx->mDecryptor, ctpCtx->mDecryptor = NULL;
}

int VNElGamal_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	if( NULL == ctpCtx->mPubKey ) return 0;

	HexEncoder encoder;
	ctpCtx->mPubKey->Save( encoder );

	hexPubKey->i.iov_base = calloc( 1, encoder.MaxRetrievable() + 1 );
	hexPubKey->i.iov_len = encoder.Get( (byte*)hexPubKey->i.iov_base, encoder.MaxRetrievable() );

	return 0;
}

int VNElGamal_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	VNElGamal_CTP_DumpPubKey( ctx, hexPubKey );

	if( NULL == ctpCtx->mPrivKey ) return 0;

	HexEncoder encoder;
	ctpCtx->mPrivKey->Save( encoder );

	hexPrivKey->i.iov_base = calloc( 1, encoder.MaxRetrievable() + 1 );
	hexPrivKey->i.iov_len = encoder.Get( (byte*)hexPrivKey->i.iov_base, encoder.MaxRetrievable() );

	return 0;
}

int VNElGamal_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	HexDecoder decoder;
	decoder.Put2( (byte*)hexPubKey->i.iov_base, hexPubKey->i.iov_len, 1, 1 );

	ctpCtx->mPubKey = new ElGamalKeys::PublicKey();
	ctpCtx->mPubKey->Load( decoder );
	ctpCtx->mEncryptor = new ElGamal::Encryptor( *( ctpCtx->mPubKey ) );

	return 0;
}

int VNElGamal_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	VNElGamal_CTP_LoadPubKey( ctx, hexPubKey );

	HexDecoder decoder;
	decoder.Put2( (byte*)hexPrivKey->i.iov_base, hexPrivKey->i.iov_len, 1, 1 );

	ctpCtx->mPrivKey = new ElGamalKeys::PrivateKey();
	ctpCtx->mPrivKey->Load( decoder );
	ctpCtx->mDecryptor = new ElGamal::Decryptor( *( ctpCtx->mPrivKey ) );

	return 0;
}

int VNElGamal_CTP_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	if( length > (int)ctpCtx->mEncryptor->FixedMaxPlaintextLength() )
	{
		printf( "%zd\n", ctpCtx->mEncryptor->FixedMaxPlaintextLength() );
		return VN_ERR_PLAINTEXT_TOO_LONG;
	}

	cipherText->i.iov_len = ctpCtx->mEncryptor->CiphertextLength( length );
	cipherText->i.iov_len = cipherText->i.iov_len == 0 ? length * 2 : cipherText->i.iov_len;
	cipherText->i.iov_base = malloc( cipherText->i.iov_len + 1 );

	ctpCtx->mEncryptor->Encrypt( ctpCtx->mRng, (const byte*)plainText, (size_t)length,
		(byte*)cipherText->i.iov_base );

	return 0;
}

int VNElGamal_CTP_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	VNElGamal_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNElGamal_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNElGamal_CTP == ctx->mType );

	plainText->i.iov_len = ctpCtx->mDecryptor->MaxPlaintextLength( length );
	plainText->i.iov_base = malloc( plainText->i.iov_len + 1 );

	DecodingResult result = ctpCtx->mDecryptor->Decrypt( ctpCtx->mRng,
		(const byte*)cipherText, (size_t)length, (byte*)plainText->i.iov_base );
	plainText->i.iov_len = result.messageLength;

	return result.isValidCoding ? 0 : -1;
}

