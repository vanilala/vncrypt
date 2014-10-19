
#include "vnecies_ctp.h"

#include <crypto++/oids.h>
#include <crypto++/osrng.h>
#include <crypto++/eccrypto.h>
#include <crypto++/asn.h>
#include <crypto++/ec2n.h>
#include <crypto++/ecp.h>
#include <crypto++/hex.h>

#include <stdio.h>

using namespace CryptoPP;

struct VNKeySize2Oid_t {
	int mKeySize;
	const char * mName;
	OID mOid;
} gKeySize2OId[] = {
	{ 112, "secp112r1", ASN1::secp112r1() },
	{ 112, "secp112r2", ASN1::secp112r2() },
	{ 160, "secp160r1", ASN1::secp160r1() },
	{ 160, "secp160k1", ASN1::secp160k1() },
	{ 256, "secp256k1", ASN1::secp256k1() },
	{ 128, "secp128r1", ASN1::secp128r1() },
	{ 128, "secp128r2", ASN1::secp128r2() },
	{ 160, "secp160r2", ASN1::secp160r2() },
	{ 192, "secp192k1", ASN1::secp192k1() },
	{ 224, "secp224k1", ASN1::secp224k1() },
	{ 224, "secp224r1", ASN1::secp224r1() },
	{ 384, "secp384r1", ASN1::secp384r1() },
	{ 521, "secp521r1", ASN1::secp521r1() },
	{ 163, "sect163k1", ASN1::sect163k1() },
	{ 163, "sect163r1", ASN1::sect163r1() },
	{ 239, "sect239k1", ASN1::sect239k1() },
	{ 113, "sect113r1", ASN1::sect113r1() },
	{ 113, "sect113r2", ASN1::sect113r2() },
	{ 163, "sect163r2", ASN1::sect163r2() },
	{ 283, "sect283k1", ASN1::sect283k1() },
	{ 283, "sect283r1", ASN1::sect283r1() },
	{ 131, "sect131r1", ASN1::sect131r1() },
	{ 131, "sect131r2", ASN1::sect131r2() },
	{ 193, "sect193r1", ASN1::sect193r1() },
	{ 193, "sect193r2", ASN1::sect193r2() },
	{ 233, "sect233k1", ASN1::sect233k1() },
	{ 233, "sect233r1", ASN1::sect233r1() },
	{ 409, "sect409k1", ASN1::sect409k1() },
	{ 409, "sect409r1", ASN1::sect409r1() },
	{ 571, "sect571k1", ASN1::sect571k1() },
	{ 571, "sect571r1", ASN1::sect571r1() },
	{ 0, "", ASN1::iso() }
};

typedef struct tagVNEcies_CTP_Ctx {
	VNAsymCryptCtx_t mCtx;

	AutoSeededRandomPool mRng;

	ECIES<ECP>::PrivateKey * mPrivKey;
	ECIES<ECP>::PublicKey * mPubKey;

	ECIES<ECP>::Encryptor * mEncryptor;
	ECIES<ECP>::Decryptor * mDecryptor;
} VNEcies_CTP_Ctx_t;

VNAsymCryptCtx_t * VNEcies_CTP_CtxNew()
{
	VNEcies_CTP_Ctx_t * ctpCtx = new VNEcies_CTP_Ctx_t();

	ctpCtx->mCtx.mType = VN_TYPE_VNEcies_CTP;

	ctpCtx->mCtx.mMethod.mCtxFree = VNEcies_CTP_CtxFree;
	ctpCtx->mCtx.mMethod.mGenKeys = VNEcies_CTP_GenKeys;
	ctpCtx->mCtx.mMethod.mClearKeys = VNEcies_CTP_ClearKeys;
	ctpCtx->mCtx.mMethod.mDumpPubKey = VNEcies_CTP_DumpPubKey;
	ctpCtx->mCtx.mMethod.mDumpPrivKey = VNEcies_CTP_DumpPrivKey;
	ctpCtx->mCtx.mMethod.mLoadPubKey = VNEcies_CTP_LoadPubKey;
	ctpCtx->mCtx.mMethod.mLoadPrivKey = VNEcies_CTP_LoadPrivKey;
	ctpCtx->mCtx.mMethod.mPubEncrypt = VNEcies_CTP_PubEncrypt;
	ctpCtx->mCtx.mMethod.mPrivDecrypt = VNEcies_CTP_PrivDecrypt;

	ctpCtx->mPrivKey = NULL;
	ctpCtx->mPubKey = NULL;

	ctpCtx->mDecryptor = NULL;
	ctpCtx->mDecryptor = NULL;

	return &( ctpCtx->mCtx );
}

void VNEcies_CTP_CtxFree( VNAsymCryptCtx_t * ctx )
{
	const VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	VNEcies_CTP_ClearKeys( ctx );

	delete ctpCtx;
}

int VNEcies_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits )
{
	VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	struct VNKeySize2Oid_t * iter = NULL;
	int interval = 1000; 

	for( int i = 0; gKeySize2OId[i].mKeySize > 0 && i < 1000; i++ )
	{
		if( abs( gKeySize2OId[i].mKeySize - keyBits ) < interval )
		{
			interval = abs( gKeySize2OId[i].mKeySize - keyBits );
			iter = &( gKeySize2OId[i] );
		}
	}

	printf( "\n\tuse %d, %s\n\n", iter->mKeySize, iter->mName );

	ctpCtx->mPrivKey = new ECIES<ECP>::PrivateKey();
	ctpCtx->mPubKey = new ECIES<ECP>::PublicKey();

	ctpCtx->mPrivKey->Initialize( ctpCtx->mRng, iter->mOid );
	ctpCtx->mPrivKey->MakePublicKey( *( ctpCtx->mPubKey ) );

	ctpCtx->mEncryptor = new ECIES<ECP>::Encryptor( *( ctpCtx->mPubKey ) );
	ctpCtx->mDecryptor = new ECIES<ECP>::Decryptor( *( ctpCtx->mPrivKey ) );

	return ( ctpCtx->mPrivKey->Validate( ctpCtx->mRng, 3 )
		&& ctpCtx->mPubKey->Validate( ctpCtx->mRng, 3 ) ) ? 0 : -1;
}

void VNEcies_CTP_ClearKeys( VNAsymCryptCtx_t * ctx )
{
	VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	if( NULL != ctpCtx->mPrivKey ) delete ctpCtx->mPrivKey, ctpCtx->mPrivKey = NULL;
	if( NULL != ctpCtx->mPubKey ) delete ctpCtx->mPubKey, ctpCtx->mPubKey = NULL;

	if( NULL != ctpCtx->mEncryptor ) delete ctpCtx->mEncryptor, ctpCtx->mEncryptor = NULL;
	if( NULL != ctpCtx->mDecryptor ) delete ctpCtx->mDecryptor, ctpCtx->mDecryptor = NULL;
}

int VNEcies_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey )
{
	const VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	if( NULL == ctpCtx->mPubKey ) return 0;

	HexEncoder encoder;
	ctpCtx->mPubKey->Save( encoder );

	hexPubKey->i.iov_base = calloc( 1, encoder.MaxRetrievable() );
	hexPubKey->i.iov_len = encoder.Get( (byte*)hexPubKey->i.iov_base, encoder.MaxRetrievable() );

	return 0;
}

int VNEcies_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey )
{
	const VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	VNEcies_CTP_DumpPubKey( ctx, hexPubKey );

	if( NULL == ctpCtx->mPrivKey ) return 0;

	HexEncoder encoder;
	ctpCtx->mPrivKey->Save( encoder );

	hexPrivKey->i.iov_base = calloc( 1, encoder.MaxRetrievable() );
	hexPrivKey->i.iov_len = encoder.Get( (byte*)hexPrivKey->i.iov_base, encoder.MaxRetrievable() );

	return 0;
}

int VNEcies_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey )
{
	VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	HexDecoder decoder;
	decoder.Put2( (byte*)hexPubKey->i.iov_base, hexPubKey->i.iov_len, 1, 1 );

	ctpCtx->mPubKey = new ECIES<ECP>::PublicKey();
	ctpCtx->mPubKey->Load( decoder );
	ctpCtx->mEncryptor = new ECIES<ECP>::Encryptor( *( ctpCtx->mPubKey ) );

	return 0;
}

int VNEcies_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey )
{
	VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	VNEcies_CTP_LoadPubKey( ctx, hexPubKey );

	HexDecoder decoder;
	decoder.Put2( (byte*)hexPrivKey->i.iov_base, hexPrivKey->i.iov_len, 1, 1 );

	ctpCtx->mPrivKey = new ECIES<ECP>::PrivateKey();
	ctpCtx->mPrivKey->Load( decoder );
	ctpCtx->mDecryptor = new ECIES<ECP>::Decryptor( *( ctpCtx->mPrivKey ) );

	return 0;
}

int VNEcies_CTP_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText )
{
	VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	cipherText->i.iov_len = ctpCtx->mEncryptor->CiphertextLength( length );
	cipherText->i.iov_base = malloc( cipherText->i.iov_len );

	ctpCtx->mEncryptor->Encrypt( ctpCtx->mRng, (const byte*)plainText, (size_t)length,
		(byte*)cipherText->i.iov_base );

	return 0;
}

int VNEcies_CTP_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText )
{
	VNEcies_CTP_Ctx_t * ctpCtx = VN_CONTAINER_OF( ctx, VNEcies_CTP_Ctx_t, mCtx );
	assert( VN_TYPE_VNEcies_CTP == ctx->mType );

	plainText->i.iov_len = ctpCtx->mDecryptor->MaxPlaintextLength( length );
	plainText->i.iov_base = malloc( plainText->i.iov_len );

	DecodingResult result = ctpCtx->mDecryptor->Decrypt( ctpCtx->mRng,
		(const byte*)cipherText, (size_t)length, (byte*)plainText->i.iov_base );
	plainText->i.iov_len = result.messageLength;

	return result.isValidCoding ? 0 : -1;
}

