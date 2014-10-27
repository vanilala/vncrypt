#pragma once

#include <sys/uio.h>
#include <stdlib.h>

typedef struct tagVNAsymCryptCtx VNAsymCryptCtx_t;

enum { VN_ERR_PLAINTEXT_TOO_LONG = -101 };

struct vn_iovec
{
	struct vn_iovec * next;
	struct iovec i;
};

typedef struct tagVNAsymCryptMethod
{
	void ( * mCtxFree ) ( VNAsymCryptCtx_t * ctx );

	int ( * mGenKeys ) ( VNAsymCryptCtx_t * ctx, int keyBits );

	void ( * mClearKeys ) ( VNAsymCryptCtx_t * ctx );

	int ( * mDumpPubKey ) ( const VNAsymCryptCtx_t * ctx,
		struct vn_iovec * hexPubKey );

	int ( * mDumpPrivKey ) ( const VNAsymCryptCtx_t * ctx,
		struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

	int ( * mLoadPubKey ) ( VNAsymCryptCtx_t * ctx,
		const struct vn_iovec * hexPubKey );

	int ( * mLoadPrivKey ) ( VNAsymCryptCtx_t * ctx,
		const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

	/* Public-key encryption */
	int ( * mPubEncrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

	int ( * mPrivDecrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText );

	/* Digital signature schemes with message recovery */
	int ( * mPrivEncrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

	int ( * mPubDecrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText );

	/* Digital signature schemes with appendix */
	int ( * mSign ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * signText );

	int ( * mVerify ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * signText, int length,
		const struct vn_iovec * plainText );
} VNAsymCryptMethod_t;

enum
{
	/*
	 * Public-key encryption algorithm
	 *
	 * every algorithm has 10 implements, max 100 algorithms
	 */

	/* rsa encryption */
	VN_TYPE_VNRsaEnc_BN = 1,
	VN_TYPE_VNRsaEnc_GMP = 2,

	VN_TYPE_VNRsaEnc_ORG = 10,

	/* rabin encryption */
	VN_TYPE_VNRabinEnc_BN = 11,
	VN_TYPE_VNRabinEnc_GMP = 12,

	/* williams encryption */
	VN_TYPE_VNWilliamsEnc_BN = 21,

	/* Ecies encryption */
	VN_TYPE_VNEcies_CTP = 31,

	/* ElGamal encryption */
	VN_TYPE_VNElGamal_CTP = 41,

	VN_TYPE_VNMaxEnc = 1000,

	/*
	 * Digital signature schemes with message recovery
	 *
	 * every algorithm has max 10 implements, max 100 algorithms
	 */

	/* rsa signature */
	VN_TYPE_VNRsaSign_BN = 1000 + 1,
	VN_TYPE_VNRsaSign_GMP = 1000 + 2,

	VN_TYPE_VNRsaSign_ORG = 1000 + 10,

	/* modified rabin signature */
	VN_TYPE_VNModRabinSign_BN = 1000 + 11,
	VN_TYPE_VNModRabinSign_GC = 1000 + 13,
	VN_TYPE_VNModRabinSign_LIP = 1000 + 14,
	VN_TYPE_VNModRabinSign_CTP = 1000 + 15,

	VN_TYPE_VNMaxSignType1 = 2000,

	/* Digital signature schemes with appendix */

	/* dsa signature */
	VN_TYPE_VNDsaSign_ORG = 2000 + 1,
	VN_TYPE_VNEcdsaSign_ORG = 2000 + 2,

	VN_TYPE_VNMaxSignType2 = 3000,
};

#define VN_CONTAINER_OF(addr,type,field) \
	(type*)( ((unsigned char*)addr) - (unsigned long)&(((type*)0)->field) )

struct tagVNAsymCryptCtx {
	int mType;
	VNAsymCryptMethod_t mMethod;
};

