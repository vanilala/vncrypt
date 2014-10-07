#pragma once

#include <sys/uio.h>

typedef struct tagVNAsymCryptCtx VNAsymCryptCtx_t;

enum { VN_ERR_PLAINTEXT_TOO_LONG = -101 };

struct vn_iovec {
	struct vn_iovec * next;
	struct iovec i;
};

typedef struct tagVNAsymCryptMethod {
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

	int ( * mPrivEncrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

	int ( * mPubDecrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText );

	int ( * mPubEncrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

	int ( * mPrivDecrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText );
} VNAsymCryptMethod_t;

enum {
	/* signature algorighm */

	/* every algorithm has max 10 implements, max 100 algorithms */

	/* rsa signature */
	VN_TYPE_VNRsaSign_BN = 1,
	VN_TYPE_VNRsaSign_GMP = 2,

	VN_TYPE_VNRsaSign_ORG = 10,

	/* rabin signature */
	VN_TYPE_VNRabinSign_BN = 11,
	VN_TYPE_VNRabinSign_GMP = 12,
	VN_TYPE_VNRabinSign_GC = 13,
	VN_TYPE_VNRabinSign_LIP = 14,

	VN_TYPE_VNMaxSign = 1000,

	/* encryption algorithm */

	/* every algorithm has 10 implements, max 100 algorithms */

	/* rsa encryption */
	VN_TYPE_VNRsaEnc_BN = 1000 + 1,
	VN_TYPE_VNRsaEnc_GMP = 1000 + 2,

	VN_TYPE_VNRsaEnc_ORG = 1000 + 10,

	/* rabin encryption */
	VN_TYPE_VNRabinEnc_BN = 1000 + 11,
	VN_TYPE_VNRabinEnc_GMP = 1000 + 12,

	/* williams encryption */
	VN_TYPE_VNWilliamsEnc_BN = 1000 + 21,
};

#define VN_CONTAINER_OF(addr,type,field) \
	((type*)((unsigned char*)addr - (unsigned long)&((type*)0)->field))

typedef struct tagVNAsymCryptCtx {
	int mType;
	VNAsymCryptMethod_t mMethod;
} VNAsymCryptCtx_t;

