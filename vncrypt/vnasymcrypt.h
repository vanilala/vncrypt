#pragma once

#include <sys/uio.h>

typedef struct tagVNAsymCryptCtx VNAsymCryptCtx_t;

enum { VN_ERR_PLAINTEXT_TOO_LONG = -101 };

typedef struct tagVNAsymCryptMethod {
	int ( * mGenKeys ) ( VNAsymCryptCtx_t * ctx, int keyBits );

	void ( * mClearKeys ) ( VNAsymCryptCtx_t * ctx );

	int ( * mDumpPubKey ) ( const VNAsymCryptCtx_t * ctx,
		struct iovec * hexPubKey );

	int ( * mDumpPrivKey ) ( const VNAsymCryptCtx_t * ctx,
		struct iovec * hexPubKey, struct iovec * hexPrivKey );

	int ( * mLoadPubKey ) ( VNAsymCryptCtx_t * ctx,
		const struct iovec * hexPubKey );

	int ( * mLoadPrivKey ) ( VNAsymCryptCtx_t * ctx,
		const struct iovec * hexPubKey, const struct iovec * hexPrivKey );

	int ( * mPrivEncrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct iovec * cipherText );

	int ( * mPubDecrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct iovec * plainText );

	int ( * mPubEncrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct iovec * cipherText );

	int ( * mPrivDecrypt ) ( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct iovec * plainText );
} VNAsymCryptMethod_t;

enum {
	VN_TYPE_VNRabinSign_BN = 1,
	VN_TYPE_VNRabinSign_GC = 2,
	VN_TYPE_VNRsaSign_BN = 3,

	VN_TYPE_VNWilliamsEnc_BN = 100,
	VN_TYPE_VNRsaEnc_BN = 101,
};

#define VN_CONTAINER_OF(addr,type,field) \
	((type*)((unsigned char*)addr - (unsigned long)&((type*)0)->field))

typedef struct tagVNAsymCryptCtx {
	int mType;
	VNAsymCryptMethod_t mMethod;
} VNAsymCryptCtx_t;

