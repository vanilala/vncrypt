
#pragma once

#include <sys/uio.h>

typedef struct tagVNAsymCryptCtx VNAsymCryptCtx_t;

typedef struct tagVNAsymCryptMethod {
	int ( * mGenKeys ) ( VNAsymCryptCtx_t * ctx, int keyBits );

	int ( * mDumpPubKey ) ( const VNAsymCryptCtx_t * ctx,
		struct iovec * hexPubKey );

	int ( * mDumpPrivKey ) ( const VNAsymCryptCtx_t * ctx,
		struct iovec * hexPubKey, struct iovec * hexPrivKey );

	int ( * mLoadPubKey ) ( VNAsymCryptCtx_t * ctx,
		struct iovec * hexPubKey );

	int ( * mLoadPrivKey ) ( VNAsymCryptCtx_t * ctx,
		struct iovec * hexPubKey, struct iovec * hexPrivKey );

	int ( * mPrivEncrypt ) ( const VNAsymCryptCtx_t * ctx,
		unsigned char * plainText, int length,
		struct iovec * cipherText );

	int ( * mPubDecrypt ) ( const VNAsymCryptCtx_t * ctx,
		unsigned char * cipherText, int length,
		struct iovec * plainText );

} VNAsymCryptMethod_t;

enum { TYPE_VNRabin_BN = 1, TYPE_VNRabin_GMP = 2 };

#define VN_CONTAINER_OF(addr,type,field) \
	((type*)((unsigned char*)addr - (unsigned long)&((type*)0)->field))

typedef struct tagVNAsymCryptCtx {
	int mType;
	VNAsymCryptMethod_t mMethod;
} VNAsymCryptCtx_t;

