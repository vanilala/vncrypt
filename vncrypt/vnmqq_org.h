#pragma once

#include "vnasymcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

VNAsymCryptCtx_t * VNMqqSign_ORG_CtxNew();

void VNMqq_ORG_CtxFree( VNAsymCryptCtx_t * ctx );

int VNMqq_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNMqq_ORG_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNMqq_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNMqq_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNMqq_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNMqq_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNMqq_ORG_Sign( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNMqq_ORG_Verify( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	const struct vn_iovec * plainText );

#ifdef __cplusplus
};
#endif

