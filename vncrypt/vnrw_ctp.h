#pragma once

#include "vnasymcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

VNAsymCryptCtx_t * VNRWSign_CTP_CtxNew();

void VNRW_CTP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRW_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRW_CTP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRW_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRW_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRW_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRW_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRW_CTP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRW_CTP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

#ifdef __cplusplus
};
#endif

