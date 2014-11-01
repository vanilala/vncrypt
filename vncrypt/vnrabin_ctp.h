#pragma once

#include "vnasymcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

VNAsymCryptCtx_t * VNRabinEnc_CTP_CtxNew();

VNAsymCryptCtx_t * VNRabinSign_CTP_CtxNew();

void VNRabin_CTP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRabin_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRabin_CTP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRabin_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRabin_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRabin_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRabin_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRabin_CTP_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRabin_CTP_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

#ifdef __cplusplus
};
#endif

