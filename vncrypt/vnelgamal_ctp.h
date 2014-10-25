#pragma once

#include "vnasymcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

VNAsymCryptCtx_t * VNElGamal_CTP_CtxNew();

void VNElGamal_CTP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNElGamal_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNElGamal_CTP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNElGamal_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNElGamal_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNElGamal_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNElGamal_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNElGamal_CTP_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNElGamal_CTP_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

#ifdef __cplusplus
};
#endif

