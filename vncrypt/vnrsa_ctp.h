#pragma once

#include "vnasymcrypt.h"

#ifdef __cplusplus
extern "C" {
#endif

VNAsymCryptCtx_t * VNRsaSign_CTP_CtxNew( unsigned long e );

VNAsymCryptCtx_t * VNRsaEnc_CTP_CtxNew( unsigned long e );

void VNRsa_CTP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRsa_CTP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRsa_CTP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRsa_CTP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRsa_CTP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRsa_CTP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRsa_CTP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRsa_CTP_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRsa_CTP_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

#ifdef __cplusplus
};
#endif

