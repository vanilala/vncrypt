
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNWilliamsEnc_BN_CtxNew();

void VNWilliamsEnc_BN_CtxFree( VNAsymCryptCtx_t * ctx );

int VNWilliamsEnc_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNWilliamsEnc_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNWilliamsEnc_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNWilliamsEnc_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNWilliamsEnc_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNWilliamsEnc_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNWilliamsEnc_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNWilliamsEnc_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

