
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRabin_BN_CtxNew();

void VNRabin_BN_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRabin_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRabin_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRabin_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRabin_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRabin_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRabin_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRabin_BN_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRabin_BN_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

