
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRabin_GC_CtxNew();

void VNRabin_GC_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRabin_GC_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRabin_GC_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRabin_GC_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRabin_GC_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRabin_GC_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRabin_GC_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRabin_GC_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRabin_GC_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

