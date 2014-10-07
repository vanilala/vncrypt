
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNModRabinSign_GC_CtxNew();

void VNModRabin_GC_CtxFree( VNAsymCryptCtx_t * ctx );

int VNModRabin_GC_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNModRabin_GC_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNModRabin_GC_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNModRabin_GC_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNModRabin_GC_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNModRabin_GC_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNModRabin_GC_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNModRabin_GC_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

