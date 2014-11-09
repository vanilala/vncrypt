
#pragma once

#include "vndefine.h"

VNAsymCryptCtx_t * VNModRabinSign_GMP_CtxNew();

void VNModRabin_GMP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNModRabin_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNModRabin_GMP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNModRabin_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNModRabin_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNModRabin_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNModRabin_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNModRabin_GMP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNModRabin_GMP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

