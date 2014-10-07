
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNModRabinSign_LIP_CtxNew();

void VNModRabin_LIP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNModRabin_LIP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNModRabin_LIP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNModRabin_LIP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNModRabin_LIP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNModRabin_LIP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNModRabin_LIP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNModRabin_LIP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNModRabin_LIP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

