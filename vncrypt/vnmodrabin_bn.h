
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNModRabinSign_BN_CtxNew();

void VNModRabin_BN_CtxFree( VNAsymCryptCtx_t * ctx );

int VNModRabin_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNModRabin_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNModRabin_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNModRabin_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNModRabin_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNModRabin_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNModRabin_BN_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNModRabin_BN_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

