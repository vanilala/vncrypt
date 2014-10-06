#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRabinEnc_GMP_CtxNew();

void VNRabinEnc_GMP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRabinEnc_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRabinEnc_GMP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRabinEnc_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRabinEnc_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRabinEnc_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRabinEnc_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRabinEnc_GMP_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRabinEnc_GMP_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

