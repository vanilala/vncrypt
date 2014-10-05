
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRsaSign_GMP_CtxNew( unsigned long e );

VNAsymCryptCtx_t * VNRsaEnc_GMP_CtxNew( unsigned long e );

void VNRsa_GMP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRsa_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRsa_GMP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRsa_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRsa_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRsa_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRsa_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRsa_GMP_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRsa_GMP_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

