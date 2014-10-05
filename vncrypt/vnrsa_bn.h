
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRsaSign_BN_CtxNew( unsigned long e );

VNAsymCryptCtx_t * VNRsaEnc_BN_CtxNew( unsigned long e );

void VNRsa_BN_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRsa_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRsa_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRsa_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRsa_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRsa_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRsa_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRsa_BN_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRsa_BN_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

