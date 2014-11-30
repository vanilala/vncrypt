
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNP1363RWSign_BN_CtxNew( unsigned long e );

void VNP1363RW_BN_CtxFree( VNAsymCryptCtx_t * ctx );

int VNP1363RW_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNP1363RW_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNP1363RW_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNP1363RW_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNP1363RW_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNP1363RW_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNP1363RW_BN_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNP1363RW_BN_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

