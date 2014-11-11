
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRWSign_BN_CtxNew();

VNAsymCryptCtx_t * VNRWEnc_BN_CtxNew();

void VNRW_BN_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRW_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRW_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRW_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRW_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRW_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRW_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRW_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRW_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

int VNRW_BN_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRW_BN_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

