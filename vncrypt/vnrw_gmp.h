
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRWSign_GMP_CtxNew();

VNAsymCryptCtx_t * VNRWEnc_GMP_CtxNew();

void VNRW_GMP_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRW_GMP_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRW_GMP_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRW_GMP_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRW_GMP_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRW_GMP_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRW_GMP_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRW_GMP_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRW_GMP_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

int VNRW_GMP_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

int VNRW_GMP_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

