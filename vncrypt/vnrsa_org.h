
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRsaSign_ORG_CtxNew( unsigned long e );

VNAsymCryptCtx_t * VNRsaEnc_ORG_CtxNew( unsigned long e );

void VNRsa_ORG_CtxFree( VNAsymCryptCtx_t * ctx );

int VNRsa_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRsa_ORG_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRsa_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNRsa_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNRsa_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNRsa_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNRsa_ORG_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRsa_ORG_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

int VNRsa_ORG_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * cipherText );

int VNRsa_ORG_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct vn_iovec * plainText );

