
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNDsaSign_ORG_CtxNew();

void VNDsa_ORG_CtxFree( VNAsymCryptCtx_t * ctx );

int VNDsa_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNDsa_ORG_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNDsa_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey );

int VNDsa_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNDsa_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey );

int VNDsa_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNDsa_ORG_Sign( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct vn_iovec * signText );

int VNDsa_ORG_Verify( const VNAsymCryptCtx_t * ctx,
	const unsigned char * signText, int length,
	const struct vn_iovec * plainText );

