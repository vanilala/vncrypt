
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNWilliamsEnc_BNCtx_New();

void VNWilliamsEnc_BNCtx_Free( VNAsymCryptCtx_t * ctx );

int VNWilliamsEnc_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNWilliamsEnc_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNWilliamsEnc_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey );

int VNWilliamsEnc_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey );

int VNWilliamsEnc_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey );

int VNWilliamsEnc_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey );

int VNWilliamsEnc_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText );

int VNWilliamsEnc_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText );

