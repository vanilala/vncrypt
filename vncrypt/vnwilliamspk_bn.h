
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNWilliamsPK_BNCtx_New();

void VNWilliamsPK_BNCtx_Free( VNAsymCryptCtx_t * ctx );

int VNWilliamsPK_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNWilliamsPK_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNWilliamsPK_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey );

int VNWilliamsPK_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey );

int VNWilliamsPK_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey );

int VNWilliamsPK_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey );

int VNWilliamsPK_BN_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText );

int VNWilliamsPK_BN_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText );

