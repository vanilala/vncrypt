
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRabin_GCCtx_New();

void VNRabin_GCCtx_Free( VNAsymCryptCtx_t * ctx );

int VNRabin_GC_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRabin_GC_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRabin_GC_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey );

int VNRabin_GC_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey );

int VNRabin_GC_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey );

int VNRabin_GC_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey );

int VNRabin_GC_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText );

int VNRabin_GC_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText );

