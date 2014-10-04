
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRsaSign_BNCtx_New( unsigned long e );

VNAsymCryptCtx_t * VNRsaEnc_BNCtx_New( unsigned long e );

void VNRsa_BNCtx_Free( VNAsymCryptCtx_t * ctx );

int VNRsa_BN_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRsa_BN_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRsa_BN_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey );

int VNRsa_BN_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey );

int VNRsa_BN_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey );

int VNRsa_BN_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey );

int VNRsa_BN_PrivProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText );

int VNRsa_BN_PubProcess( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText );

