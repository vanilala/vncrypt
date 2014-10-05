
#pragma once

#include "vnasymcrypt.h"

VNAsymCryptCtx_t * VNRsaSign_ORGCtx_New( unsigned long e );

VNAsymCryptCtx_t * VNRsaEnc_ORGCtx_New( unsigned long e );

void VNRsa_ORGCtx_Free( VNAsymCryptCtx_t * ctx );

int VNRsa_ORG_GenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNRsa_ORG_ClearKeys( VNAsymCryptCtx_t * ctx );

int VNRsa_ORG_DumpPubKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey );

int VNRsa_ORG_DumpPrivKey( const VNAsymCryptCtx_t * ctx,
	struct iovec * hexPubKey, struct iovec * hexPrivKey );

int VNRsa_ORG_LoadPubKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey );

int VNRsa_ORG_LoadPrivKey( VNAsymCryptCtx_t * ctx,
	const struct iovec * hexPubKey, const struct iovec * hexPrivKey );

int VNRsa_ORG_PrivEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText );

int VNRsa_ORG_PubDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText );

int VNRsa_ORG_PubEncrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * plainText, int length,
	struct iovec * cipherText );

int VNRsa_ORG_PrivDecrypt( const VNAsymCryptCtx_t * ctx,
	const unsigned char * cipherText, int length,
	struct iovec * plainText );

