#pragma once

#include "vndefine.h"

/* asymmetric cryptography */

int VNAsymCryptGenKeys( VNAsymCryptCtx_t * ctx, int keyBits );

void VNAsymCryptClearKeys( VNAsymCryptCtx_t * ctx );

int VNAsymCryptDumpPubKey( const VNAsymCryptCtx_t * ctx,
		struct vn_iovec * hexPubKey );

int VNAsymCryptDumpPrivKey( const VNAsymCryptCtx_t * ctx,
		struct vn_iovec * hexPubKey, struct vn_iovec * hexPrivKey );

int VNAsymCryptLoadPubKey( VNAsymCryptCtx_t * ctx,
		const struct vn_iovec * hexPubKey );

int VNAsymCryptLoadPrivKey( VNAsymCryptCtx_t * ctx,
		const struct vn_iovec * hexPubKey, const struct vn_iovec * hexPrivKey );

int VNAsymCryptPrivEncrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

int VNAsymCryptPubDecrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText );

int VNAsymCryptPubEncrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

int VNAsymCryptPrivDecrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, int length,
		struct vn_iovec * plainText );

/* helper function */

void VNIovecPrint( const char * prompt, struct vn_iovec * head );

void VNIovecFreeBufferAndTail( struct vn_iovec * head );

void VNIovecGetRandomBuffer( struct vn_iovec * head, int length );

