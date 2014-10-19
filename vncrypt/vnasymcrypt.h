#pragma once

#include "vndefine.h"

/* asymmetric cryptography */

void VNAsymCryptCtxFree( VNAsymCryptCtx_t * ctx );

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

/* Public-key encryption */

int VNAsymCryptPubEncrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

int VNAsymCryptPrivDecrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, const int length,
		struct vn_iovec * plainText, const int fillUpLength );

/* Digital signature schemes with message recovery */

int VNAsymCryptPrivEncrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * cipherText );

int VNAsymCryptPubDecrypt( const VNAsymCryptCtx_t * ctx,
		const unsigned char * cipherText, const int length,
		struct vn_iovec * plainText, const int fillUpLength );

/* Digital signature schemes with appendix */

int VNAsymCryptSign( const VNAsymCryptCtx_t * ctx,
		const unsigned char * plainText, int length,
		struct vn_iovec * signText );

int VNAsymCryptVerify( const VNAsymCryptCtx_t * ctx,
		const unsigned char * signText, const int length,
		const struct vn_iovec * plainText );

/* helper function */

void VNIovecPrint( const char * prompt, const struct vn_iovec * head, int toHex );

void VNIovecFreeBufferAndTail( struct vn_iovec * head );

void VNIovecGetRandomBuffer( struct vn_iovec * head, int length );

