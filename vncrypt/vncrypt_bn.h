#pragma once

#include "vndefine.h"

#include <openssl/bn.h>

int VN_BN_jacobi( const BIGNUM *za, const BIGNUM *zn, int *jacobi, BN_CTX *ctx );
void VN_BN_gcdext( const BIGNUM * za, const BIGNUM * zb,
	BIGNUM * zx, BIGNUM * zy, BIGNUM * gcd, BN_CTX * ctx );
int VN_BN_jacobi( const BIGNUM *za, const BIGNUM *zn, int *jacobi, BN_CTX *ctx );

int VN_BN_lcm( BIGNUM * zr,const BIGNUM * za,const BIGNUM * zb,BN_CTX * ctx );

void VN_BN_dump_hex( const BIGNUM * za, struct vn_iovec * hex );
void VN_BN_load_hex( const struct vn_iovec * hex, BIGNUM * za );

void VN_BN_dump_bin( const BIGNUM * za, struct vn_iovec * bin );

void VN_BN_bin2hex( const unsigned char * bin, int length, struct vn_iovec * hex );
void VN_BN_hex2bin( const unsigned char * hex, int length, struct vn_iovec * bin );

