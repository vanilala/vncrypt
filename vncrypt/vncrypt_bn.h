#pragma once

#include "vnasymcrypt.h"

#include <openssl/bn.h>
#include <sys/uio.h>

int VN_BN_jacobi( const BIGNUM *za, const BIGNUM *zn, int *jacobi, BN_CTX *ctx );

void VN_BN_dump_hex( const BIGNUM * za, struct vn_iovec * hex );
void VN_BN_load_hex( const struct vn_iovec * hex, BIGNUM * za );

