#pragma once

#include "vndefine.h"

#include <gmp.h>

void VN_GMP_dump_hex( const mpz_t za, struct vn_iovec * hex );
void VN_GMP_load_hex( const struct vn_iovec * hex, mpz_t za );

void VN_GMP_dump_bin( const mpz_t za, struct vn_iovec * bin );
