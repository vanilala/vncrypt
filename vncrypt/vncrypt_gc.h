#pragma once

#include "vndefine.h"

#include <gcrypt.h>

unsigned long VN_gcry_mpi_mod_ui( const gcry_mpi_t za, unsigned long m );

int VN_gcry_mpi_jacobi( const gcry_mpi_t za, const gcry_mpi_t zn, int *jacobi );

void VN_GC_dump_hex( const gcry_mpi_t za, struct vn_iovec * hex );

void VN_GC_dump_bin( const gcry_mpi_t za, struct vn_iovec * bin );

