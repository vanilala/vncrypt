#pragma once

#include "vndefine.h"

#include "lip.h"

void VN_LIP_dump_hex( verylong za, struct vn_iovec * hex );

void VN_LIP_load_hex( const struct vn_iovec * hex, verylong * za );

void VN_LIP_dump_bin( verylong za, struct vn_iovec * bin );

void VN_LIP_load_bin( const unsigned char * ptr, int length, verylong * za );
