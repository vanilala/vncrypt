#pragma once

#include "vndefine.h"

#ifdef __cplusplus
extern "C" {
#endif

void VN_Botan_dump_hex( const void * za, struct vn_iovec * hex );
void VN_Botan_load_hex( const struct vn_iovec * hex, void * za );

void VN_Botan_dump_bin( const void * za, struct vn_iovec * bin );

#ifdef __cplusplus
};
#endif
