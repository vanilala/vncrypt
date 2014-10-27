#pragma once

#include "vndefine.h"

#ifdef __cplusplus
extern "C" {
#endif

void VN_CTP_dump_hex( void * integer, struct vn_iovec * hex );

void VN_CTP_load_hex( const struct vn_iovec * hex, void * integer );

#ifdef __cplusplus
};
#endif

