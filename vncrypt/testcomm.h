
#pragma once

#include "vnasymcrypt.h"

void VN_Test( VNAsymCryptCtx_t * ctx, int keyBits,
	long length, int value, int encryptCount, int decryptCount );

