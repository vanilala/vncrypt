
#pragma once

#include "vnasymcrypt.h"

#include <stdio.h>

typedef struct tagVNTestArgs {
        int mArgc;
        const char ** mArgv;

	int mKeyBits;
	int mLength;
	unsigned char mInitValue;
	int mEncryptCount;
	int mDecryptCount;
} VNTestArgs_t;

typedef struct tagVNTestEnv {
	void ( * mTestMain ) ( VNTestArgs_t * args );

	VNAsymCryptCtx_t * ( * mSignCtxNew )();
	void ( * mSignCtxFree )( VNAsymCryptCtx_t * ctx );

	VNAsymCryptCtx_t * ( * mEncCtxNew )();
	void ( * mEncCtxFree )( VNAsymCryptCtx_t * ctx );
} VNTestEnv_t;

int VN_Test( int argc, const char * argv[], VNTestEnv_t * env );

void VN_Run( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args );

double VN_RunTime( unsigned long long prevUsec, unsigned long long * nowUsec );

void VN_PrintKey( VNAsymCryptCtx_t * ctx );

