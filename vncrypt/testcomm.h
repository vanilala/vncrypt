
#pragma once

#include "vnasymcrypt.h"

#include <stdio.h>

typedef struct tagVNTestArgs {
        int mArgc;
        const char ** mArgv;

	int mE;
	int mDebug;
	int mKeyBits;
	int mLength;
	int mSrcType;
	int mRunSeconds;
} VNTestArgs_t;

typedef struct tagVNTestEnv {
	void ( * mTestMain ) ( VNTestArgs_t * args );

	VNAsymCryptCtx_t * ( * mSignCtxNew )();
	VNAsymCryptCtx_t * ( * mEncCtxNew )();
} VNTestEnv_t;

typedef struct tagVNTestFunc {
	int mIsSign;

	const char * mEncryptName;
	int ( * mEncrypt ) ( const VNAsymCryptCtx_t * , const unsigned char * ,
		int , struct vn_iovec * );

	const char * mDecryptName;
	int ( * mDecrypt ) ( const VNAsymCryptCtx_t * , const unsigned char * ,
		const int , struct vn_iovec * , const int );

	int ( * mVerify ) ( const VNAsymCryptCtx_t * , const unsigned char * ,
		const int , const struct vn_iovec * );
} VNTestFunc_t;

int VN_Test( int argc, const char * argv[], VNTestEnv_t * env );

void VN_Run( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args );
void VN_Run_Impl( VNAsymCryptCtx_t * ctx, VNTestArgs_t * args, VNTestFunc_t * func );

void VN_GenSrc( VNTestArgs_t * args, struct vn_iovec * src );

double VN_RunTime( unsigned long long prevUsec, unsigned long long * nowUsec );

void VN_PrintKey( VNAsymCryptCtx_t * ctx );

