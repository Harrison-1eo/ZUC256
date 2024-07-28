#ifndef _ZUC256_SK_H_
#define _ZUC256_SK_H_

#include <stdio.h>
#include <immintrin.h>
typedef unsigned char u8;
typedef unsigned int u32;

typedef struct {
    u8 key[32];
    u8 iv[25];
	long long LFSR_S[20];
	long long BRC_X[4];
    long long F_R[2];
} ZUC256_SK_AVX512_State;

void ZUC256_SK_AVX512_Setup();
void ZUC256_SK_AVX512_Init(ZUC256_SK_AVX512_State* state, u8* const k, u8* const iv);
void ZUC256_SK_AVX512_Gene(ZUC256_SK_AVX512_State* state, u32* keystream, u32 keylen);

#endif
