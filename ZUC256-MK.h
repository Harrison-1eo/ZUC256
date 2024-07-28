#ifndef _ZUC256_MK_H_
#define _ZUC256_MK_H_

#include <stdio.h>
#include <immintrin.h>
typedef unsigned char u8;
typedef unsigned int u32;

typedef struct {
	__m512i LFSR_S[16];		// 16个512 ZMM
	__m512i F_R[2];
	__m512i BRC_X[4];
} ZUC256_MK_AVX512_State;

void ZUC256_MK_AVX512_Setup();
void ZUC256_MK_AVX512_Init(ZUC256_MK_AVX512_State *state, u32 *ks, int wordlen, const u8 *k, const u8 *iv);
void ZUC256_MK_AVX512_Gene(ZUC256_MK_AVX512_State* state, u32* keystream, u32 keylen);
void ZUC256_MK_AVX512_Mac (ZUC256_MK_AVX512_State *state, u32 *MAC, int MAC_BITLEN, const u32 *M, const u32 LENGTH);

#endif
