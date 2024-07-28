#ifndef zuc_sk_h
#define zuc_sk_h


#include <stdlib.h>

typedef unsigned int uint32;
typedef unsigned char uint8;

typedef struct {
    uint8 key[32];
    uint8 iv[25];
    uint32 LFSR[16];
    uint32 X[4];
    uint32 R1, R2;
    uint32 W;
} ZUC_State;

void ZUC_Init(ZUC_State* state, uint8* const k, uint8* const iv);
void ZUC_Gene(ZUC_State* state, uint32* keystream, uint32 keylen);

#endif /* zuc_sk_h */