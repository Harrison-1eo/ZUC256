#include "zuc.h"

static uint8 S0[256] = {
        0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
        0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
        0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
        0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
        0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
        0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
        0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
        0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
        0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
        0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
        0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
        0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
        0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
        0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
        0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
        0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60
        };

static uint8 S1[256] = {
        0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
        0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
        0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
        0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
        0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
        0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
        0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
        0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
        0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
        0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
        0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
        0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
        0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
        0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
        0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
        0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2
        };

static uint8 d[16] = {
        0x22, 0x2f, 0x24, 0x2a, 
        0x6d, 0x40, 0x40, 0x40,
        0x40, 0x40, 0x40, 0x40, 
        0x40, 0x52, 0x10, 0x30
        };

void BitReconstruction(uint32* const LFSR,uint32* const X)
{
    X[0] = ((LFSR[15] & 0x7fff8000) << 1) | (LFSR[14] & 0xffff);
    X[1] = (LFSR[11] << 16) | (LFSR[9] >> 15);
    X[2] = (LFSR[7] << 16) | (LFSR[5] >> 15);
    X[3] = (LFSR[2] << 16) | (LFSR[0] >> 15);
}

uint32 S(uint32 a)
{
    uint8 x[4] = {0}, y[4] = {0};
    uint32 b = 0;
    int i = 0, row = 0, line = 0;
    x[0] = a >> 24;
    x[1] = (a >> 16) & 0xff;
    x[2] = (a >> 8) & 0xff;
    x[3] = a & 0xff;
    for (i = 0; i < 4; i++)
    {
        //row = x[i] >> 4;
        //line = x[i] & 0xf;
        if (i == 0 || i == 2)
            y[i] = S0[x[i]];
        else
            y[i] = S1[x[i]];
    }
    b = (y[0] << 24) | (y[1] << 16) | (y[2] << 8) | y[3];
    return b;
}

uint32 Rot(uint32 x, int move)
{
    return ((x << move) | (x >> (32 - move)));
}

uint32 L1(uint32 x)
{
    return (x ^ Rot(x, 2) ^ Rot(x, 10) ^ Rot(x, 18) ^ Rot(x, 24));
}

uint32 L2(uint32 x)
{
    return (x ^ Rot(x, 8) ^ Rot(x, 14) ^ Rot(x, 22) ^ Rot(x, 30));
}

void F(uint32 *W, uint32 *R1, uint32 *R2, uint32* const X)
{
    uint32 W1 = 0, W2 = 0;
    uint32 tmp1 = 0, tmp2 = 0;
    *W = (X[0] ^ (*R1)) + (*R2);
    W1 = (*R1) + X[1];
    W2 = (*R2) ^ X[2];
    *R1 = S(L1((W1 << 16) | (W2 >> 16)));
    *R2 = S(L2((W2 << 16) | (W1 >> 16)));
}

uint32 mod_add(uint32 a, uint32 b)
{
    uint32 c = a + b;
    c = (c & 0x7fffffff) + (c >> 31);
    return c;
}

uint32 mod_2exp_mul(uint32 x, int exp)
{
    return ((x << exp) | (x >> (31 - exp))) & 0x7fffffff;
}



void Key_IV_Insert(uint8* const k, uint8* const iv, uint32* const LFSR)
{
    //S组成方式1
    LFSR[0]=(k[0]<<23)|(d[0]<<16)|(k[21]<<8)|(k[16]);
    LFSR[1]=(k[1]<<23)|(d[1]<<16)|(k[22]<<8)|(k[17]);
    LFSR[2]=(k[2]<<23)|(d[2]<<16)|(k[23]<<8)|(k[18]);
    LFSR[3]=(k[3]<<23)|(d[3]<<16)|(k[24]<<8)|(k[19]);
    LFSR[4]=(k[4]<<23)|(d[4]<<16)|(k[25]<<8)|(k[20]);
    //S组成方式2
    LFSR[5]=(iv[0]<<23)|((d[5]|iv[17])<<16)|(k[5]<<8)|(k[26]);
    LFSR[6]=(iv[1]<<23)|((d[6]|iv[18])<<16)|(k[6]<<8)|(k[27]);
    //S组成方式3
    LFSR[7]=(iv[10]<<23)|((d[7]|iv[19])<<16)|(k[7]<<8)|(iv[2]);
    //S组成方式4
    LFSR[8]=(k[8]<<23)|((d[8]|iv[20])<<16)|(iv[3]<<8)|(iv[11]);
    LFSR[9]=(k[9]<<23)|((d[9]|iv[20])<<16)|(iv[12]<<8)|(iv[4]);
    //S组成方式2
    LFSR[10]=(iv[5]<<23)|((d[10]|iv[22])<<16)|(k[10]<<8)|(k[28]);
    //S组成方式4
    LFSR[11]=(k[11]<<23)|((d[11]|iv[23])<<16)|(iv[6]<<8)|(iv[13]);
    LFSR[12]=(k[12]<<23)|((d[12]|iv[24])<<16)|(iv[7]<<8)|(iv[14]);
    //S组成方式5
    LFSR[13]=(k[13]<<23)|(d[13]<<16)|(iv[15]<<8)|(iv[8]);
    //S组成方式6
    LFSR[14]=(k[14]<<23)|((d[14]|(k[31]>>4))<<16)|(iv[16]<<8)|(iv[9]);
    LFSR[15]=(k[15]<<23)|((d[15]|(k[31] & 0xf))<<16)|(iv[16]<<8)|(iv[9]);

}

void LFSRWithInitMode(uint32* const LFSR, uint32 u)
{
    uint32 v = 0, tmp = 0, i = 0, s16=0;

    v = LFSR[0];//s0

    tmp = mod_2exp_mul(LFSR[0], 8);
    v = mod_add(v, tmp);//s0+2^8*s0

    tmp = mod_2exp_mul(LFSR[4], 20);
    v = mod_add(v, tmp);//s0+2^8*s0+2^20*s4

    tmp = mod_2exp_mul(LFSR[10], 21);
    v = mod_add(v, tmp);//s0+2^8*s0+2^20*s4+2^21*s10

    tmp = mod_2exp_mul(LFSR[13], 17);
    v = mod_add(v, tmp);//s0+2^8*s0+2^20*s4+2^21*s10+2^17*s13

    tmp = mod_2exp_mul(LFSR[15], 15);
    v = mod_add(v, tmp);//s0+2^8*s0+2^20*s4+2^21*s10+2^17*s13+2^15*s15

    if (v == 0)
    {
        v = 0x7fffffff;
    }
    
    s16 = mod_add(v, u);
    
    if (s16 == 0)
    {
        s16 = 0x7fffffff;
    }
    
    for (i = 0; i < 15; i++)
    {
        LFSR[i] = LFSR[i + 1];
    }
    LFSR[15] = s16;
}

void LFSRWithWorkMode(uint32* const LFSR)
{
    uint32 s16 = 0, tmp = 0, i = 0;

    s16 = LFSR[0];//s0

    tmp = mod_2exp_mul(LFSR[0], 8);
    s16 = mod_add(s16, tmp);//s0+2^8*s0

    tmp = mod_2exp_mul(LFSR[4], 20);
    s16 = mod_add(s16, tmp);//s0+2^8*s0+2^20*s4

    tmp = mod_2exp_mul(LFSR[10], 21);
    s16 = mod_add(s16, tmp);//s0+2^8*s0+2^20*s4+2^21*s10

    tmp = mod_2exp_mul(LFSR[13], 17);
    s16 = mod_add(s16, tmp);//s0+2^8*s0+2^20*s4+2^21*s10+2^17*s13

    tmp = mod_2exp_mul(LFSR[15], 15);
    s16 = mod_add(s16, tmp);//s0+2^8*s0+2^20*s4+2^21*s10+2^17*s13+2^15*s15

    if (s16 == 0)
        s16 = 0x7fffffff;

    for (i = 0; i < 15; i++)
    {
        LFSR[i] = LFSR[i + 1];
    }    
    LFSR[15] = s16;
}


void ZUC_Init(ZUC_State* state, uint8* const k, uint8* const iv)
{
    for (int i = 0; i < 32; i++)
    {
        state->key[i] = k[i];
    }
    for (int i = 0; i < 25; i++)
    {
        state->iv[i] = iv[i];
    }
    for (int i = 0; i < 16; i++)
    {
        state->LFSR[i] = 0;
    }
    for (int i = 0; i < 4; i++)
    {
        state->X[i] = 0;
    }
    state->R1 = 0;
    state->R2 = 0;

    Key_IV_Insert(k, iv, state->LFSR);
    uint32 i = 0, u = 0;
    for (i = 0; i < 32; i++)
    {
        BitReconstruction(state->LFSR, state->X);
        F(&(state->W), &(state->R1), &(state->R2), state->X);
        u = (state->W)>>1;
        LFSRWithInitMode(state->LFSR, u);
    }
    BitReconstruction(state->LFSR, state->X);
    F(&(state->W), &(state->R1), &(state->R2), state->X);
    LFSRWithWorkMode(state->LFSR);
}

void ZUC_Gene(ZUC_State* state, uint32* keystream, uint32 keylen)
{
    uint32 Z = 0, i = 0;
    for (i = 0; i < keylen; i++)
    {
        BitReconstruction(state->LFSR, state->X);
        F(&(state->W), &(state->R1), &(state->R2), state->X);
        keystream[i] = state->W ^ state->X[3];
        LFSRWithWorkMode(state->LFSR);
    }
}

