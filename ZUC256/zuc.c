//
//  zuc.c
//  ZUC256
//
//  Created by Harrison Lee on 2024/3/17.
//

#include "zuc.h"

#define left_rotate(x, n) ((x << n) | (x >> (32 - n)))
#define multi_add_mod(a, b) ((1 << b) * s[a] + v) % (1 << 31 - 1)

u8 key[32];
u8 iv[32];

u32 s[17] = {0};
u32 x[4] = {0};
u32 r1 = 0;
u32 r2 = 0;

void initialization (u8 *k, u8 *iv){
    for (int i = 0; i < 32; i++){
        key[i] = k[i];
        iv[i] = iv[i];
    }
    load_LFSR();
    r1 = r2 = 0;

    u32 w = 0;
    for (int i = 0; i < 32; i++){
        bit_reorganization();
        w = F(x[0], x[1], x[2]);
        LFSR_with_initialization_mode(w >> 1);
    }
    bit_reorganization();
    w = F(x[0], x[1], x[2]);
    LFSR_with_work_mode();
}

u32 key_stream_generator(void){
    bit_reorganization();
    u32 w = F(x[0], x[1], x[2]);
    LFSR_with_work_mode();
    return w ^ x[3];
}

// 输入4个u8，将四个字符的比特连接起来得到一个u32
u32 link_char_to_int(u8 a, u8 b, u8 c, u8 d){
    u32 result = 0;
    result = (a << 24) | (b << 16) | (c << 8) | d;
    return result;
}

// 输入两个u32 和两个左右指示符，
// 将两个u32的高16比特或者低16比特连接起来得到一个u32
u32 link_int_to_int(u32 a, char a_pos, u32 b, char b_pos){
    u32 result = 0;
    if (a_pos == 'L'){
        result = (a & 0x0000FFFF);
    } else if (a_pos == 'H'){
        result = (a & 0xFFFF0000);
    }

    if (b_pos == 'L'){
        result = result | (b & 0x0000FFFF);
    } else if (b_pos == 'H'){
        result = result | (b & 0xFFFF0000);
    }
    return result;
}

void load_LFSR (void){
    s[0] = link_char_to_int(key[0], d[0], key[21], key[16]);
    s[1] = link_char_to_int(key[1], d[1], key[22], key[17]);
    s[2] = link_char_to_int(key[2], d[2], key[23], key[18]);
    s[3] = link_char_to_int(key[3], d[3], key[24], key[19]);
    s[4] = link_char_to_int(key[4], d[4], key[25], key[20]);
    s[5] = link_char_to_int(iv[0], (d[5] | iv[17]), key[5], key[26]);
    s[6] = link_char_to_int(iv[1], (d[6] | iv[18]), key[6], key[27]);
    s[7] = link_char_to_int(iv[10], (d[7] | iv[19]), key[7], iv[2]);
    s[8] = link_char_to_int(key[8], (d[8] | iv[20]), iv[3], iv[11]);
    s[9] = link_char_to_int(key[9], (d[9] | iv[21]), iv[12], iv[4]);
    s[10] = link_char_to_int(iv[5], (d[10] | iv[22]), key[10], key[28]);
    s[11] = link_char_to_int(key[11], (d[11] | iv[23]), iv[6], iv[13]);
    s[12] = link_char_to_int(key[12], (d[12] | iv[24]), iv[7], iv[14]);
    s[13] = link_char_to_int(key[13], d[13], iv[15], iv[8]);
    s[14] = link_char_to_int(key[14], (d[14] | (key[31] & 0b11110000)), iv[16], iv[9]);
    s[15] = link_char_to_int(key[15], (d[15] | (key[31] & 0b00001111)), key[30], key[29]);
}

void bit_reorganization(void){
    x[0] = link_int_to_int(s[15], 'H', s[15], 'L');
    x[1] = link_int_to_int(s[11], 'L', s[9], 'H');
    x[2] = link_int_to_int(s[7], 'L', s[5], 'H');
    x[3] = link_int_to_int(s[2], 'L', s[0], 'H');
}

u32 S (u32 x){
    u8 bit8[4] = {0};
    u8 result[4] = {0};
    bit8[0] = x >> 24;
    bit8[1] = (x >> 16) & 0xff;
    bit8[2] = (x >> 8) & 0xff;
    bit8[3] = x & 0xff;
    for (int i = 0; i < 4; i++){
        u8 row = bit8[i] >> 4;
        u8 nuw = bit8[i] & 0xf;
        if (i == 0 || i == 2){
            result[i] = S0[row][nuw];
        } else {
            result[i] = S1[row][nuw];
        }
    }
    u32 ans = (result[0] << 24) | (result[1] << 16) | (result[2] << 8) | result[3];
}

u32 L1 (u32 x){
    return x ^ left_rotate(x, 2) ^ left_rotate(x, 10) ^ left_rotate(x, 18) ^ left_rotate(x, 24);
}

u32 L2 (u32 x){
    return x ^ left_rotate(x, 8) ^ left_rotate(x, 14) ^ left_rotate(x, 22) ^ left_rotate(x, 30);
}

u32 F (u32 x0, u32 x1, u32 x2){
    u32 w, w1, w2;
    w = (x[0] ^ r1) + r2;
    w1 = r1 + x[1];
    w2 = r2 ^ x[2];
    r1 = S(L1(link_int_to_int(w1, 'L', w2, 'H')));
    r2 = S(L2(link_int_to_int(w2, 'L', w1, 'H')));
    return w;
}

void LFSR_with_initialization_mode(u32 u){
    u32 v = s[0];
    v = multi_add_mod(0, 8);
    v = multi_add_mod(4, 20);
    v = multi_add_mod(10, 21);
    v = multi_add_mod(13, 17);
    v = multi_add_mod(15, 15);
    if (v == 0)
        v = 1 << 31 - 1;

    s[16] = (u + v) % (1 << 31 - 1);
    if (s[16] == 0)
        s[16] = 1 << 31 - 1;

    // s16, s15,..., s1 -> s15, s14,..., s0
    for (int i = 15; i >= 0; i--){
        s[i] = s[i + 1];
    }
    return;
}

void LFSR_with_work_mode(void){
    u32 v = 0;
    v = multi_add_mod(0, 8);
    v = multi_add_mod(4, 20);
    v = multi_add_mod(10, 21);
    v = multi_add_mod(13, 17);
    v = multi_add_mod(15, 15);

    s[16] = v;
    if (s[16] == 0)
        s[16] = 1 << 31 - 1;

    // s16, s15,..., s1 -> s15, s14,..., s0
    for (int i = 15; i >= 0; i--){
        s[i] = s[i + 1];
    }
    return;
}



