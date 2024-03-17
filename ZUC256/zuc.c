//
//  zuc.c
//  ZUC256
//
//  Created by Harrison Lee on 2024/3/17.
//

#include "zuc.h"

uchar d[16] = {
    0b0100010, 0b0101111, 0b0100100, 0b0101010,
    0b1101101, 0b1000000, 0b1000000, 0b1000000,
    0b1000000, 0b1000000, 0b1000000, 0b1000000,
    0b1000000, 0b1010010, 0b0010000, 0b0110000
};

uchar key[32];
uchar iv[32];

uint s[16] = {0};
uint x[4] = {0};
uint r1 = 0;
uint r2 = 0;

// 输入4个uchar，将四个字符的比特连接起来得到一个uint
uint link_char_to_int(uchar a, uchar b, uchar c, uchar d){
    uint result = 0;
    result = (a << 24) | (b << 16) | (c << 8) | d;
    return result;
}

// 输入两个uint 和两个左右指示符，
// 将两个uint的高16比特或者低16比特连接起来得到一个uint
uint link_int_to_int(uint a, char a_pos, uint b, char b_pos){
    uint result = 0;
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

uint S (uint x){
    // S盒，待补充
    return 0;
}

uint L1 (uint x){
    // L1，待补充
    return 0;
}

uint L2 (uint x){
    // L2，待补充
    return 0;
}

uint F (uint x0, uint x1, uint x2){
    uint w, w1, w2;
    w = (x[0] ^ r1) + r2;
    w1 = r1 + x[1];
    w2 = r2 ^ x[2];
    r1 = S(L1(link_int_to_int(w1, 'L', w2, 'H')));
    r2 = S(L2(link_int_to_int(w2, 'L', w1, 'H')));
    return w;
}

void LFSR_with_initialization_mode(uint u){
    // 待补充
    return;
}

void LFSR_with_work_mode(void){
    // 待补充
    return;
}

void initialization (uchar *k, uchar *iv){
    for (int i = 0; i < 32; i++){
        key[i] = k[i];
        iv[i] = iv[i];
    }
    load_LFSR();
    r1 = r2 = 0;

    uint w = 0;
    for (int i = 0; i < 32; i++){
        bit_reorganization();
        w = F(x[0], x[1], x[2]);
        LFSR_with_initialization_mode(w >> 1);
    }
    bit_reorganization();
    w = F(x[0], x[1], x[2]);
    LFSR_with_work_mode();
}

