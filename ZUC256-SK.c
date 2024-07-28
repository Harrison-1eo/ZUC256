#include "ZUC256-SK.h"

#define P1_MASK_128 0x09030507, 0x0C000400, 0x0A020F0F, 0x0E000F09 // P1的128bit定义
#define P2_MASK_128 0x0209030F, 0x0A0E010B, 0x040C0007, 0x05060D08 // P2的128bit定义
#define P3_MASK_128 0x0D0C0900, 0x050D0303, 0x0F0A0D00, 0x060A0602 // P3的128bit定义
#define P1_MASK P1_MASK_128, P1_MASK_128, P1_MASK_128, P1_MASK_128 // P1的512bit定义，用于适应寄存器
#define P2_MASK P2_MASK_128, P2_MASK_128, P2_MASK_128, P2_MASK_128 // P2的512bit定义，用于适应寄存器
#define P3_MASK P3_MASK_128, P3_MASK_128, P3_MASK_128, P3_MASK_128 // P3的512bit定义，用于适应寄存器
__m512i p1_mask;												   // 512 ZMM
__m512i p2_mask;
__m512i p3_mask;

#define LOWER_NIBBLE_MASK 0x0F // 低4bit
#define LOWER_5BITS_MASK 0x1F  // 低5bit
#define HIGHER_3BITS_MASK 0xE0 // 高3bit
__m512i lower_nibble_mask;
__m512i lower_5bits_mask;
__m512i higher_3bits_mask;

#define RIGHT_1BIT_MASK 0x55
#define LEFT_1BIT_MASK 0xAA
#define RIGHT_2BITS_MASK 0x33
#define LEFT_2BITS_MASK 0xCC
#define RIGHT_4BITS_MASK 0x0F
#define LEFT_4BITS_MASK 0xF0
#define RIGHT_8BITS_MASK 0x00FF
#define LEFT_8BITS_MASK 0xFF00
__m512i right_1bit_mask;
__m512i left_1bit_mask;
__m512i right_2bits_mask;
__m512i left_2bits_mask;
__m512i right_4bits_mask;
__m512i left_4bits_mask;
__m512i right_8bits_mask;
__m512i left_8bits_mask;

#define K_MUL_MASK1_128 0xD3D20A0B, 0xB8B96160, 0xB3B26A6B, 0xD8D90100
#define K_MUL_MASK2_128 0x29AB63E1, 0xEE6CA426, 0x0F8D45C7, 0xC84A8200
#define K_MUL_MASK1 K_MUL_MASK1_128, K_MUL_MASK1_128, K_MUL_MASK1_128, K_MUL_MASK1_128
#define K_MUL_MASK2 K_MUL_MASK2_128, K_MUL_MASK2_128, K_MUL_MASK2_128, K_MUL_MASK2_128
__m512i k_mul_mask1;
__m512i k_mul_mask2;

#define T_MUL_MASK1_128 0x5B867FA2, 0xA479805D, 0x538E77AA, 0xAC718855
#define T_MUL_MASK2_128 0x47DE73EA, 0x33AA079E, 0xD940ED74, 0xAD349900
#define T_MUL_MASK1 T_MUL_MASK1_128, T_MUL_MASK1_128, T_MUL_MASK1_128, T_MUL_MASK1_128
#define T_MUL_MASK2 T_MUL_MASK2_128, T_MUL_MASK2_128, T_MUL_MASK2_128, T_MUL_MASK2_128
__m512i t_mul_mask1;
__m512i t_mul_mask2;

#define AES_SHUF_MASK_128 0x0306090c, 0x0f020508, 0x0b0e0104, 0x070a0d00
#define AES_SHUF_MASK AES_SHUF_MASK_128, AES_SHUF_MASK_128, AES_SHUF_MASK_128, AES_SHUF_MASK_128
#define AES_CONST_KEY 0x63
__m512i aes_const_key;

#define MBP_MASK 0x7FFFFFFF
__m512i mbp_mask;

__m512i shuffle_mask;
__m512i F1_mx[2];
__m512i F2_mx[2];
__m512i G1_mx[2];
__m512i G2_mx[2];

static const u8 EK_d[16] =
	{
		0x22, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30};

/* the constants MAC d */
static const u8 EK_d_MAC[3 * 16] =
	{
		0x22, 0x2F, 0x25, 0x2A, 0x6D, 0x40, 0x40, 0x40,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
		0x23, 0x2F, 0x24, 0x2A, 0x6D, 0x40, 0x40, 0x40,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30,
		0x23, 0x2F, 0x25, 0x2A, 0x6D, 0x40, 0x40, 0x40,
		0x40, 0x40, 0x40, 0x40, 0x40, 0x52, 0x10, 0x30};

int SetupSign = 0;

/* ========== 1. 初始化填充优化 ========== */
void ZUC256_SK_AVX512_Setup()
{
	if (SetupSign == 1)
		return;

	p1_mask = _mm512_set_epi32(P1_MASK); // P1存入寄存器
	p2_mask = _mm512_set_epi32(P2_MASK);
	p3_mask = _mm512_set_epi32(P3_MASK);

	lower_nibble_mask = _mm512_set1_epi8(LOWER_NIBBLE_MASK); // 将64*0x0F存入寄存器
	lower_5bits_mask = _mm512_set1_epi8(LOWER_5BITS_MASK);	 // 将64*0x1F存入寄存器
	higher_3bits_mask = _mm512_set1_epi8(HIGHER_3BITS_MASK); // 将64*0xE0存入寄存器

	right_1bit_mask = _mm512_set1_epi8(RIGHT_1BIT_MASK);	// 将64*0x55存入寄存器
	left_1bit_mask = _mm512_set1_epi8(LEFT_1BIT_MASK);		// 将64*0xAA存入寄存器
	right_2bits_mask = _mm512_set1_epi8(RIGHT_2BITS_MASK);	// 将64*0x33存入寄存器
	left_2bits_mask = _mm512_set1_epi8(LEFT_2BITS_MASK);	// 将64*0xCC存入寄存器
	right_4bits_mask = _mm512_set1_epi8(RIGHT_4BITS_MASK);	// 将64*0x0F存入寄存器
	left_4bits_mask = _mm512_set1_epi8(LEFT_4BITS_MASK);	// 将64*0xF0存入寄存器
	right_8bits_mask = _mm512_set1_epi16(RIGHT_8BITS_MASK); // 将32*0x00FF存入寄存器
	left_8bits_mask = _mm512_set1_epi16(LEFT_8BITS_MASK);	// 将32*0xFF00存入寄存器

	k_mul_mask1 = _mm512_set_epi32(K_MUL_MASK1);	// K1存入
	k_mul_mask2 = _mm512_set_epi32(K_MUL_MASK2);	// K2存入
	t_mul_mask1 = _mm512_set_epi32(T_MUL_MASK1);	// T1
	t_mul_mask2 = _mm512_set_epi32(T_MUL_MASK2);	// T2
	shuffle_mask = _mm512_set_epi32(AES_SHUF_MASK); // AES的行移位
	// aes_const_key = V1SET1B(AES_CONST_KEY);		// AES的轮密钥
	F1_mx[0] = _mm512_set_epi32(0x2000a0, 0x100050, 0x80028, 0x40014, 0x2000a, 0x10005, 0x800002, 0x400001, 0x200080, 0x100040, 0x80020, 0x40010, 0x20008, 0x10004, 0x800082, 0x400041);
	F1_mx[1] = _mm512_set_epi32(0x80000200, 0x40000100, 0xa0008000, 0x50004000, 0x28002000, 0x14001000, 0xa000800, 0x5000400, 0x2008200, 0x1004100, 0x80002000, 0x40001000, 0x20000800, 0x10000400, 0x8000200, 0x4000100);
	F2_mx[0] = _mm512_set_epi32(0x2008000, 0x1004000, 0x8000a000, 0x40005000, 0x20002800, 0x10001400, 0x8000a00, 0x4000500, 0x82000200, 0x41000100, 0x20008000, 0x10004000, 0x8002000, 0x4001000, 0x2000800, 0x1000400);
	F2_mx[1] = _mm512_set_epi32(0xa00020, 0x500010, 0x280008, 0x140004, 0xa0002, 0x50001, 0x20080, 0x10040, 0x800020, 0x400010, 0x200008, 0x100004, 0x80002, 0x40001, 0x820080, 0x410040);
	G1_mx[0] = _mm512_set_epi32(0x800020, 0x5b00e6, 0x5600b5, 0x860081, 0x10050, 0xd20094, 0x2300f8, 0x640019, 0x2000a0, 0xe600bd, 0xb500e3, 0x810007, 0x500051, 0x940046, 0xf800db, 0x19007d);
	G1_mx[1] = _mm512_set_epi32(0x82000200, 0x99006e00, 0xd5005b00, 0x6001800, 0x40000500, 0x53004900, 0xe0008f00, 0x65009100, 0x80000200, 0xf7006e00, 0x8e005b00, 0x1e001800, 0x45000500, 0x1a004900, 0x6f008f00, 0xf4009100);
	G2_mx[0] = _mm512_set_epi32(0x2008200, 0x6e009900, 0x5b00d500, 0x18000600, 0x5004000, 0x49005300, 0x8f00e000, 0x91006500, 0x2008000, 0x6e00f700, 0x5b008e00, 0x18001e00, 0x5004500, 0x49001a00, 0x8f006f00, 0x9100f400);
	G2_mx[1] = _mm512_set_epi32(0x200080, 0xe6005b, 0xb50056, 0x810086, 0x500001, 0x9400d2, 0xf80023, 0x190064, 0xa00020, 0xbd00e6, 0xe300b5, 0x70081, 0x510050, 0x460094, 0xdb00f8, 0x7d0019);

	aes_const_key = _mm512_set1_epi8(AES_CONST_KEY);

	mbp_mask = _mm512_set_epi32(MBP_MASK, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

	SetupSign = 1;

	return;
}

void ZUC256_SK_AVX512_LFSRINIT(ZUC256_SK_AVX512_State *state, const u8 *k, const u8 *iv, const u8 *d)
{
	__m512i sa, sb, sc;
	sa = _mm512_setr_epi8(
		0, d[0], k[21], k[16],
		0, d[1], k[22], k[17],
		0, d[2], k[23], k[18],
		0, d[3], k[24], k[19],
		0, d[4], k[25], k[20],
		0, d[5] | iv[17], k[5], k[26],
		0, d[6] | iv[18], k[6], k[27],
		0, d[7] | iv[19], k[7], iv[2],
		0, d[8] | iv[20], iv[3], iv[11],
		0, d[9] | iv[21], iv[12], iv[4],
		0, d[10] | iv[22], k[10], k[28],
		0, d[11] | iv[23], iv[6], iv[13],
		0, d[12] | iv[24], iv[7], iv[14],
		0, d[13], iv[15], iv[8],
		0, d[14] | (k[31] >> 4), iv[16], iv[9],
		0, d[15] | (k[31] & 0xF), iv[30], k[29]);
	sb = _mm512_setr_epi8(
		k[0], 0, 0, 0,
		k[1], 0, 0, 0,
		k[2], 0, 0, 0,
		k[3], 0, 0, 0,
		k[4], 0, 0, 0,
		iv[0], 0, 0, 0,
		iv[1], 0, 0, 0,
		iv[10], 0, 0, 0,
		k[8], 0, 0, 0,
		k[9], 0, 0, 0,
		iv[5], 0, 0, 0,
		k[11], 0, 0, 0,
		k[12], 0, 0, 0,
		k[13], 0, 0, 0,
		k[14], 0, 0, 0,
		k[15], 0, 0, 0);
	sb = _mm512_srli_epi32(sb, 1);
	sc = _mm512_setr_epi8(
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, 0, 0, 0,
		0, iv[17], 0, 0,
		0, iv[18], 0, 0,
		0, iv[19], 0, 0,
		0, iv[20], 0, 0,
		0, iv[21], 0, 0,
		0, iv[22], 0, 0,
		0, iv[23], 0, 0,
		0, iv[24], 0, 0,
		0, 0, 0, 0,
		0, k[31] >> 4, 0, 0,
		0, k[31] & 0xF, 0, 0);
	sa = _mm512_or_epi32(sa, sb);
	sa = _mm512_or_epi32(sa, sc);
	int flp = 0;
	long long *pos = (long long *)&sa;
	for (flp = 0; flp < 16; flp++)
	{
		state->LFSR_S[flp] = pos[flp];
	}
	for (flp = 0; flp < 4; flp++)
	{
		state->LFSR_S[flp + 16] = 0;
	}
	state->BRC_X[0] = 0;
	state->BRC_X[1] = 0;
	state->BRC_X[2] = 0;
	state->BRC_X[3] = 0;
	state->F_R[0] = 0;
	state->F_R[1] = 0;
	return;
}

__m512i sbox0(const int input) // S0
{
	__m512i in = _mm512_set1_epi32(input);
	__m512i hi = _mm512_and_si512(_mm512_srli_epi32(in, 4), lower_nibble_mask); //	取出每8bit的高4位
	__m512i low = _mm512_and_si512(in, lower_nibble_mask);						//	取出每8bit的低4位

	__m512i t1 = _mm512_xor_si512(hi, _mm512_shuffle_epi8(p1_mask, low));
	__m512i t2 = _mm512_xor_si512(low, _mm512_shuffle_epi8(p2_mask, t1));
	__m512i t3 = _mm512_xor_si512(t1, _mm512_shuffle_epi8(p3_mask, t2));

	__m512i out = _mm512_or_si512(t2, _mm512_slli_epi32(t3, 4));

	low = _mm512_and_si512(_mm512_srli_epi32(out, 3), lower_5bits_mask);
	hi = _mm512_and_si512(_mm512_slli_epi32(out, 5), higher_3bits_mask);
	return _mm512_xor_si512(hi, low);
}

/* ========== 2. 延迟模约 ========== */
#define V_FEEDBACK(f, v)                                                                                                 \
	v = LFSR_S[0] + (LFSR_S[0] << 8) + (LFSR_S[4] << 20) + (LFSR_S[10] << 21) + (LFSR_S[13] << 17) + (LFSR_S[15] << 15); \
	f = (v & 0x7FFFFFFF) + (v >> 31)

/* ========== 3. S1盒的同构映射实现 ========== */
__m512i sbox1(const int input) // S1
{
	__m512i in = _mm512_set1_epi32(input);
	__m512i y_inv = in, low, hi;

	y_inv = _mm512_aesenclast_epi128(y_inv, aes_const_key);

	low = _mm512_shuffle_epi8(t_mul_mask1, _mm512_and_si512(y_inv, lower_nibble_mask));
	hi = _mm512_shuffle_epi8(t_mul_mask2, _mm512_and_si512(_mm512_srli_epi32(y_inv, 4), lower_nibble_mask));

	return _mm512_xor_si512(low, hi);
}

/* ========== 4. 矩阵乘法进行线性运算 ========== */
void matix_plus(int *c, const long long W1, const long long W2)
{
	__m512i buf1, buf2, c0 = _mm512_setzero_si512();
	__mmask16 k1, k2, k = 0xFFFF;

	k1 = *((unsigned short *)&W1 + 2);
	k2 = *((unsigned short *)&W1 + 3);
	buf1 = _mm512_mask_xor_epi32(c0, k1, c0, F1_mx[0]);
	buf1 = _mm512_mask_xor_epi32(buf1, k2, buf1, F1_mx[1]);
	buf2 = _mm512_mask_xor_epi32(c0, k1, c0, G1_mx[0]);
	buf2 = _mm512_mask_xor_epi32(buf2, k2, buf2, G1_mx[1]);

	k1 = *((unsigned short *)&W2 + 2);
	k2 = *((unsigned short *)&W2 + 3);
	buf1 = _mm512_mask_xor_epi32(buf1, k1, buf1, F2_mx[0]);
	buf1 = _mm512_mask_xor_epi32(buf1, k2, buf1, F2_mx[1]);
	buf2 = _mm512_mask_xor_epi32(buf2, k1, buf2, G2_mx[0]);
	buf2 = _mm512_mask_xor_epi32(buf2, k2, buf2, G2_mx[1]);

	c[0] = _mm512_mask_reduce_xor_epi32(k, buf1);
	c[1] = _mm512_mask_reduce_xor_epi32(k, buf2);
}

#define V_FSM()                       \
	W = (BRC_X[0] ^ F_R[0]) + F_R[1]; \
	W1 = F_R[0] + BRC_X[1];           \
	W2 = F_R[1] ^ BRC_X[2];           \
	matix_plus(c, W1, W2);            \
	a = sbox0(c[0]);                  \
	b = sbox1(c[1]);                  \
	pos1 = (int *)&a;                 \
	pos2 = (int *)&b;                 \
	F_R[0] = pos1[0];                 \
	F_R[1] = pos2[0]

#define V_BITR()                                                         \
	BRC_X[0] = ((LFSR_S[15] & 0x7FFF8000) << 1) | (LFSR_S[14] & 0xFFFF); \
	BRC_X[1] = ((LFSR_S[11] & 0xFFFF) << 16) | (LFSR_S[9] >> 15);        \
	BRC_X[2] = ((LFSR_S[7] & 0xFFFF) << 16) | (LFSR_S[5] >> 15);         \
	BRC_X[3] = ((LFSR_S[2] & 0xFFFF) << 16) | (LFSR_S[0] >> 15)

#define V_SHIFT()            \
	LFSR_S[0] = LFSR_S[1];   \
	LFSR_S[1] = LFSR_S[2];   \
	LFSR_S[2] = LFSR_S[3];   \
	LFSR_S[3] = LFSR_S[4];   \
	LFSR_S[4] = LFSR_S[5];   \
	LFSR_S[5] = LFSR_S[6];   \
	LFSR_S[6] = LFSR_S[7];   \
	LFSR_S[7] = LFSR_S[8];   \
	LFSR_S[8] = LFSR_S[9];   \
	LFSR_S[9] = LFSR_S[10];  \
	LFSR_S[10] = LFSR_S[11]; \
	LFSR_S[11] = LFSR_S[12]; \
	LFSR_S[12] = LFSR_S[13]; \
	LFSR_S[13] = LFSR_S[14]; \
	LFSR_S[14] = LFSR_S[15]; \
	LFSR_S[15] = f

inline void CalculateLFSRWithSimd(long long *LFSR_S)
{
	__m256i ymm1, ymm2, ymm3, ymm4, ymm5;
	int i = 0;
	ymm1 = _mm256_setr_epi64x(LFSR_S[0], LFSR_S[1], LFSR_S[2], LFSR_S[3]);
	ymm2 = _mm256_setr_epi64x(LFSR_S[4], LFSR_S[5], LFSR_S[6], LFSR_S[7]);
	ymm3 = _mm256_setr_epi64x(LFSR_S[10], LFSR_S[11], LFSR_S[12], LFSR_S[13]);
	ymm4 = _mm256_setr_epi64x(LFSR_S[13], LFSR_S[14], LFSR_S[15], 0);
	ymm5 = _mm256_add_epi64(ymm1, _mm256_slli_epi64(ymm1, 8));
	ymm5 = _mm256_add_epi64(ymm5, _mm256_slli_epi64(ymm2, 20));
	ymm5 = _mm256_add_epi64(ymm5, _mm256_slli_epi64(ymm3, 21));
	ymm5 = _mm256_add_epi64(ymm5, _mm256_slli_epi64(ymm4, 17));
	long long *pos = (long long *)&ymm5;
	for (i = 0; i < 4; i++)
	{
		LFSR_S[16 + i] = pos[i];
	}
	for (i = 0; i < 3; i++)
	{
		LFSR_S[16 + i] = LFSR_S[16 + i] + (LFSR_S[15 + i] << 15);
		LFSR_S[16 + i] = (LFSR_S[16 + i] & 0x7FFFFFFF) + (LFSR_S[16 + i] >> 31);
	}
	LFSR_S[19] = LFSR_S[19] + (LFSR_S[18] << 15) + (LFSR_S[16] << 17);
	LFSR_S[19] = (LFSR_S[19 + i] & 0x7FFFFFFF) + (LFSR_S[19 + i] >> 31);

	return;
}

void ZUC256_SK_AVX512_Init(ZUC256_SK_AVX512_State *state, u8 *const k, u8 *const iv)
{
	ZUC256_SK_AVX512_Setup();

	__m512i a, b;
	int c[2];
	int i, j = 0;
	int *ans = NULL, *pos1 = NULL, *pos2 = NULL;
	long long W, W1, W2, f, v;

	for (i = 0; i < 32; i++)
	{
		state->key[i] = k[i];
	}
	for (i = 0; i < 25; i++)
	{
		state->iv[i] = iv[i];
	}
	long long *LFSR_S = state->LFSR_S, *F_R = state->F_R, *BRC_X = state->BRC_X;

	ZUC256_SK_AVX512_LFSRINIT(state, k, iv, EK_d);

	for (i = 0; i < 32; i++)
	{
		V_BITR();
		V_FSM();
		V_FEEDBACK(f, v);
		f = f + (W << 1);
		f = (f & 0x7FFFFFFF) + (f >> 31);
		V_SHIFT();
	}
	V_BITR();
	V_FSM();
}

void ZUC256_SK_AVX512_Gene(ZUC256_SK_AVX512_State *state, u32 *keystream, u32 keylen)
{
	ZUC256_SK_AVX512_Setup();

	__m512i a, b;
	int c[2];
	int i, j = 0;
	int *ans = NULL, *pos1 = NULL, *pos2 = NULL;
	long long W, W1, W2, f, v;

	long long *LFSR_S = state->LFSR_S, *F_R = state->F_R, *BRC_X = state->BRC_X;

	for (i = 0; i < keylen; i++)
	{
		V_BITR();
		V_FSM();
		keystream[i] = (u32 *)(W ^ BRC_X[3]);
		V_SHIFT();
	}
}
