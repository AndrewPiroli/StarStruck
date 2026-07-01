/*
	SFFS host tool - self-contained crypto implementations.

	AES-128 (FIPS-197), SHA-1 (RFC 3174) and HMAC-SHA1 (RFC 2104).
	Compact, portable, no external dependencies.
*/

#include <string.h>

#include "crypto.h"

/* ======================================================================
   AES-128
   ====================================================================== */

static const u8 kSbox[256] = {
	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
	0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
	0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
	0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
	0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
	0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
	0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
	0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
	0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
	0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
	0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
	0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
	0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
	0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
	0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static u8 kInvSbox[256];
static int kInvSboxReady = 0;

static void InitInvSbox(void)
{
	if (kInvSboxReady)
		return;
	for (int i = 0; i < 256; i++)
		kInvSbox[kSbox[i]] = (u8)i;
	kInvSboxReady = 1;
}

static const u8 kRcon[11] = { 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

void AesSetKey(AesContext* ctx, const u8 key[16])
{
	InitInvSbox();
	u8* rk = ctx->round_key;
	memcpy(rk, key, 16);

	for (int i = 4; i < 44; i++)
	{
		u8 t[4];
		memcpy(t, rk + (i - 1) * 4, 4);
		if ((i & 3) == 0)
		{
			u8 tmp = t[0];
			t[0] = (u8)(kSbox[t[1]] ^ kRcon[i / 4]);
			t[1] = kSbox[t[2]];
			t[2] = kSbox[t[3]];
			t[3] = kSbox[tmp];
		}
		for (int j = 0; j < 4; j++)
			rk[i * 4 + j] = (u8)(rk[(i - 4) * 4 + j] ^ t[j]);
	}
}

static u8 GfMul(u8 a, u8 b)
{
	u8 p = 0;
	for (int i = 0; i < 8; i++)
	{
		if (b & 1)
			p ^= a;
		u8 hi = (u8)(a & 0x80);
		a = (u8)(a << 1);
		if (hi)
			a ^= 0x1b;
		b >>= 1;
	}
	return p;
}

static void AddRoundKey(u8 s[16], const u8* rk)
{
	for (int i = 0; i < 16; i++)
		s[i] ^= rk[i];
}

static void EncryptBlock(const AesContext* ctx, u8 s[16])
{
	const u8* rk = ctx->round_key;
	AddRoundKey(s, rk);

	for (int round = 1; round <= 10; round++)
	{
		/* SubBytes */
		for (int i = 0; i < 16; i++)
			s[i] = kSbox[s[i]];

		/* ShiftRows */
		u8 t[16];
		t[0] = s[0];  t[4] = s[4];  t[8] = s[8];   t[12] = s[12];
		t[1] = s[5];  t[5] = s[9];  t[9] = s[13];  t[13] = s[1];
		t[2] = s[10]; t[6] = s[14]; t[10] = s[2];  t[14] = s[6];
		t[3] = s[15]; t[7] = s[3];  t[11] = s[7];  t[15] = s[11];
		memcpy(s, t, 16);

		if (round != 10)
		{
			/* MixColumns */
			for (int c = 0; c < 4; c++)
			{
				u8* col = s + c * 4;
				u8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
				col[0] = (u8)(GfMul(a0, 2) ^ GfMul(a1, 3) ^ a2 ^ a3);
				col[1] = (u8)(a0 ^ GfMul(a1, 2) ^ GfMul(a2, 3) ^ a3);
				col[2] = (u8)(a0 ^ a1 ^ GfMul(a2, 2) ^ GfMul(a3, 3));
				col[3] = (u8)(GfMul(a0, 3) ^ a1 ^ a2 ^ GfMul(a3, 2));
			}
		}

		AddRoundKey(s, rk + round * 16);
	}
}

static void DecryptBlock(const AesContext* ctx, u8 s[16])
{
	const u8* rk = ctx->round_key;
	AddRoundKey(s, rk + 10 * 16);

	for (int round = 9; round >= 0; round--)
	{
		/* InvShiftRows */
		u8 t[16];
		t[0] = s[0];  t[4] = s[4];  t[8] = s[8];   t[12] = s[12];
		t[1] = s[13]; t[5] = s[1];  t[9] = s[5];   t[13] = s[9];
		t[2] = s[10]; t[6] = s[14]; t[10] = s[2];  t[14] = s[6];
		t[3] = s[7];  t[7] = s[11]; t[11] = s[15]; t[15] = s[3];
		memcpy(s, t, 16);

		/* InvSubBytes */
		for (int i = 0; i < 16; i++)
			s[i] = kInvSbox[s[i]];

		AddRoundKey(s, rk + round * 16);

		if (round != 0)
		{
			/* InvMixColumns */
			for (int c = 0; c < 4; c++)
			{
				u8* col = s + c * 4;
				u8 a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
				col[0] = (u8)(GfMul(a0, 14) ^ GfMul(a1, 11) ^ GfMul(a2, 13) ^ GfMul(a3, 9));
				col[1] = (u8)(GfMul(a0, 9) ^ GfMul(a1, 14) ^ GfMul(a2, 11) ^ GfMul(a3, 13));
				col[2] = (u8)(GfMul(a0, 13) ^ GfMul(a1, 9) ^ GfMul(a2, 14) ^ GfMul(a3, 11));
				col[3] = (u8)(GfMul(a0, 11) ^ GfMul(a1, 13) ^ GfMul(a2, 9) ^ GfMul(a3, 14));
			}
		}
	}
}

void AesCbcDecrypt(AesContext* ctx, u8 iv[16], const u8* in, u8* out, u32 len)
{
	u8 block[16];
	u8 next_iv[16];
	for (u32 off = 0; off < len; off += 16)
	{
		memcpy(next_iv, in + off, 16);
		memcpy(block, in + off, 16);
		DecryptBlock(ctx, block);
		for (int i = 0; i < 16; i++)
			out[off + i] = (u8)(block[i] ^ iv[i]);
		memcpy(iv, next_iv, 16);
	}
}

void AesCbcEncrypt(AesContext* ctx, u8 iv[16], const u8* in, u8* out, u32 len)
{
	u8 block[16];
	for (u32 off = 0; off < len; off += 16)
	{
		for (int i = 0; i < 16; i++)
			block[i] = (u8)(in[off + i] ^ iv[i]);
		EncryptBlock(ctx, block);
		memcpy(out + off, block, 16);
		memcpy(iv, block, 16);
	}
}

/* ======================================================================
   SHA-1
   ====================================================================== */

static u32 Rotl32(u32 v, int n)
{
	return (v << n) | (v >> (32 - n));
}

static void Sha1Block(Sha1Context* ctx, const u8* p)
{
	u32 w[80];
	for (int i = 0; i < 16; i++)
		w[i] = ((u32)p[i * 4] << 24) | ((u32)p[i * 4 + 1] << 16) | ((u32)p[i * 4 + 2] << 8) | (u32)p[i * 4 + 3];
	for (int i = 16; i < 80; i++)
		w[i] = Rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

	u32 a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3], e = ctx->state[4];

	for (int i = 0; i < 80; i++)
	{
		u32 f, k;
		if (i < 20)
		{
			f = (b & c) | ((~b) & d);
			k = 0x5A827999;
		}
		else if (i < 40)
		{
			f = b ^ c ^ d;
			k = 0x6ED9EBA1;
		}
		else if (i < 60)
		{
			f = (b & c) | (b & d) | (c & d);
			k = 0x8F1BBCDC;
		}
		else
		{
			f = b ^ c ^ d;
			k = 0xCA62C1D6;
		}
		u32 tmp = Rotl32(a, 5) + f + e + k + w[i];
		e = d;
		d = c;
		c = Rotl32(b, 30);
		b = a;
		a = tmp;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

void Sha1Init(Sha1Context* ctx)
{
	ctx->state[0] = 0x67452301;
	ctx->state[1] = 0xEFCDAB89;
	ctx->state[2] = 0x98BADCFE;
	ctx->state[3] = 0x10325476;
	ctx->state[4] = 0xC3D2E1F0;
	ctx->length = 0;
	ctx->buffered = 0;
}

void Sha1Update(Sha1Context* ctx, const u8* data, u32 len)
{
	ctx->length += (u64)len * 8;
	while (len > 0)
	{
		u32 take = 64 - ctx->buffered;
		if (take > len)
			take = len;
		memcpy(ctx->buffer + ctx->buffered, data, take);
		ctx->buffered += take;
		data += take;
		len -= take;
		if (ctx->buffered == 64)
		{
			Sha1Block(ctx, ctx->buffer);
			ctx->buffered = 0;
		}
	}
}

void Sha1Final(Sha1Context* ctx, u8 digest[20])
{
	u64 bitlen = ctx->length;
	u8 pad = 0x80;
	Sha1Update(ctx, &pad, 1);

	u8 zero = 0;
	while (ctx->buffered != 56)
		Sha1Update(ctx, &zero, 1);

	u8 lenbytes[8];
	for (int i = 0; i < 8; i++)
		lenbytes[i] = (u8)(bitlen >> (56 - i * 8));
	Sha1Update(ctx, lenbytes, 8);

	for (int i = 0; i < 5; i++)
	{
		digest[i * 4] = (u8)(ctx->state[i] >> 24);
		digest[i * 4 + 1] = (u8)(ctx->state[i] >> 16);
		digest[i * 4 + 2] = (u8)(ctx->state[i] >> 8);
		digest[i * 4 + 3] = (u8)(ctx->state[i]);
	}
}

/* ======================================================================
   HMAC-SHA1
   ====================================================================== */

void HmacSha1Init(HmacSha1Context* ctx, const u8* key, u32 keyLen)
{
	u8 k[64];
	memset(k, 0, sizeof(k));

	if (keyLen > 64)
	{
		Sha1Context t;
		Sha1Init(&t);
		Sha1Update(&t, key, keyLen);
		Sha1Final(&t, k); /* first 20 bytes */
	}
	else
	{
		memcpy(k, key, keyLen);
	}

	u8 ipad[64], opad[64];
	for (int i = 0; i < 64; i++)
	{
		ipad[i] = (u8)(k[i] ^ 0x36);
		opad[i] = (u8)(k[i] ^ 0x5c);
	}

	Sha1Init(&ctx->inner);
	Sha1Update(&ctx->inner, ipad, 64);
	Sha1Init(&ctx->outer);
	Sha1Update(&ctx->outer, opad, 64);
}

void HmacSha1Update(HmacSha1Context* ctx, const u8* data, u32 len)
{
	Sha1Update(&ctx->inner, data, len);
}

void HmacSha1Final(HmacSha1Context* ctx, u8 digest[20])
{
	u8 innerDigest[20];
	Sha1Final(&ctx->inner, innerDigest);
	Sha1Update(&ctx->outer, innerDigest, 20);
	Sha1Final(&ctx->outer, digest);
}
