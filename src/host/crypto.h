/*
	SFFS host tool - self-contained crypto (AES-128-CBC + SHA1 + HMAC-SHA1).

	No external dependencies. Implementations are public-domain style,
	sufficient for offline processing of Wii NAND dumps.
*/

#pragma once

#include <types.h>

/* ---- AES-128 ---- */
typedef struct
{
	u8 round_key[176]; /* 11 round keys * 16 bytes */
} AesContext;

void AesSetKey(AesContext* ctx, const u8 key[16]);

/* CBC mode. iv is updated in place so successive calls chain correctly.
   in and out may alias. len must be a multiple of 16. */
void AesCbcDecrypt(AesContext* ctx, u8 iv[16], const u8* in, u8* out, u32 len);
void AesCbcEncrypt(AesContext* ctx, u8 iv[16], const u8* in, u8* out, u32 len);

/* ---- SHA-1 ---- */
typedef struct
{
	u32 state[5];
	u64 length; /* total message length in bits */
	u8 buffer[64];
	u32 buffered; /* bytes currently in buffer */
} Sha1Context;

void Sha1Init(Sha1Context* ctx);
void Sha1Update(Sha1Context* ctx, const u8* data, u32 len);
void Sha1Final(Sha1Context* ctx, u8 digest[20]);

/* ---- HMAC-SHA1 ---- */
typedef struct
{
	Sha1Context inner;
	Sha1Context outer;
} HmacSha1Context;

void HmacSha1Init(HmacSha1Context* ctx, const u8* key, u32 keyLen);
void HmacSha1Update(HmacSha1Context* ctx, const u8* data, u32 len);
void HmacSha1Final(HmacSha1Context* ctx, u8 digest[20]);
