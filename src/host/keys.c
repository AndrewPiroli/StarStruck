/*
	SFFS host tool - key material loading.
*/

#include <stdio.h>
#include <string.h>

#include <ios/errno.h>
#include <ios/keyring.h>
#include <ios/syscalls.h>

#include "keys.h"

NandKeys g_nandKeys = { 0 };
u32 g_nandGeneration = 0;

/*
	OTP layout (128 bytes), per wiibrew Hardware/OTP:
		0x00  boot1 hash        (20)
		0x14  common key        (16)
		0x24  ng_id             (4)
		0x28  ng_priv           (30)
		0x44  nand_hmac         (20)
		0x58  nand_key          (16)
		0x68  rng_key           (16)
		0x78  unknown/misc       (8)
*/
#define OTP_NAND_HMAC_OFF 0x44
#define OTP_NAND_KEY_OFF  0x58

s32 LoadKeysFromOtp(const u8 otp[128])
{
	memcpy(g_nandKeys.NandHmac, otp + OTP_NAND_HMAC_OFF, 20);
	memcpy(g_nandKeys.NandKey, otp + OTP_NAND_KEY_OFF, 16);
	g_nandKeys.Valid = true;
	return IPC_SUCCESS;
}

/*
	keys.bin layout (as documented for BootMii/keys.bin dumps):
		0x144  NAND HMAC (20 bytes)
		0x158  NAND AES key (16 bytes)
	This is effectively the OTP block mapped at 0x100.
*/
#define KEYSBIN_NAND_HMAC_OFF 0x144
#define KEYSBIN_NAND_KEY_OFF  0x158
#define KEYSBIN_MIN_SIZE      (KEYSBIN_NAND_KEY_OFF + 16)

s32 LoadKeysFromKeysBin(const char* path)
{
	FILE* f = fopen(path, "rb");
	if (f == NULL)
	{
		fprintf(stderr, "keys: cannot open '%s'\n", path);
		return IPC_ENOENT;
	}

	u8 buf[0x400];
	memset(buf, 0, sizeof(buf));
	size_t n = fread(buf, 1, sizeof(buf), f);
	fclose(f);

	if (n < KEYSBIN_MIN_SIZE)
	{
		fprintf(stderr, "keys: '%s' too small (%zu bytes)\n", path, n);
		return IPC_INVALIDSIZE;
	}

	memcpy(g_nandKeys.NandHmac, buf + KEYSBIN_NAND_HMAC_OFF, 20);
	memcpy(g_nandKeys.NandKey, buf + KEYSBIN_NAND_KEY_OFF, 16);
	g_nandKeys.Valid = true;
	return IPC_SUCCESS;
}

/* ---- IOSC keyring shim used by the SFFS core ---- */

s32 OSGetIOSCData(u32 key, u32* out)
{
	if (out == NULL)
		return IPC_EINVAL;

	switch (key)
	{
		case KEYRING_CONST_NAND_GEN:
			*out = g_nandGeneration;
			return IPC_SUCCESS;
		default:
			return IPC_EINVAL;
	}
}

s32 OSSetIOSCData(u32 key, u32 value)
{
	switch (key)
	{
		case KEYRING_CONST_NAND_GEN:
			g_nandGeneration = value;
			return IPC_SUCCESS;
		default:
			return IPC_EINVAL;
	}
}
