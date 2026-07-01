/*
	SFFS host tool - key material.

	Holds the NAND AES key and NAND HMAC key needed to decrypt/verify SFFS
	clusters, plus the NAND generation counter (normally in the IOSC keyring).
	Keys may come from a keys.bin file or from the OTP block in a BackupMii
	nand.bin footer.
*/

#pragma once

#include <types.h>

typedef struct
{
	u8 NandHmac[20]; /* keys.bin 0x144 / OTP */
	u8 NandKey[16];  /* keys.bin 0x158 / OTP */
	bool Valid;
} NandKeys;

extern NandKeys g_nandKeys;

/* NAND generation counter, backed here for OSGet/SetIOSCData shim. */
extern u32 g_nandGeneration;

/* Load keys from a keys.bin (BootMii/other) file. Returns 0 on success. */
s32 LoadKeysFromKeysBin(const char* path);

/* Extract keys from a 128-byte OTP block (as found in the nand.bin footer).
   Returns 0 on success. */
s32 LoadKeysFromOtp(const u8 otp[128]);
