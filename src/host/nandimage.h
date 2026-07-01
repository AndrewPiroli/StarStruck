/*
	SFFS host tool - NAND image backend.

	Emulates the raw NAND page interface against a BackupMii-style nand.bin
	dump (4096 blocks * 64 pages * (2048 + 64) + 1024-byte footer).

	This replaces the on-device hardware/nand.c page primitives.
*/

#pragma once

#include <types.h>

/* Standard Wii NAND geometry (matches the on-device 512MB chip entry). */
#define NI_PAGE_SIZE      0x800  /* 2048 data bytes per page */
#define NI_SPARE_SIZE     0x40   /* 64 spare bytes per page (HMAC + ECC) */
#define NI_PAGE_TOTAL     (NI_PAGE_SIZE + NI_SPARE_SIZE)
#define NI_PAGES_PER_BLOCK 64
#define NI_BLOCK_COUNT    4096
#define NI_TOTAL_PAGES    (NI_BLOCK_COUNT * NI_PAGES_PER_BLOCK)
#define NI_PAGES_PER_CLUSTER 8   /* 16KB cluster / 2KB page */
#define NI_FOOTER_SIZE    0x400

/* Open a nand.bin. writable selects O_RDWR (writes are flushed to disk).
   Returns 0 on success. */
s32 NandImageOpen(const char* path, bool writable);
void NandImageClose(void);
bool NandImageIsOpen(void);

/* Retrieve the 128-byte OTP block from the footer (BackupMii format).
   Returns 0 on success, negative if no footer / not present. */
s32 NandImageGetOtp(u8 otp[128]);

/* Raw page access into the mmap'd image (data = 2048 bytes, spare = 64 bytes).
   Either pointer may be NULL to skip. Returns 0 on success. */
s32 NandImageReadPageRaw(u32 page, u8* data, u8* spare);
s32 NandImageWritePageRaw(u32 page, const u8* data, const u8* spare);

/* ECC helpers over a single 2048-byte page. */
void NandEccCalculate(const u8* data, u8 ecc[16]);
/* Verify/correct: compares stored ecc (16 bytes) to computed, corrects data
   in place. Returns 0 (ok), 1 (corrected), or -1 (uncorrectable). */
s32 NandEccCorrect(u8* data, const u8 storedEcc[16]);
