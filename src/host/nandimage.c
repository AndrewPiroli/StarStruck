/*
	SFFS host tool - NAND image backend implementation.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <ios/errno.h>

#include "nandimage.h"

static int s_fd = -1;
static u8* s_map = NULL;
static size_t s_mapSize = 0;
static bool s_writable = false;
static bool s_hasFooter = false;

bool NandImageIsOpen(void)
{
	return s_map != NULL;
}

s32 NandImageOpen(const char* path, bool writable)
{
	struct stat st;
	if (stat(path, &st) != 0)
	{
		fprintf(stderr, "nand: cannot stat '%s'\n", path);
		return IPC_ENOENT;
	}

	const off_t dataSize = (off_t)NI_TOTAL_PAGES * NI_PAGE_TOTAL;      /* 553648128 */
	const off_t withFooter = dataSize + NI_FOOTER_SIZE;               /* 553649152 */

	if (st.st_size != dataSize && st.st_size != withFooter)
	{
		fprintf(stderr,
		        "nand: '%s' has unexpected size %lld (expected %lld or %lld)\n",
		        path, (long long)st.st_size, (long long)dataSize, (long long)withFooter);
		return IPC_INVALIDSIZE;
	}

	s_hasFooter = (st.st_size == withFooter);
	s_writable = writable;

	s_fd = open(path, writable ? O_RDWR : O_RDONLY);
	if (s_fd < 0)
	{
		fprintf(stderr, "nand: cannot open '%s'\n", path);
		return IPC_EACCES;
	}

	s_mapSize = (size_t)st.st_size;
	s_map = mmap(NULL, s_mapSize, writable ? (PROT_READ | PROT_WRITE) : PROT_READ, MAP_SHARED, s_fd, 0);
	if (s_map == MAP_FAILED)
	{
		s_map = NULL;
		close(s_fd);
		s_fd = -1;
		fprintf(stderr, "nand: mmap failed\n");
		return IPC_UNKNOWN;
	}

	return IPC_SUCCESS;
}

void NandImageClose(void)
{
	if (s_map != NULL)
	{
		if (s_writable)
			msync(s_map, s_mapSize, MS_SYNC);
		munmap(s_map, s_mapSize);
		s_map = NULL;
	}
	if (s_fd >= 0)
	{
		close(s_fd);
		s_fd = -1;
	}
}

s32 NandImageGetOtp(u8 otp[128])
{
	if (!NandImageIsOpen() || !s_hasFooter)
		return IPC_ENOENT;

	/* Footer layout: 256 info + 128 OTP + 128 pad + 256 SEEPROM + 256 pad. */
	const size_t footerBase = (size_t)NI_TOTAL_PAGES * NI_PAGE_TOTAL;
	memcpy(otp, s_map + footerBase + 256, 128);
	return IPC_SUCCESS;
}

s32 NandImageReadPageRaw(u32 page, u8* data, u8* spare)
{
	if (!NandImageIsOpen())
		return IPC_NOTREADY;
	if (page >= NI_TOTAL_PAGES)
		return IPC_EINVAL;

	const u8* p = s_map + (size_t)page * NI_PAGE_TOTAL;
	if (data != NULL)
		memcpy(data, p, NI_PAGE_SIZE);
	if (spare != NULL)
		memcpy(spare, p + NI_PAGE_SIZE, NI_SPARE_SIZE);
	return IPC_SUCCESS;
}

s32 NandImageWritePageRaw(u32 page, const u8* data, const u8* spare)
{
	if (!NandImageIsOpen())
		return IPC_NOTREADY;
	if (!s_writable)
		return IPC_EACCES;
	if (page >= NI_TOTAL_PAGES)
		return IPC_EINVAL;

	u8* p = s_map + (size_t)page * NI_PAGE_TOTAL;
	if (data != NULL)
		memcpy(p, data, NI_PAGE_SIZE);
	if (spare != NULL)
		memcpy(p + NI_PAGE_SIZE, spare, NI_SPARE_SIZE);
	return IPC_SUCCESS;
}

/* ======================================================================
   NAND ECC (SmartMedia-style Hamming, as used by the Wii NAND controller).

   Each 512-byte chunk produces 3 bytes of parity, stored as 4 bytes:
   [LP even/odd, CP, LP high]. A 2048-byte page has 4 chunks -> 16 bytes.
   Layout matches segher's Wii tools and the on-device CorrectNandData().
   ====================================================================== */

static u8 Parity(u8 x)
{
	u8 y = 0;
	while (x)
	{
		y ^= (u8)(x & 1);
		x >>= 1;
	}
	return y;
}

/* Canonical Wii NAND ECC over a 512-byte chunk (segher's Wii tools).
   Produces 4 bytes: [LP low, LP high, CP, 0]. */
static void EccCalcChunk(const u8* data, u8 ecc[4])
{
	u8 a[12][2];
	u32 a0, a1;
	u8 x;
	int i, j;

	memset(a, 0, sizeof(a));
	for (i = 0; i < 512; i++)
	{
		x = data[i];
		for (j = 0; j < 9; j++)
			a[j][(i >> j) & 1] ^= x;
	}

	x = (u8)(a[0][0] ^ a[0][1]);
	a[0][0] = (u8)(x & 0x55);
	a[0][1] = (u8)(x & 0xaa);
	a[1][0] = (u8)(x & 0x33);
	a[1][1] = (u8)(x & 0xcc);
	a[2][0] = (u8)(x & 0x0f);
	a[2][1] = (u8)(x & 0xf0);

	for (j = 0; j < 3; j++)
	{
		a[j][0] = (u8)(Parity(a[j][0]));
		a[j][1] = (u8)(Parity(a[j][1]));
	}
	for (j = 3; j < 9; j++)
	{
		a[j][0] = (u8)(Parity(a[j][0]));
		a[j][1] = (u8)(Parity(a[j][1]));
	}

	a0 = a1 = 0;
	for (j = 0; j < 9; j++)
	{
		a0 |= (u32)(a[j][0] << j);
		a1 |= (u32)(a[j][1] << j);
	}

	ecc[0] = (u8)a0;
	ecc[1] = (u8)a1;
	ecc[2] = (u8)((a[2][0] << 0) | (a[2][1] << 1) | (a[1][0] << 2) | (a[1][1] << 3) | (a[0][0] << 4) |
	              (a[0][1] << 5) | ((a0 >> 8) << 6) | ((a1 >> 8) << 7));
	ecc[3] = 0;
}

void NandEccCalculate(const u8* data, u8 ecc[16])
{
	for (int chunk = 0; chunk < 4; chunk++)
		EccCalcChunk(data + chunk * 512, ecc + chunk * 4);
}

s32 NandEccCorrect(u8* data, const u8 storedEcc[16])
{
	u8 calc[16];
	NandEccCalculate(data, calc);
	if (memcmp(calc, storedEcc, 16) == 0)
		return 0;

	/* Match on-device single-bit correction semantics (see CorrectNandData). */
	s32 ret = 0;
	for (int index = 0; index < 4; index++)
	{
		u32 eccCalc, eccRead;
		memcpy(&eccCalc, calc + index * 4, 4);
		memcpy(&eccRead, storedEcc + index * 4, 4);
		if (eccCalc == eccRead)
			continue;

		u32 swRead = (eccRead >> 24) | ((eccRead & 0xff0000) >> 8) | ((eccRead & 0xff00) << 8) | (eccRead << 24);
		u32 swCalc = (eccCalc >> 24) | ((eccCalc & 0xff0000) >> 8) | ((eccCalc & 0xff00) << 8) | (eccCalc << 24);
		u32 syndrome = (swRead ^ swCalc) & 0x0FFF0FFF;

		if (((syndrome - 1) & syndrome) == 0)
		{
			ret = 1; /* single-bit error in ECC itself */
			continue;
		}

		u32 unknown = syndrome >> 16;
		if ((((syndrome | 0xFFFFF000) ^ unknown) & 0xFFFF) != 0xFFFF)
			return -1; /* uncorrectable */

		u32 location = (unknown >> 3) & 0x1FF;
		u8* dp = data + location + index * 0x200;
		*dp = (u8)((1 << (unknown & 7)) ^ *dp);
		ret = 1;
	}

	return ret;
}
