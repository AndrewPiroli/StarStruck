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

   Each 512-byte chunk produces 24 parity bits, stored as 4 bytes. A
   2048-byte page has 4 chunks -> 16 bytes at the end of the spare area.
   Algorithm and byte layout are the canonical Wii ones (segher's Wii
   tools / BootMii mini calc_ecc), verified against console-written dumps.
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

/* Canonical Wii NAND ECC over a 512-byte chunk.

   a[3+j][b] accumulates the XOR of every byte whose address has bit j equal
   to b (line parities, 9 address bits); a[0..2] hold the column parities of
   the XOR of all bytes (bit position within the byte). After parity
   reduction the 12 "0"-side bits form a0 and the 12 "1"-side bits form a1.

   Produces 4 bytes: [a0 & 0xFF, a0 >> 8, a1 & 0xFF, a1 >> 8]. */
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
			a[3 + j][(i >> j) & 1] ^= x;
	}

	x = (u8)(a[3][0] ^ a[3][1]);
	a[0][0] = (u8)(x & 0x55);
	a[0][1] = (u8)(x & 0xaa);
	a[1][0] = (u8)(x & 0x33);
	a[1][1] = (u8)(x & 0xcc);
	a[2][0] = (u8)(x & 0x0f);
	a[2][1] = (u8)(x & 0xf0);

	for (j = 0; j < 12; j++)
	{
		a[j][0] = (u8)(Parity(a[j][0]));
		a[j][1] = (u8)(Parity(a[j][1]));
	}

	a0 = a1 = 0;
	for (j = 0; j < 12; j++)
	{
		a0 |= (u32)a[j][0] << j;
		a1 |= (u32)a[j][1] << j;
	}

	ecc[0] = (u8)a0;
	ecc[1] = (u8)(a0 >> 8);
	ecc[2] = (u8)a1;
	ecc[3] = (u8)(a1 >> 8);
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

	/* Standard SmartMedia-style single-bit correction, per 512-byte chunk.

	   The two 12-bit parity words a0 ("address bit = 0" side) and a1
	   ("address bit = 1" side) are complementary for every bit covering a
	   single-bit data error: syn0 ^ syn1 == 0xFFF identifies one, and syn1
	   then directly encodes the error position (bits 0-2 = bit within the
	   byte, bits 3-11 = byte offset in the chunk). A syndrome with exactly
	   one set bit means the stored ECC itself took the hit. */
	s32 ret = 0;
	for (int chunk = 0; chunk < 4; chunk++)
	{
		const u8* c = calc + chunk * 4;
		const u8* s = storedEcc + chunk * 4;
		const u32 calc0 = (u32)c[0] | ((u32)c[1] << 8);
		const u32 calc1 = (u32)c[2] | ((u32)c[3] << 8);
		const u32 read0 = (u32)s[0] | ((u32)s[1] << 8);
		const u32 read1 = (u32)s[2] | ((u32)s[3] << 8);
		const u32 syn0 = (calc0 ^ read0) & 0xFFF;
		const u32 syn1 = (calc1 ^ read1) & 0xFFF;
		const u32 syndrome = syn0 | (syn1 << 12);

		if (syndrome == 0)
			continue;

		if ((syndrome & (syndrome - 1)) == 0)
		{
			ret = 1; /* single-bit error in the stored ECC itself; data is fine */
			continue;
		}

		if ((syn0 ^ syn1) != 0xFFF)
			return -1; /* uncorrectable */

		u8* dp = data + chunk * 0x200 + (syn1 >> 3);
		*dp = (u8)(*dp ^ (1 << (syn1 & 7)));
		ret = 1;
	}

	return ret;
}
