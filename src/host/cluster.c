/*
	SFFS host tool - cluster layer (host reimplementation).

	Mirrors the on-device hardware/cluster.c semantics (AES-CBC decrypt/encrypt
	per page + HMAC-SHA1 over salt+plaintext, embedded in the spare area) but
	runs entirely in software against a nand.bin image.
*/

#include <string.h>

#include <ios/errno.h>

#include "../hardware/nand.h"
#include "../hardware/nand_helpers.h"
#include "../hardware/cluster.h"
#include "../errors.h"
#include "../sffs/filesystem.h"
#include "crypto.h"
#include "keys.h"
#include "nandimage.h"
#include "endian.h"

/* The one-and-only in-memory superblock buffer (defined in filesystem.c). Any
   cluster op whose data buffer is this address is a superblock op and needs
   big-endian <-> host swapping. File data clusters are byte streams. */
extern SuperBlockInfo _superblockStorage;

static bool IsSuperblockBuffer(const u8* data)
{
	return data == (const u8*)&_superblockStorage;
}

/* IV = last 16 bytes of the 64-byte salt (see GenerateFSAesIv on device).
   These bytes live in SaltData.Unknown (a raw byte array), so they are the
   same regardless of endianness. */
static void GenerateFSAesIv(const u8* salt, u8 ivOut[16])
{
	for (u32 destIndex = 0; destIndex < 0x10; destIndex++)
		for (u32 saltIndex = destIndex; saltIndex < 0x40; saltIndex += 0x10)
			ivOut[destIndex] = salt[saltIndex];
}

/* HMAC over the big-endian salt (if any) then the data, matching the
   on-device OSIOSCGenerateBlockMAC usage. `data` must already be in on-NAND
   (big-endian) byte order. */
static void ComputeClusterHmac(const SaltData* salt, const u8* data, u32 dataLen, u8 digest[20])
{
	HmacSha1Context ctx;
	HmacSha1Init(&ctx, g_nandKeys.NandHmac, 20);
	if (salt != NULL)
	{
		u8 saltBE[0x40];
		SerializeSaltBE(salt, saltBE);
		HmacSha1Update(&ctx, saltBE, sizeof(saltBE));
	}
	HmacSha1Update(&ctx, data, dataLen);
	HmacSha1Final(&ctx, digest);
}

s32 ReadClusters(u16 cluster, u32 count, ClusterFlags flags, SaltData* salt, u8* data, u32* hmacOut)
{
	if (((u32)cluster + count > GetMaxClusters()) || data == NULL || (flags != ClusterFlagsNone && salt == NULL))
		return TranslateErrno(IPC_EINVAL);
	if (!IsNandInitialized())
		return TranslateErrno(IPC_ENOENT);
	if ((flags != ClusterFlagsNone) && !g_nandKeys.Valid)
		return TranslateErrno(IPC_ENOENT);

	const u32 pageSize = GetPageSize();               /* 2048 */
	const u32 pagesPerCluster = GetPagesPerCluster(); /* 8 */
	const u32 hmacSizeShift = SelectedNandChip.Info.SizeInfo.HMACSizeShift;
	const u32 pagesWithHmac = 1u << (6 - hmacSizeShift);       /* 2 */
	const u32 hmacChunkSize = 1u << hmacSizeShift;             /* 32 */
	const u32 hmacOffset = SelectedNandChip.Info.SizeInfo.EccDataCheckByteOffset + 1; /* spare offset 1 */
	const u32 totalPages = count * pagesPerCluster;

	u8 ecc[16];
	u8 spare[NI_SPARE_SIZE];
	u8 hmacFromSpare[0x40] = { 0 };
	u32 hmacBytes = 0;

	/* Read + (optionally) correct + (optionally) decrypt every page. */
	u8 iv[16];
	bool doDecrypt = (flags & ClusterFlagsEncryptDecrypt) != 0;
	if (doDecrypt)
		GenerateFSAesIv((const u8*)salt, iv);

	AesContext aes;
	if (doDecrypt)
		AesSetKey(&aes, g_nandKeys.NandKey);

	s32 status = IPC_SUCCESS; /* worst ECC status seen */

	for (u32 pageIndex = 0; pageIndex < totalPages; pageIndex++)
	{
		u32 absPage = (u32)cluster * pagesPerCluster + pageIndex;
		u8* pageBuf = data + pageIndex * pageSize;

		s32 ret = NandImageReadPageRaw(absPage, pageBuf, spare);
		if (ret != IPC_SUCCESS)
			return TranslateErrno(ret);

		/* ECC: last 16 bytes of the 64-byte spare hold the stored ECC.
		   We verify but never destructively "correct" a clean dump. */
		memcpy(ecc, spare + (NI_SPARE_SIZE - 16), 16);
		/* (correction intentionally skipped for offline dumps; HMAC guards data) */

		/* Collect HMAC bytes from the spare of the last pages of the last cluster. */
		const u32 pageOffsetInCluster = pageIndex & (pagesPerCluster - 1);
		const u32 clusterIndex = pageIndex >> (CLUSTER_SIZE_SHIFT - SelectedNandChip.Info.SizeInfo.PageSizeBitShift);
		const bool isInHmacPages = (pagesPerCluster - pagesWithHmac) <= pageOffsetInCluster;
		const bool isLastCluster = (salt == NULL) || (clusterIndex == count - 1);

		bool wantHmac = (flags & ClusterFlagsVerify) != 0;
		if (wantHmac && isInHmacPages && isLastCluster && hmacBytes + hmacChunkSize <= sizeof(hmacFromSpare))
		{
			memcpy(hmacFromSpare + hmacBytes, spare + hmacOffset, hmacChunkSize);
			hmacBytes += hmacChunkSize;
		}
		else if (hmacOut != NULL && salt == NULL && isInHmacPages &&
		         hmacBytes + hmacChunkSize <= sizeof(hmacFromSpare))
		{
			/* raw HMAC extraction path (hmacOut provided, no salt) */
			memcpy((u8*)hmacOut + hmacBytes, spare + hmacOffset, hmacChunkSize);
			hmacBytes += hmacChunkSize;
		}

		if (doDecrypt)
			AesCbcDecrypt(&aes, iv, pageBuf, pageBuf, pageSize);
	}

	/* At this point `data` holds on-NAND (big-endian) bytes. HMAC is computed
	   over those bytes, exactly as the big-endian Starlet would. */
	if (flags & ClusterFlagsVerify)
	{
		u8 digest[20];
		ComputeClusterHmac(salt, data, totalPages * pageSize, digest);

		s32 result;
		if (memcmp(digest, hmacFromSpare, 0x14) == 0)
			result = status;
		else if (memcmp(digest, hmacFromSpare + 0x14, 0x14) == 0)
			result = (status == IPC_ECC_CRIT) ? IPC_ECC_CRIT : IPC_ECC;
		else
		{
			memset(data, 0, count << CLUSTER_SIZE_SHIFT);
			return TranslateErrno(IPC_CHECKVALUE);
		}

		/* A verified superblock read is always the full superblock; convert
		   it entirely to host byte order for the SFFS core. */
		if (IsSuperblockBuffer(data))
			SwapSuperblockEndian((SuperBlockInfo*)data);

		return TranslateErrno(result);
	}

	/* No HMAC. The only unverified superblock read is the 1-cluster identifier
	   probe, which reads just the header + partial FAT; swap the header only so
	   we never touch memory past what was read. */
	if (IsSuperblockBuffer(data))
		SwapSuperblockHeaderEndian((SuperBlockInfo*)data);

	return TranslateErrno(status);
}

s32 WriteClusters(u16 cluster, u32 count, ClusterFlags flags, SaltData* salt, u8* data, u32* hmacData)
{
	(void)hmacData;
	if (((u32)cluster + count > GetMaxClusters()) || data == NULL || (flags != ClusterFlagsNone && salt == NULL))
		return TranslateErrno(IPC_EINVAL);
	if (!IsNandInitialized())
		return TranslateErrno(IPC_NOTREADY);
	if ((flags != ClusterFlagsNone) && !g_nandKeys.Valid)
		return TranslateErrno(IPC_NOTREADY);

	const u32 pageSize = GetPageSize();
	const u32 pagesPerCluster = GetPagesPerCluster();
	const u32 hmacSizeShift = SelectedNandChip.Info.SizeInfo.HMACSizeShift;
	const u32 pagesWithHmac = 1u << (6 - hmacSizeShift);
	const u32 hmacChunkSize = 1u << hmacSizeShift;
	const u32 hmacOffset = SelectedNandChip.Info.SizeInfo.EccDataCheckByteOffset + 1;
	const u32 totalPages = count * pagesPerCluster;

	/* The SFFS core hands us a host (little-endian) superblock; NAND stores it
	   big-endian. Swap in place to on-NAND order for HMAC/encrypt/write, then
	   swap back afterwards so the core's in-memory copy stays valid. */
	const bool swapSuperblock = IsSuperblockBuffer(data);
	if (swapSuperblock)
		SwapSuperblockEndian((SuperBlockInfo*)data);

	/* Compute HMAC over the big-endian salt + on-NAND (big-endian) data. */
	u8 hmacBuffer[0x40] = { 0 };
	if (flags & ClusterFlagsVerify)
	{
		u8 digest[20];
		ComputeClusterHmac(salt, data, totalPages * pageSize, digest);
		memcpy(hmacBuffer, digest, 0x14);
	}
	u32 hmacBytes = 0;

	bool doEncrypt = (flags & ClusterFlagsEncryptDecrypt) != 0;
	u8 iv[16];
	AesContext aes;
	if (doEncrypt)
	{
		GenerateFSAesIv((const u8*)salt, iv);
		AesSetKey(&aes, g_nandKeys.NandKey);
	}

	u8 pageBuf[NI_PAGE_SIZE];
	u8 spare[NI_SPARE_SIZE];

	for (u32 pageIndex = 0; pageIndex < totalPages; pageIndex++)
	{
		u32 absPage = (u32)cluster * pagesPerCluster + pageIndex;

		/* Encrypt (or copy) page data. */
		if (doEncrypt)
			AesCbcEncrypt(&aes, iv, data + pageIndex * pageSize, pageBuf, pageSize);
		else
			memcpy(pageBuf, data + pageIndex * pageSize, pageSize);

		/* Build spare: 0xFF fill, then HMAC in the last pages, then ECC. */
		memset(spare, 0xFF, NI_SPARE_SIZE);

		const u32 pageOffsetInCluster = pageIndex & (pagesPerCluster - 1);
		const u32 clusterIndex = pageIndex >> (CLUSTER_SIZE_SHIFT - SelectedNandChip.Info.SizeInfo.PageSizeBitShift);
		const bool isInHmacPages = (pagesPerCluster - pagesWithHmac) <= pageOffsetInCluster;
		const bool isLastCluster = (salt == NULL) || (clusterIndex == count - 1);

		if ((flags & ClusterFlagsVerify) && isInHmacPages && isLastCluster &&
		    hmacBytes + hmacChunkSize <= sizeof(hmacBuffer))
		{
			memcpy(spare + hmacOffset, hmacBuffer + hmacBytes, hmacChunkSize);
			hmacBytes += hmacChunkSize;
		}

		/* Compute and store ECC in the last 16 bytes of spare. */
		u8 ecc[16];
		NandEccCalculate(pageBuf, ecc);
		memcpy(spare + (NI_SPARE_SIZE - 16), ecc, 16);

		s32 ret = NandImageWritePageRaw(absPage, pageBuf, spare);
		if (ret != IPC_SUCCESS)
		{
			if (swapSuperblock)
				SwapSuperblockEndian((SuperBlockInfo*)data);
			return TranslateErrno(ret);
		}
	}

	/* Restore the caller's superblock buffer to host byte order. */
	if (swapSuperblock)
		SwapSuperblockEndian((SuperBlockInfo*)data);

	return TranslateErrno(IPC_SUCCESS);
}

s32 CopyClusters(u16 srcCluster, u16 dstCluster, u32 count)
{
	const u32 maxClusters = GetMaxClusters();
	if ((u32)srcCluster + count > maxClusters || (u32)dstCluster + count > maxClusters)
		return FS_EINVAL;

	for (u32 i = 0; i < count; i++)
	{
		s32 errno = CopyCluster((u16)(srcCluster + i), (u16)(dstCluster + i));
		if (errno != IPC_SUCCESS)
			return TranslateErrno(errno);
	}
	return TranslateErrno(IPC_SUCCESS);
}

s32 CheckCluster(u32 cluster)
{
	if (cluster >= GetMaxClusters())
		return TranslateErrno(IPC_EINVAL);
	return TranslateErrno(CheckClusterBlocks(cluster));
}
