/*
	SFFS host tool - NAND hardware layer (host reimplementation).

	Provides the globals and cluster/page primitives that the SFFS core and
	the host cluster layer expect, backed by the nand.bin image instead of
	the Wii NAND controller registers.
*/

#include <string.h>

#include <ios/errno.h>

#include "../hardware/nand.h"
#include "../hardware/nand_helpers.h"
#include "../errors.h"
#include "nandimage.h"

/* Globals declared extern by nand.h / consumed by the SFFS core + helpers. */
NandInformation SelectedNandChip;
NandSizeInformation SelectedNandSizeInfo;
u8 EccBuffer[0x40 * 6] __attribute__((aligned(0x80))) = { 0 };
s32 IrqMessageQueueId = 0;
s32 IoscMessageQueueId = 0;

static bool s_nandInitialized = false;

/* Standard Wii 512MB NAND size info (matches on-device chip table). */
static const NandSizeInformation kWiiSizeInfo = {
	.NandSizeBitShift = 0x1D,       /* 512 MB */
	.BlockSizeBitShift = 0x11,      /* 128 KB block (64 pages) */
	.PageSizeBitShift = 0x0B,       /* 2048 byte page */
	.EccSizeBitShift = 0x06,        /* 64 byte spare/ecc region */
	.HMACSizeShift = 0x05,          /* 32 bytes hmac chunk per page */
	.PageCopyMask = 0x0001,
	.SupportPageCopy = 0x0000,
	.EccDataCheckByteOffset = 0x00,
	.Padding = { 0x00, 0x00 },
};

bool IsNandInitialized(void)
{
	return s_nandInitialized && NandImageIsOpen();
}

/* Called once by the tool after opening the image. Populates SelectedNandChip
   size info so the geometry helpers work. */
void HostNandInit(void)
{
	memset(&SelectedNandChip, 0, sizeof(SelectedNandChip));
	SelectedNandChip.Info.SizeInfo = kWiiSizeInfo;
	SelectedNandSizeInfo = kWiiSizeInfo;
	s_nandInitialized = true;
}

s32 GetNandSizeInfo(NandSizeInformation* dest)
{
	if (dest == NULL)
		return IPC_EINVAL;
	if (!IsNandInitialized())
		return IPC_NOTREADY;
	memcpy(dest, &SelectedNandChip.Info.SizeInfo, sizeof(NandSizeInformation));
	return IPC_SUCCESS;
}

s32 SelectNandSize(bool selectNandSize)
{
	s32 errno = IPC_SUCCESS;
	if (selectNandSize)
		errno = GetNandSizeInfo(&SelectedNandSizeInfo);
	return errno;
}

/* Erase (delete) is a no-op against a file-backed image: our writes overwrite
   pages directly. We keep the block-boundary semantics the caller relies on. */
s32 DeleteCluster(u32 cluster)
{
	if (cluster >= GetMaxClusters())
		return IPC_EINVAL;
	if (!IsNandInitialized())
		return IPC_NOTREADY;
	return IPC_SUCCESS;
}

/* Copy a whole cluster (all pages, including spare) from src to dst. */
s32 CopyCluster(u16 srcCluster, u16 dstCluster)
{
	if (srcCluster >= GetMaxClusters() || dstCluster >= GetMaxClusters())
		return IPC_EINVAL;
	if (!IsNandInitialized())
		return IPC_NOTREADY;

	const u32 pagesPerCluster = GetPagesPerCluster();
	u8 data[NI_PAGE_SIZE];
	u8 spare[NI_SPARE_SIZE];

	for (u32 i = 0; i < pagesPerCluster; i++)
	{
		u32 srcPage = (u32)srcCluster * pagesPerCluster + i;
		u32 dstPage = (u32)dstCluster * pagesPerCluster + i;
		s32 ret = NandImageReadPageRaw(srcPage, data, spare);
		if (ret != IPC_SUCCESS)
			return ret;
		ret = NandImageWritePageRaw(dstPage, data, spare);
		if (ret != IPC_SUCCESS)
			return ret;
	}
	return IPC_SUCCESS;
}

/* On a dump we treat all blocks as good. */
s32 CheckClusterBlocks(u32 cluster)
{
	(void)cluster;
	if (!IsNandInitialized())
		return IPC_NOTREADY;
	return IPC_SUCCESS;
}
