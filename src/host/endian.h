/*
	SFFS host tool - endianness helpers.

	The Starlet ARM core runs big-endian (for PPC compatibility), so every
	multi-byte field that SFFS stores on NAND is big-endian. This host tool is
	little-endian (x86), so on-NAND structures must be byte-swapped when they
	cross the NAND boundary:

	  - SuperBlockInfo   swapped in place after read / before write
	  - SaltData         serialised big-endian before being fed to HMAC

	Raw file *data* clusters are byte streams and are never swapped.
*/

#pragma once

#include <types.h>

#include "../sffs/filesystem.h"
#include "../hardware/cluster.h"

static inline u16 Bswap16(u16 v)
{
	return (u16)((v >> 8) | (v << 8));
}

static inline u32 Bswap32(u32 v)
{
	return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) | ((v & 0x00FF0000u) >> 8) |
	       ((v & 0xFF000000u) >> 24);
}

/* Convert a SuperBlockInfo between on-NAND big-endian and host little-endian.
   The transform is symmetric, so one routine handles both directions. */
void SwapSuperblockEndian(SuperBlockInfo* sb);

/* Swap only the 12-byte header (Identifier/Version/Generation). Used by the
   1-cluster superblock-identifier probe, which does not read the full FAT/FST
   and therefore must not touch that (unread) memory. */
void SwapSuperblockHeaderEndian(SuperBlockInfo* sb);

/* Serialise a SaltData into a 64-byte big-endian buffer for HMAC input. */
void SerializeSaltBE(const SaltData* salt, u8 out[0x40]);
