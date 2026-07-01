/*
	SFFS host tool - endianness helpers implementation.
*/

#include "endian.h"

#include "../hardware/nand.h"
#include "../hardware/nand_helpers.h"

/*
	st_mode is a bitfield packed [Owner:2][Group:2][Other:2][Type:2] in
	declaration order. On the big-endian Starlet, the first field occupies the
	most-significant bits; on a little-endian host compiler it occupies the
	least-significant bits. The byte is not multi-byte so a normal byte-swap
	does nothing, but the bit-group order must be reversed. This reversal is its
	own inverse, so it serves both directions.
*/
static u8 FixModeByte(u8 b)
{
	u8 f0 = (u8)((b >> 6) & 3);
	u8 f1 = (u8)((b >> 4) & 3);
	u8 f2 = (u8)((b >> 2) & 3);
	u8 f3 = (u8)(b & 3);
	return (u8)(f0 | (f1 << 2) | (f2 << 4) | (f3 << 6));
}

void SwapSuperblockHeaderEndian(SuperBlockInfo* sb)
{
	sb->Identifier = Bswap32(sb->Identifier);
	sb->Version = Bswap32(sb->Version);
	sb->Generation = Bswap32(sb->Generation);
}

void SwapSuperblockEndian(SuperBlockInfo* sb)
{
	/* Header */
	SwapSuperblockHeaderEndian(sb);

	/* FAT: array of u16 entries. The real number of entries depends on the
	   NAND size (GetFatArraySize bytes / 2). */
	const u32 fatEntries = GetFatArraySize() / sizeof(u16);
	for (u32 i = 0; i < fatEntries; i++)
		sb->FatEntries[i] = Bswap16(sb->FatEntries[i]);

	/* FST: array of FileSystemTableEntry. Name is a byte array (no swap);
	   every other field is multi-byte. */
	const u32 fstCount = GetFstEntryCount();
	for (u32 i = 0; i < fstCount; i++)
	{
		FileSystemTableEntry* e = GetFstEntry(sb, i);
		/* Name[12] and Attributes(u8) need no swap; Mode is a bitfield that
		   needs bit-group reordering (not a byte swap). */
		e->Mode.Value = FixModeByte(e->Mode.Value);
		e->StartCluster = Bswap16(e->StartCluster);
		e->Sibling = Bswap16(e->Sibling);
		e->FileSize = Bswap32(e->FileSize);
		e->UserId = Bswap32(e->UserId);
		e->GroupId = Bswap16(e->GroupId);
		e->SFFSGeneration = Bswap32(e->SFFSGeneration);
	}
}

void SerializeSaltBE(const SaltData* salt, u8 out[0x40])
{
	/* Layout mirrors SaltData (0x40 bytes):
	     0x00 Uid          u32
	     0x04 Filename     u8[12]
	     0x10 ChainIndex   u32
	     0x14 Inode        u32
	     0x18 Miscellaneous u32
	     0x1C Unknown      u8[0x24]
	   Multi-byte fields are written big-endian. */
	u32 v;
	v = Bswap32(salt->Uid);
	__builtin_memcpy(out + 0x00, &v, 4);
	__builtin_memcpy(out + 0x04, salt->Filename, 0x0C);
	v = Bswap32(salt->ChainIndex);
	__builtin_memcpy(out + 0x10, &v, 4);
	v = Bswap32(salt->Inode);
	__builtin_memcpy(out + 0x14, &v, 4);
	v = Bswap32(salt->Miscellaneous);
	__builtin_memcpy(out + 0x18, &v, 4);
	__builtin_memcpy(out + 0x1C, salt->Unknown, 0x24);
}
