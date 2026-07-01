/*
	StarStruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	Copyright (C) 2025	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#pragma once
#include <ios/ipc.h>
#include <types.h>

typedef struct
{
	u16 InUse;
	u16 GroupId;
	u32 UserId;
	u32 Inode;
	AccessMode Mode;
	u32 FilePosition;
	u32 FilePointer;
	u32 Size;
	u32 ShouldFlushSuperblock;
	u32 Error;
} FSHandle;

/* In-memory-only handle; layout not serialised to NAND. Offset/size asserts
   are omitted so the struct works on a 64-bit host. */

#define FS_MAX_FILE_HANDLES 0x10
extern FSHandle _fileHandles[FS_MAX_FILE_HANDLES];
