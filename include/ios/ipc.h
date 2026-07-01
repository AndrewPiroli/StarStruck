/*
	SFFS host tool - slim ipc.h.

	The SFFS core only needs AccessMode, SeekMode and IoctlvMessageData from
	the IOS IPC surface. The full on-device IPC structs embed 32-bit pointers
	and carry CHECK_SIZE asserts that do not hold on a 64-bit host, so we omit
	them here.
*/

#ifndef __IOS_MODULE_H__
#define __IOS_MODULE_H__

#include "types.h"

typedef enum
{
	NoAccess = 0x00,
	Read = 0x01,
	Write = 0x02,
	ReadWrite = 0x03,
	AccessModeSize = 0xFFFFFFFF
} AccessMode;
CHECK_SIZE(AccessMode, 4);

typedef enum
{
	SeekSet = 0,
	SeekCur = 1,
	SeekEnd = 2
} SeekMode;

/* Host layout: real pointer (size differs from on-device 0x08, which is fine
   since this is never serialised to NAND). */
typedef struct
{
	void* Data;
	u32 Length;
} IoctlvMessageData;

#endif
