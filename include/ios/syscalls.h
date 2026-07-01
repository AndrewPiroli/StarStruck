/*
	SFFS host tool - syscall shim.

	The SFFS core only needs a tiny slice of the IOS syscall surface: the
	NAND generation counter, stored in the IOSC keyring on real hardware.
	On the host we back it with a plain global (see host/keys.c).
*/

#pragma once

#include <types.h>
#include <ios/errno.h>

/* Read/write an IOSC keyring value. Only KEYRING_CONST_NAND_GEN is used by
   the SFFS core; other keys are handled internally by the crypto layer. */
s32 OSGetIOSCData(u32 key, u32* out);
s32 OSSetIOSCData(u32 key, u32 value);
