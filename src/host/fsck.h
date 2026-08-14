/*
	SFFS host tool - filesystem consistency check.

	Read-only verification of the mounted SFFS: inode tree, cluster chains,
	orphaned clusters and the superblock statistics. Reports problems, never
	repairs them.
*/

#pragma once

#include <types.h>

/* Run the checks against the mounted filesystem.
   Returns 0 when clean, 1 when problems were found. */
int CmdFsck(void);
