/*
	SFFS host tool - host NAND init hook.
*/

#pragma once

/* Populate SelectedNandChip/SelectedNandSizeInfo with the standard Wii
   512MB geometry and mark the NAND layer initialized. Call once after
   NandImageOpen(). */
void HostNandInit(void);
