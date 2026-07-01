sffs-host -- Wii NAND SFFS tool
===

A host (PC) tool for reading and writing the SFFS filesystem inside a Wii
NAND dump (`nand.bin`). The SFFS driver is the original StarStruck IOS
implementation; the Wii NAND hardware interface has been replaced with an
image backend that operates on a dump file using standard POSIX syscalls.

* SFFS driver: Copyright (c) 2025 DacoTaco (StarStruck), GPLv2
* Host backend / crypto / CLI: added for offline dump processing

Building
---
Requires a C compiler (GCC/Clang). No external dependencies (AES-128,
SHA-1 and HMAC-SHA1 are bundled).

    make

Produces the `sffs` binary.

NAND dump format
---
The tool expects a BackupMii-style dump:

    4096 blocks * 64 pages * (2048 + 64) bytes  (data + spare/ECC)
    optional 1024-byte footer (BackupMii keying info)

Both the 553648128-byte (no footer) and 553649152-byte (with footer)
sizes are accepted.

Keys
---
SFFS clusters are AES-128-CBC encrypted and HMAC-SHA1 signed with the
per-console NAND keys. Supply them one of two ways:

* `--keys keys.bin` : NAND HMAC at 0x144 (20 bytes), NAND AES key at
  0x158 (16 bytes).
* Omit `--keys` and the tool falls back to the 128-byte OTP block in the
  dump's footer (NAND HMAC at OTP 0x44, NAND AES key at OTP 0x58).

Usage
---
    sffs <nand.bin> [--keys keys.bin] [--rw] <command> [args]

    ls    <path>              list a directory
    cat   <path> [outfile]    read a file (to stdout or a file)
    put   <hostfile> <path>   write a host file into an existing SFFS file
    touch <path>              create an empty file
    mkdir <path>              create a directory
    format                    create a fresh SFFS (destroys all data)
    stat                      print filesystem statistics

`--rw` opens the image read/write; it is implied by write commands.

Endianness
---
The Starlet ARM core runs big-endian (for PPC compatibility), so every
multi-byte field SFFS writes to NAND is big-endian. This tool is a
little-endian x86 binary, so on-NAND structures are converted at the NAND
boundary (see `src/host/endian.c`):

* `SuperBlockInfo` (Identifier/Version/Generation, the FAT u16 array and all
  FST entry fields) is byte-swapped in place after read / before write.
* `SaltData` is serialised big-endian before being fed to HMAC.
* The `st_mode` bitfield is bit-group-reversed: the on-NAND layout packs
  Owner/Group/Other/Type from the most-significant bits (big-endian bit
  order), which a little-endian compiler would otherwise read backwards.
* Raw file *data* clusters are byte streams and are never swapped.

Notes
---
* ECC in a clean dump is trusted on read; SFFS HMAC verification is what
  guards data integrity. Written pages get freshly computed ECC.
* Standard 512MB Wii NAND geometry is assumed.
