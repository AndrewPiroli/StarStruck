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
    sffs <nand.bin> [--keys keys.bin] [--rw] [--scrub] <command> [args]

    ls    <path>              list a directory
    cat   <path> [outfile]    read a file (to stdout or a file)
    put   [--append] [--no-create] <hostfile> <path>
                              replace an SFFS file with a host file,
                              creating it if it does not exist
    rm    [-r] <path>         delete a file; -r deletes a directory tree
    truncate <path>           release a file's contents, keeping the inode
    touch <path>              create an empty file
    mkdir <path>              create a directory
    format                    create a fresh SFFS (destroys all data)
    stat                      print filesystem statistics
    fsck                      check filesystem consistency

`--rw` opens the image read/write; it is implied by write commands.

`--scrub` zeroes each cluster as it is released, so the previous contents
of a replaced or deleted file do not linger in the image. Without it only
the FAT entry changes and the old encrypted data stays on the "free"
clusters.

Replacing files
---
`put` performs a true replacement: an existing target is truncated first,
so the result is exactly the size of the source file, whether that is
larger or smaller than before. It creates the file when it is missing
(`--no-create` disables that).

This matters because the underlying `WriteFile` can only ever *extend*: it
releases at most as many clusters as it writes, re-links any remaining old
tail onto the new chain, and never shrinks `FileSize`. Writing a shorter
file over a longer one without truncating therefore leaves the tail of the
old contents attached. That is the original IOS behaviour -- on a console,
callers delete and recreate a file instead of overwriting it.

Truncating is preferred over delete-and-recreate here because the per-file
encryption salt is derived from the file's **UserId, name, inode number and
generation** (`InitFileSalt`). Truncating in place preserves all of them,
so a replaced file keeps its identity, ownership and permissions and stays
readable by the console. Recreating it would allocate a different inode and
reset ownership to uid 0.

For the same reason, ownership must be set *before* a file's data is
written: changing `UserId` afterwards changes the salt and silently
invalidates the HMAC of every data cluster.

`--append` appends instead of replacing. SFFS can only seek in whole
clusters, so appending to a file whose size is not a multiple of the 16 KB
cluster resumes at the next cluster boundary; the tool warns when this
applies.

Checking
---
`fsck` walks the inode tree from the root, follows every file's cluster
chain and cross-checks the result against the FAT and the superblock
statistics. It reports loops, cross-linked or out-of-range chains, size
mismatches, unreachable inodes, orphaned clusters and statistics drift. It
is read-only and never repairs. Running it before and after a modification
is the quickest way to confirm the image is still sound.

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
* The image is modified in place through a shared mapping and there is no
  undo. Work on a copy.
* Files created by `touch` or by `put` on a missing path get uid 0, gid 0
  and owner/group read-write permissions. If the console expects specific
  ownership, replace an existing file rather than creating a new one.
* A regular file's basename cannot be changed, because the name feeds the
  encryption salt. Moving a file between directories is fine.
* `truncate` only truncates to zero length; partial truncation would
  require rewriting a partial cluster and is not implemented.
* Freeing clusters marks them `SFFSFreeNode`, which is not immediately
  allocatable: the allocator hands out only erased clusters and reclaims
  free ones once a whole block is free, or on demand via `ReclaimBlocks`.
  Space returned by a delete may therefore not show up as usable until the
  next allocation forces a reclaim.
