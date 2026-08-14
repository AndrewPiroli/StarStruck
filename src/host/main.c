/*
	SFFS host tool - command line interface.

	Reads and writes the SFFS filesystem inside a Wii nand.bin dump from a PC.

	Usage:
	  sffs <nand.bin> [--keys keys.bin] [--rw] [--scrub] <command> [args...]

	Commands:
	  ls   <path>                 list a directory
	  cat  <path> [outfile]       read a file (to stdout or outfile)
	  put  <hostfile> <path>      replace (or create) an SFFS file
	  rm   [-r] <path>            delete a file, or a tree with -r
	  truncate <path>             release a file's contents, keeping the inode
	  touch <path>                create an empty file
	  mkdir <path>                create a directory
	  format                      create a fresh SFFS
	  stat                        print filesystem statistics
	  fsck                        check filesystem consistency
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ios/errno.h>
#include <fs/errors.h>
#include <fs/types.h>

#include "../sffs/filesystem.h"
#include "../sffs/commands.h"
#include "../sffs/inode.h"
#include "../sffs/cache.h"
#include "../handles.h"

#include "../hardware/cluster.h"

#include "nandimage.h"
#include "hostnand.h"
#include "keys.h"
#include "fsck.h"

/* _fileHandles is declared extern in handles.h but defined on-device in
   devfs.c (which we dropped); provide it here. _superblockOffset and
   _fileSystemDataSize are defined by the SFFS core (commands.c). */
FSHandle _fileHandles[FS_MAX_FILE_HANDLES];

static const char* ErrName(s32 e)
{
	switch (e)
	{
		case IPC_SUCCESS: return "OK";
		case FS_EINVAL: return "invalid argument/path";
		case FS_EACCESS: return "permission denied";
		case FS_ECORRUPT: return "corrupted NAND";
		case FS_NOFILESYSTEM: return "no filesystem";
		case FS_EEXIST: return "already exists";
		case FS_ENOENT: return "no such file or directory";
		case FS_NO_INODES: return "no free inodes";
		case FS_EFBIG: return "no space";
		case FS_ENAMELEN: return "name too long";
		case FS_BADBLOCK: return "bad block";
		case FS_EIO: return "ECC/IO error";
		case FS_ENOTEMPTY: return "not empty";
		case FS_AUTHENTICATION: return "authentication/HMAC failure";
		case FS_NOTIMPL: return "not implemented";
		default: return "error";
	}
}

/* ---- Path helpers ---- */

/* Resolve a path to its inode and entry type. Either output may be NULL.
   Returns FS_ENOENT when the path does not exist. */
static s32 LookupPath(const char* path, u32* inodeOut, FileSystemEntryType* typeOut)
{
	SuperBlockInfo* sb = SelectSuperBlock();
	if (sb == NULL)
		return FS_NOFILESYSTEM;

	u32 inode = FindInodeByPath(sb, path);
	if (inode == SFFSErasedNode)
		return FS_ENOENT;

	if (inodeOut != NULL)
		*inodeOut = inode;
	if (typeOut != NULL)
		*typeOut = GetFstEntry(sb, inode)->Mode.Fields.Type;

	return IPC_SUCCESS;
}

/* ---- Minimal handle helpers (ported from devfs.c) ---- */

static FSHandle* OpenFile(u32 uid, u16 gid, const char* path, AccessMode mode)
{
	SuperBlockInfo* sb = SelectSuperBlock();
	if (sb == NULL)
		return NULL;

	u32 inode;
	FileSystemEntryType type;
	if (LookupPath(path, &inode, &type) != IPC_SUCCESS || (type & S_IFMT) != S_IFREG)
		return NULL;

	FileSystemTableEntry* entry = GetFstEntry(sb, inode);

	for (u32 i = 0; i < FS_MAX_FILE_HANDLES; i++)
	{
		if (_fileHandles[i].InUse)
			continue;
		_fileHandles[i].InUse = 1;
		_fileHandles[i].UserId = uid;
		_fileHandles[i].GroupId = gid;
		_fileHandles[i].Inode = inode;
		_fileHandles[i].Mode = mode;
		_fileHandles[i].FilePosition = 0;
		_fileHandles[i].FilePointer = 0;
		_fileHandles[i].Size = entry->FileSize;
		_fileHandles[i].ShouldFlushSuperblock = 0;
		_fileHandles[i].Error = 0;
		return &_fileHandles[i];
	}
	return NULL;
}

static s32 CloseFile(FSHandle* h)
{
	ClusterCacheEntry* cache = FindCachedCluster(h);
	s32 ret = IPC_SUCCESS;
	if (cache != NULL)
	{
		ret = FlushCachedCluster(cache);
		cache->FileHandle = NULL;
	}
	if (h->ShouldFlushSuperblock)
	{
		s32 r = TryWriteSuperblock();
		if (r != IPC_SUCCESS)
			ret = r;
	}
	h->InUse = 0;
	return ret;
}

/* ---- Optional scrubbing of freed clusters ----

   Freeing a cluster only changes its FAT entry; the old encrypted contents stay
   in the image. With --scrub we snapshot the FAT before a destructive command
   and afterwards zero every cluster that went from in-use to free.

   This runs *after* the operation has flushed the superblock. Zeroing first
   would destroy live data if that flush failed. It is also safe across the
   relocations ReclaimBlocks performs, since a relocated cluster's contents
   already exist at their new home by the time the source is released. */

static bool g_scrub = false;
static u16* g_fatBefore = NULL;

static void ScrubBegin(void)
{
	if (!g_scrub)
		return;

	SuperBlockInfo* sb = SelectSuperBlock();
	if (sb == NULL)
		return;

	const u32 count = GetFatArraySize() / sizeof(u16);
	free(g_fatBefore);
	g_fatBefore = malloc(count * sizeof(u16));
	if (g_fatBefore != NULL)
		memcpy(g_fatBefore, sb->FatEntries, count * sizeof(u16));
}

static void ScrubEnd(void)
{
	if (!g_scrub || g_fatBefore == NULL)
		return;

	SuperBlockInfo* sb = SelectSuperBlock();
	if (sb == NULL)
		return;

	u8* zero = calloc(1, CLUSTER_SIZE);
	if (zero == NULL)
		return;

	const u32 count = GetFatArraySize() / sizeof(u16);
	u32 scrubbed = 0;
	for (u32 cluster = 0; cluster < count; cluster++)
	{
		/* Reserved/bad entries are above SFFSLastNode, so they never qualify. */
		const bool wasUsed = g_fatBefore[cluster] <= SFFSLastNode;
		const u16 now = sb->FatEntries[cluster];
		const bool nowFree = (now == SFFSFreeNode || now == SFFSErasedNode);

		if (!wasUsed || !nowFree)
			continue;

		if (WriteClusters((u16)cluster, 1, ClusterFlagsNone, NULL, zero, NULL) == IPC_SUCCESS)
			scrubbed++;
	}

	free(zero);
	free(g_fatBefore);
	g_fatBefore = NULL;

	if (scrubbed != 0)
		fprintf(stderr, "scrubbed %u freed cluster%s\n", scrubbed, scrubbed == 1 ? "" : "s");
}

/* ---- Commands ---- */

static int CmdStat(void)
{
	SFFSStatistics st;
	s32 ret = GetStats(&st);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "stat: %s (%d)\n", ErrName(ret), ret);
		return 1;
	}
	printf("cluster size    : %u\n", st.ClusterSize);
	printf("free clusters   : %u\n", st.FreeClusters);
	printf("used clusters   : %u\n", st.UsedClusters);
	printf("bad clusters    : %u\n", st.BadClusters);
	printf("reserved clust. : %u\n", st.ReservedClusters);
	printf("free inodes     : %u\n", st.FreeInodes);
	printf("used inodes     : %u\n", st.UsedInodes);
	return 0;
}

static int CmdLs(const char* path)
{
	u32 count = 0;
	s32 ret = ReadDirectory(0, 0, path, NULL, &count);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "ls: %s (%d)\n", ErrName(ret), ret);
		return 1;
	}

	char* buf = calloc(count, MAX_FILE_SIZE + 1);
	if (buf == NULL)
		return 1;

	ret = ReadDirectory(0, 0, path, buf, &count);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "ls: %s (%d)\n", ErrName(ret), ret);
		free(buf);
		return 1;
	}

	const char* p = buf;
	for (u32 i = 0; i < count; i++)
	{
		printf("%s\n", p);
		p += strlen(p) + 1;
	}
	free(buf);
	return 0;
}

static int CmdCat(const char* path, const char* outfile)
{
	FSHandle* h = OpenFile(0, 0, path, Read);
	if (h == NULL)
	{
		fprintf(stderr, "cat: cannot open '%s'\n", path);
		return 1;
	}

	FILE* out = stdout;
	if (outfile != NULL)
	{
		out = fopen(outfile, "wb");
		if (out == NULL)
		{
			fprintf(stderr, "cat: cannot create '%s'\n", outfile);
			CloseFile(h);
			return 1;
		}
	}

	int rc = 0;
	u32 size = h->Size;
	if (size > 0)
	{
		/* ReadFile operates on whole clusters; read the cluster-rounded size
		   into an aligned buffer then emit only the real byte count. */
		u32 aligned = (size + (CLUSTER_SIZE - 1)) & CLUSTER_MASK;
		u8* buf = malloc(aligned);
		if (buf == NULL)
		{
			if (out != stdout)
				fclose(out);
			CloseFile(h);
			return 1;
		}

		s32 got = ReadFile(h, buf, aligned);
		if (got < 0)
		{
			fprintf(stderr, "cat: read error %s (%d)\n", ErrName(got), got);
			rc = 1;
		}
		else
		{
			fwrite(buf, 1, size, out);
		}
		free(buf);
	}

	if (out != stdout)
		fclose(out);
	CloseFile(h);
	return rc;
}

static int CmdRm(const char* path, bool recursive)
{
	FileSystemEntryType type;
	s32 ret = LookupPath(path, NULL, &type);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "rm: '%s': %s (%d)\n", path, ErrName(ret), ret);
		return 1;
	}

	/* DeletePath removes a directory's entire subtree without asking, so make
	   the caller say so explicitly. */
	if (type == S_IFDIR && !recursive)
	{
		fprintf(stderr, "rm: '%s' is a directory; pass -r to delete it and everything under it\n", path);
		return 1;
	}

	ret = DeletePath(0, 0, path);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "rm: '%s': %s (%d)\n", path, ErrName(ret), ret);
		return 1;
	}
	return 0;
}

static int CmdTruncate(const char* path)
{
	s32 ret = TruncateFile(0, 0, path);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "truncate: '%s': %s (%d)\n", path, ErrName(ret), ret);
		return 1;
	}
	return 0;
}

/* Write a host file into the SFFS.

   By default this is a true replacement: an existing target is truncated first
   so the file ends up exactly the size of the source. Without that truncation
   WriteFile can only ever extend, because it frees at most as many clusters as
   it writes, re-links whatever old tail remains onto the new chain, and never
   shrinks FileSize.

   Truncating (rather than deleting and recreating) keeps the inode number,
   name, owner, group, permissions and generation, all of which feed the per
   file encryption salt. */
static int CmdPut(const char* hostfile, const char* path, bool append, bool noCreate)
{
	FILE* in = fopen(hostfile, "rb");
	if (in == NULL)
	{
		fprintf(stderr, "put: cannot open '%s'\n", hostfile);
		return 1;
	}

	FileSystemEntryType type;
	s32 ret = LookupPath(path, NULL, &type);

	if (ret == FS_ENOENT)
	{
		if (noCreate)
		{
			fprintf(stderr, "put: '%s' does not exist (--no-create)\n", path);
			fclose(in);
			return 1;
		}

		/* Same defaults as touch: uid 0, gid 0, owner/group rw, other none.
		   Ownership must be set before any data is written, since UserId is
		   part of the encryption salt. */
		ret = CreateFile(0, 0, path, 0, 3, 3, 0);
		if (ret != IPC_SUCCESS)
		{
			fprintf(stderr, "put: cannot create '%s': %s (%d)\n", path, ErrName(ret), ret);
			fclose(in);
			return 1;
		}
	}
	else if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "put: '%s': %s (%d)\n", path, ErrName(ret), ret);
		fclose(in);
		return 1;
	}
	else if (type != S_IFREG)
	{
		fprintf(stderr, "put: '%s' is not a regular file\n", path);
		fclose(in);
		return 1;
	}
	else if (!append)
	{
		ret = TruncateFile(0, 0, path);
		if (ret != IPC_SUCCESS)
		{
			fprintf(stderr, "put: cannot truncate '%s': %s (%d)\n", path, ErrName(ret), ret);
			fclose(in);
			return 1;
		}
	}

	FSHandle* h = OpenFile(0, 0, path, ReadWrite);
	if (h == NULL)
	{
		fprintf(stderr, "put: cannot open target '%s'\n", path);
		fclose(in);
		return 1;
	}

	if (append && h->Size != 0)
	{
		/* SFFS can only seek in whole clusters, so an append to a file whose
		   size is not a multiple of the cluster size resumes at the next
		   cluster boundary, leaving the remainder of the last cluster in
		   place. */
		if ((h->Size & (CLUSTER_SIZE - 1)) != 0)
			fprintf(stderr,
			        "put: warning: '%s' is %u bytes, which is not a multiple of the %u byte cluster;\n"
			        "     appended data will start at the next cluster boundary\n",
			        path, h->Size, CLUSTER_SIZE);

		s32 sret = SeekFile(h, 0, SeekEnd);
		if (sret != IPC_SUCCESS)
		{
			fprintf(stderr, "put: cannot seek to end of '%s': %s (%d)\n", path, ErrName(sret), sret);
			fclose(in);
			CloseFile(h);
			return 1;
		}
	}

	/* Slurp the whole host file. WriteFile writes cluster by cluster and reads
	   a full cluster from the buffer even for the final partial cluster, so we
	   pad the buffer up to a cluster boundary. */
	fseek(in, 0, SEEK_END);
	long fsz = ftell(in);
	fseek(in, 0, SEEK_SET);

	int rc = 0;
	if (fsz < 0)
	{
		fprintf(stderr, "put: cannot size '%s'\n", hostfile);
		fclose(in);
		CloseFile(h);
		return 1;
	}

	u32 size = (u32)fsz;
	if (size > 0)
	{
		u32 aligned = (size + (CLUSTER_SIZE - 1)) & CLUSTER_MASK;
		u8* buf = calloc(1, aligned);
		if (buf == NULL || fread(buf, 1, size, in) != size)
		{
			fprintf(stderr, "put: read error on '%s'\n", hostfile);
			free(buf);
			fclose(in);
			CloseFile(h);
			return 1;
		}

		s32 wr = WriteFile(h, buf, size);
		if (wr < 0)
		{
			fprintf(stderr, "put: write error %s (%d)\n", ErrName(wr), wr);
			rc = 1;
		}
		free(buf);
	}
	fclose(in);
	s32 cret = CloseFile(h);
	if (cret != IPC_SUCCESS)
	{
		fprintf(stderr, "put: close/flush error %s (%d)\n", ErrName(cret), cret);
		rc = 1;
	}
	return rc;
}

static int CmdFormat(void)
{
	s32 ret = Format(0, _fileHandles, FS_MAX_FILE_HANDLES);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "format: %s (%d)\n", ErrName(ret), ret);
		return 1;
	}
	printf("formatted\n");
	return 0;
}

static int CmdTouch(const char* path)
{
	s32 ret = CreateFile(0, 0, path, 0, 3, 3, 0);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "touch: %s (%d)\n", ErrName(ret), ret);
		return 1;
	}
	return 0;
}

static int CmdMkdir(const char* path)
{
	/* owner rw, group rw, other none, attributes 0, uid/gid 0 */
	s32 ret = CreateDirectory(0, 0, path, 0, 3, 3, 0);
	if (ret != IPC_SUCCESS)
	{
		fprintf(stderr, "mkdir: %s (%d)\n", ErrName(ret), ret);
		return 1;
	}
	return 0;
}

static void Usage(const char* prog)
{
	fprintf(stderr,
	        "usage: %s <nand.bin> [--keys keys.bin] [--rw] [--scrub] <command> [args]\n"
	        "\n"
	        "global options:\n"
	        "  --keys <file>               load NAND keys from keys.bin\n"
	        "  --rw                        open the image read/write\n"
	        "  --scrub                     zero clusters as they are freed\n"
	        "\n"
	        "commands:\n"
	        "  ls    <path>\n"
	        "  cat   <path> [outfile]\n"
	        "  put   [--append] [--no-create] <hostfile> <path>\n"
	        "                              replace a file (truncates first),\n"
	        "                              creating it if it does not exist\n"
	        "  rm    [-r] <path>           delete a file; -r deletes a directory tree\n"
	        "  truncate <path>             release a file's contents, keeping the inode\n"
	        "  touch <path>                create an empty file\n"
	        "  mkdir <path>\n"
	        "  format                      create a fresh SFFS (destroys data)\n"
	        "  stat\n"
	        "  fsck                        check filesystem consistency\n",
	        prog);
}

int main(int argc, char** argv)
{
	if (argc < 3)
	{
		Usage(argv[0]);
		return 2;
	}

	const char* nandPath = argv[1];
	const char* keysPath = NULL;
	bool writable = false;

	int i = 2;
	for (; i < argc; i++)
	{
		if (strcmp(argv[i], "--keys") == 0 && i + 1 < argc)
			keysPath = argv[++i];
		else if (strcmp(argv[i], "--rw") == 0)
			writable = true;
		else if (strcmp(argv[i], "--scrub") == 0)
			g_scrub = true;
		else
			break;
	}

	if (i >= argc)
	{
		Usage(argv[0]);
		return 2;
	}
	const char* cmd = argv[i++];

	/* Per-command options, accepted before the positional arguments. */
	bool flagRecursive = false;
	bool flagAppend = false;
	bool flagNoCreate = false;
	for (; i < argc && argv[i][0] == '-' && argv[i][1] != '\0'; i++)
	{
		if (strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "--recursive") == 0)
			flagRecursive = true;
		else if (strcmp(argv[i], "--append") == 0)
			flagAppend = true;
		else if (strcmp(argv[i], "--no-create") == 0)
			flagNoCreate = true;
		else
		{
			fprintf(stderr, "unknown option '%s'\n", argv[i]);
			Usage(argv[0]);
			return 2;
		}
	}

	const bool destructive = strcmp(cmd, "put") == 0 || strcmp(cmd, "rm") == 0 || strcmp(cmd, "truncate") == 0;

	if (destructive || strcmp(cmd, "mkdir") == 0 || strcmp(cmd, "touch") == 0 || strcmp(cmd, "format") == 0)
		writable = true;

	if (g_scrub && !destructive)
		fprintf(stderr, "warning: --scrub has no effect on '%s'\n", cmd);

	if (NandImageOpen(nandPath, writable) != IPC_SUCCESS)
		return 1;

	HostNandInit();

	/* Load keys: prefer --keys, else the nand.bin footer OTP. */
	s32 kret = IPC_ENOENT;
	if (keysPath != NULL)
		kret = LoadKeysFromKeysBin(keysPath);
	if (kret != IPC_SUCCESS)
	{
		u8 otp[128];
		if (NandImageGetOtp(otp) == IPC_SUCCESS)
			kret = LoadKeysFromOtp(otp);
	}
	if (kret != IPC_SUCCESS)
		fprintf(stderr, "warning: no keys loaded; encrypted/HMAC operations will fail\n");

	int rc = 0;

	/* format creates the filesystem, so it must not require a prior mount. */
	if (strcmp(cmd, "format") == 0)
	{
		rc = CmdFormat();
		NandImageClose();
		return rc;
	}

	/* Mount the SFFS (mode 1 = read/parse superblock). */
	s32 mret = InitializeSFFS(1);
	if (mret != IPC_SUCCESS)
	{
		fprintf(stderr, "mount: %s (%d)\n", ErrName(mret), mret);
		NandImageClose();
		return 1;
	}

	if (destructive)
		ScrubBegin();

	if (strcmp(cmd, "stat") == 0)
		rc = CmdStat();
	else if (strcmp(cmd, "fsck") == 0)
		rc = CmdFsck();
	else if (strcmp(cmd, "touch") == 0 && i < argc)
		rc = CmdTouch(argv[i]);
	else if (strcmp(cmd, "ls") == 0 && i < argc)
		rc = CmdLs(argv[i]);
	else if (strcmp(cmd, "cat") == 0 && i < argc)
		rc = CmdCat(argv[i], (i + 1 < argc) ? argv[i + 1] : NULL);
	else if (strcmp(cmd, "put") == 0 && i + 1 < argc)
		rc = CmdPut(argv[i], argv[i + 1], flagAppend, flagNoCreate);
	else if (strcmp(cmd, "rm") == 0 && i < argc)
		rc = CmdRm(argv[i], flagRecursive);
	else if (strcmp(cmd, "truncate") == 0 && i < argc)
		rc = CmdTruncate(argv[i]);
	else if (strcmp(cmd, "mkdir") == 0 && i < argc)
		rc = CmdMkdir(argv[i]);
	else
	{
		Usage(argv[0]);
		rc = 2;
	}

	if (destructive && rc == 0)
		ScrubEnd();

	NandImageClose();
	return rc;
}
