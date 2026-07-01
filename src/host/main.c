/*
	SFFS host tool - command line interface.

	Reads and writes the SFFS filesystem inside a Wii nand.bin dump from a PC.

	Usage:
	  sffs <nand.bin> [--keys keys.bin] [--rw] <command> [args...]

	Commands:
	  ls   <path>                 list a directory
	  cat  <path> [outfile]       read a file (to stdout or outfile)
	  put  <hostfile> <path>      write host file into an existing SFFS file
	  mkdir <path>                create a directory
	  stat                        print filesystem statistics
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

#include "nandimage.h"
#include "hostnand.h"
#include "keys.h"

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

/* ---- Minimal handle helpers (ported from devfs.c) ---- */

static FSHandle* OpenFile(u32 uid, u16 gid, const char* path, AccessMode mode)
{
	SuperBlockInfo* sb = SelectSuperBlock();
	if (sb == NULL)
		return NULL;

	u32 inode = FindInodeByPath(sb, path);
	if (inode == SFFSErasedNode)
		return NULL;

	FileSystemTableEntry* entry = GetFstEntry(sb, inode);
	if ((entry->Mode.Fields.Type & S_IFMT) != S_IFREG)
		return NULL;

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

static int CmdPut(const char* hostfile, const char* path)
{
	FILE* in = fopen(hostfile, "rb");
	if (in == NULL)
	{
		fprintf(stderr, "put: cannot open '%s'\n", hostfile);
		return 1;
	}

	FSHandle* h = OpenFile(0, 0, path, ReadWrite);
	if (h == NULL)
	{
		fprintf(stderr, "put: cannot open target '%s' (must exist)\n", path);
		fclose(in);
		return 1;
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
	        "usage: %s <nand.bin> [--keys keys.bin] [--rw] <command> [args]\n"
	        "commands:\n"
	        "  ls    <path>\n"
	        "  cat   <path> [outfile]\n"
	        "  put   <hostfile> <path>\n"
	        "  touch <path>                create an empty file\n"
	        "  mkdir <path>\n"
	        "  format                      create a fresh SFFS (destroys data)\n"
	        "  stat\n",
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
		else
			break;
	}

	if (i >= argc)
	{
		Usage(argv[0]);
		return 2;
	}
	const char* cmd = argv[i++];

	if (strcmp(cmd, "put") == 0 || strcmp(cmd, "mkdir") == 0 || strcmp(cmd, "touch") == 0 ||
	    strcmp(cmd, "format") == 0)
		writable = true;

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

	if (strcmp(cmd, "stat") == 0)
		rc = CmdStat();
	else if (strcmp(cmd, "touch") == 0 && i < argc)
		rc = CmdTouch(argv[i]);
	else if (strcmp(cmd, "ls") == 0 && i < argc)
		rc = CmdLs(argv[i]);
	else if (strcmp(cmd, "cat") == 0 && i < argc)
		rc = CmdCat(argv[i], (i + 1 < argc) ? argv[i + 1] : NULL);
	else if (strcmp(cmd, "put") == 0 && i + 1 < argc)
		rc = CmdPut(argv[i], argv[i + 1]);
	else if (strcmp(cmd, "mkdir") == 0 && i < argc)
		rc = CmdMkdir(argv[i]);
	else
	{
		Usage(argv[0]);
		rc = 2;
	}

	NandImageClose();
	return rc;
}
