/*
	SFFS host tool - filesystem consistency check.

	Walks the inode tree from the root, follows every file's cluster chain and
	cross-checks the result against the FAT and the superblock statistics.

	This is deliberately read-only. Its job is to tell you whether a delete,
	truncate or replace left the filesystem in a sane state, not to paper over
	damage. Note that the sentinel values (0xFFFB-0xFFFF) are far outside the
	valid cluster range, so a chain that fails to terminate at SFFSLastNode
	would index past the FAT and into the FST: those cases are reported here
	rather than followed.
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ios/errno.h>
#include <fs/errors.h>
#include <fs/types.h>

#include "../sffs/filesystem.h"
#include "../sffs/commands.h"
#include "../sffs/inode.h"
#include "../handles.h"

#include "fsck.h"

/* Marker for "no file owns this cluster" in the ownership map. */
#define FSCK_NO_OWNER 0xFFFF

typedef struct
{
	SuperBlockInfo* superblock;
	u32 fstEntryCount;
	u32 fatEntryCount;
	u8* inodeSeen;      /* one byte per FST entry */
	u16* clusterOwner;  /* owning inode per cluster, or FSCK_NO_OWNER */
	u32 problems;
	u32 fileCount;
	u32 dirCount;
	u32 chainClusters;  /* clusters accounted for by file chains */
} FsckContext;

static void Problem(FsckContext* ctx, const char* fmt, ...) __attribute__((format(printf, 2, 3)));

static void Problem(FsckContext* ctx, const char* fmt, ...)
{
	va_list ap;
	ctx->problems++;
	fputs("  ! ", stdout);
	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
	fputc('\n', stdout);
}

/* Copy an FST name into a NUL terminated buffer; the on-disk field is not
   guaranteed to be terminated. */
static void EntryName(const FileSystemTableEntry* entry, char out[MAX_FILE_SIZE + 1])
{
	memcpy(out, entry->Name, MAX_FILE_SIZE);
	out[MAX_FILE_SIZE] = '\0';
}

/* Follow one file's cluster chain, recording ownership and reporting loops,
   cross-links, out of range links and size mismatches. */
static void CheckFileChain(FsckContext* ctx, u32 inode, const char* path)
{
	FileSystemTableEntry* entry = GetFstEntry(ctx->superblock, inode);
	u16 cluster = entry->StartCluster;
	u32 length = 0;

	while (cluster != SFFSLastNode)
	{
		if (!IsDataCluster(cluster))
		{
			Problem(ctx, "%s (inode %u): chain link 0x%04X is outside the data area", path, inode, cluster);
			return;
		}

		if (ctx->clusterOwner[cluster] != FSCK_NO_OWNER)
		{
			Problem(ctx, "%s (inode %u): cluster %u is also claimed by inode %u", path, inode, cluster,
			        ctx->clusterOwner[cluster]);
			return;
		}

		ctx->clusterOwner[cluster] = (u16)inode;
		length++;
		ctx->chainClusters++;

		if (length > ctx->fatEntryCount)
		{
			Problem(ctx, "%s (inode %u): cluster chain does not terminate", path, inode);
			return;
		}

		cluster = ctx->superblock->FatEntries[cluster];
	}

	const u32 expected = (entry->FileSize + (CLUSTER_SIZE - 1)) >> CLUSTER_SIZE_SHIFT;
	if (length != expected)
		Problem(ctx, "%s (inode %u): size %u needs %u cluster%s but the chain holds %u", path, inode,
		        entry->FileSize, expected, expected == 1 ? "" : "s", length);

	if ((entry->FileSize & FILE_DELETED_FLAG) != 0)
		Problem(ctx, "%s (inode %u): still marked pending delete", path, inode);
}

/* Recursively walk a directory's child list. */
static void CheckDirectory(FsckContext* ctx, u32 inode, const char* path, u32 depth)
{
	if (depth > 64)
	{
		Problem(ctx, "%s: directory nesting deeper than 64 levels, not descending", path);
		return;
	}

	FileSystemTableEntry* entry = GetFstEntry(ctx->superblock, inode);
	u32 child = entry->StartCluster;
	u32 seen = 0;

	while (child != SFFSErasedNode)
	{
		if (child >= ctx->fstEntryCount)
		{
			Problem(ctx, "%s: child inode %u is out of range", path, child);
			return;
		}

		if (ctx->inodeSeen[child])
		{
			Problem(ctx, "%s: inode %u is reachable more than once (sibling loop or shared entry)", path, child);
			return;
		}
		ctx->inodeSeen[child] = 1;

		if (++seen > ctx->fstEntryCount)
		{
			Problem(ctx, "%s: sibling chain does not terminate", path);
			return;
		}

		FileSystemTableEntry* childEntry = GetFstEntry(ctx->superblock, child);
		char name[MAX_FILE_SIZE + 1];
		EntryName(childEntry, name);

		/* Build the child's path for reporting. */
		char childPath[MAX_FILE_PATH];
		snprintf(childPath, sizeof(childPath), "%s%s%s", path, (strcmp(path, "/") == 0) ? "" : "/", name);

		switch (childEntry->Mode.Fields.Type)
		{
			case S_IFREG:
				ctx->fileCount++;
				CheckFileChain(ctx, child, childPath);
				break;

			case S_IFDIR:
				ctx->dirCount++;
				CheckDirectory(ctx, child, childPath, depth + 1);
				break;

			default:
				Problem(ctx, "%s (inode %u): unexpected entry type %u", childPath, child,
				        childEntry->Mode.Fields.Type);
				break;
		}

		child = childEntry->Sibling;
	}
}

int CmdFsck(void)
{
	FsckContext ctx;
	memset(&ctx, 0, sizeof(ctx));

	ctx.superblock = SelectSuperBlock();
	if (ctx.superblock == NULL)
	{
		fprintf(stderr, "fsck: no filesystem\n");
		return 1;
	}

	ctx.fstEntryCount = GetFstEntryCount();
	ctx.fatEntryCount = GetFatArraySize() / sizeof(u16);

	ctx.inodeSeen = calloc(ctx.fstEntryCount, 1);
	ctx.clusterOwner = malloc(ctx.fatEntryCount * sizeof(u16));
	if (ctx.inodeSeen == NULL || ctx.clusterOwner == NULL)
	{
		fprintf(stderr, "fsck: out of memory\n");
		free(ctx.inodeSeen);
		free(ctx.clusterOwner);
		return 1;
	}
	for (u32 i = 0; i < ctx.fatEntryCount; i++) ctx.clusterOwner[i] = FSCK_NO_OWNER;

	/* 1. Inode tree, starting at the root. */
	FileSystemTableEntry* root = GetFstEntry(ctx.superblock, 0);
	if (root->Mode.Fields.Type != S_IFDIR)
		Problem(&ctx, "root inode 0 is not a directory (type %u)", root->Mode.Fields.Type);

	ctx.inodeSeen[0] = 1;
	ctx.dirCount++;
	CheckDirectory(&ctx, 0, "/", 0);

	/* 2. Unreachable FST entries: in use but not part of the tree. */
	u32 unreachable = 0;
	for (u32 inode = 0; inode < ctx.fstEntryCount; inode++)
	{
		FileSystemTableEntry* entry = GetFstEntry(ctx.superblock, inode);
		if (entry->Mode.Fields.Type == S_IFZERO || ctx.inodeSeen[inode])
			continue;

		char name[MAX_FILE_SIZE + 1];
		EntryName(entry, name);
		Problem(&ctx, "inode %u ('%s') is in use but not reachable from the root", inode, name);
		unreachable++;
	}

	/* 3. Orphaned clusters: marked in use but owned by no file. */
	const u32 firstCluster = GetFirstDataCluster();
	const u32 clusterCount = GetDataClusterCount();
	u32 orphans = 0;
	u32 used = 0, free_ = 0, bad = 0, reserved = 0;

	for (u32 cluster = firstCluster; cluster < firstCluster + clusterCount; cluster++)
	{
		const u16 fat = ctx.superblock->FatEntries[cluster];

		if (fat == SFFSBadNode)
			bad++;
		else if (fat == SFFSFreeNode || fat == SFFSErasedNode)
			free_++;
		else if (fat == SFFSReservedNode)
			reserved++;
		else
		{
			used++;
			if (ctx.clusterOwner[cluster] == FSCK_NO_OWNER)
				orphans++;
		}
	}

	if (orphans != 0)
		Problem(&ctx, "%u cluster%s marked in use but owned by no file (leaked space)", orphans,
		        orphans == 1 ? " is" : "s are");

	/* 4. Cross-check the superblock statistics against a fresh count. */
	SFFSStatistics stats;
	if (GetStats(&stats) == IPC_SUCCESS)
	{
		if (stats.UsedClusters != used)
			Problem(&ctx, "statistics disagree: used clusters %u recorded, %u counted", stats.UsedClusters, used);
		if (stats.FreeClusters != free_)
			Problem(&ctx, "statistics disagree: free clusters %u recorded, %u counted", stats.FreeClusters, free_);
		if (stats.BadClusters != bad)
			Problem(&ctx, "statistics disagree: bad clusters %u recorded, %u counted", stats.BadClusters, bad);
		if (stats.ReservedClusters != reserved)
			Problem(&ctx, "statistics disagree: reserved clusters %u recorded, %u counted", stats.ReservedClusters,
			        reserved);
	}

	printf("checked %u director%s, %u file%s, %u cluster%s in use\n", ctx.dirCount, ctx.dirCount == 1 ? "y" : "ies",
	       ctx.fileCount, ctx.fileCount == 1 ? "" : "s", used, used == 1 ? "" : "s");

	if (ctx.problems == 0)
		printf("filesystem is consistent\n");
	else
		printf("%u problem%s found\n", ctx.problems, ctx.problems == 1 ? "" : "s");

	free(ctx.inodeSeen);
	free(ctx.clusterOwner);
	return ctx.problems == 0 ? 0 : 1;
}
