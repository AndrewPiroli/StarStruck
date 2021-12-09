/*
	starstruck - a Free Software reimplementation for the Nintendo/BroadOn IOS.
	heaps - management of memory heaps

	Copyright (C) 2021	DacoTaco

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include <errno.h>
#include <ios/processor.h>
#include <ios/gecko.h>

#include "core/defines.h"
#include "memory/heaps.h"
#include "memory/memory.h"
#include "interrupt/irq.h"
#include "interrupt/threads.h"

#define ALIGNED_BLOCK_HEADER_SIZE	((sizeof(heap_block) + 0x0F) & -0x10)
#define MAX_HEAP 					0x10

static heap_info heaps[MAX_HEAP];

s32 CreateHeap(void *ptr, u32 size)
{
	s32 irq_state = irq_kill();
	s8 heap_index = 0;
	
	if(ptr == NULL || ((u32)ptr & 0x1f) != 0 || size < 0x30 || CheckMemoryPointer(ptr, size, 4, currentThread->processId, 0) < 0 )
	{
		heap_index = -4;
		goto restore_and_return;
	}
	
	while(heap_index < MAX_HEAP && heaps[heap_index].heap != NULL)
		heap_index++;
	
	if(heap_index >= MAX_HEAP)
	{
		heap_index = -5;
		goto restore_and_return;
	}

	heap_block* firstBlock = (heap_block*)ptr;
	firstBlock->blockFlag = HEAP_INIT_FLAG;
	firstBlock->size = size - ALIGNED_BLOCK_HEADER_SIZE;
	firstBlock->prevBlock = NULL;
	firstBlock->nextBlock = NULL;
	
	heaps[heap_index].heap = ptr;
	heaps[heap_index].size = size;
	heaps[heap_index].firstBlock = firstBlock;
	
restore_and_return:
	irq_restore(irq_state);
	return heap_index;
}

s32 DestroyHeap(s32 heapid)
{
	s32 irq_state = irq_kill();
	s32 ret = 0;
	
	if(heapid < 0 || heapid > MAX_HEAP)
	{
		ret = -4;
		goto restore_and_return;
	}
	
	if(heaps[heapid].heap != NULL)
	{
		heaps[heapid].heap = NULL;
		heaps[heapid].size = 0;
		heaps[heapid].firstBlock = NULL;
	}
	
restore_and_return:
	irq_restore(irq_state);
	return ret;
}

void* AllocateOnHeap(s32 heapid, u32 size)
{
	return MallocateOnHeap(heapid, size, 0x20);
}

void* MallocateOnHeap(s32 heapid, u32 size, u32 alignment)
{
	s32 irq_state = irq_kill();
	u32 ret = 0;
	
	if(	heapid < 0 || heapid > MAX_HEAP || !heaps[heapid].heap || 
		size == 0 || heaps[heapid].size < size || alignment < 0x20)
	{
		goto restore_and_return;
	}
		
	if(heaps[heapid].heap == NULL)
		goto restore_and_return;
	
	//align size by 0x20
	u32 alignedSize = (size + 0x1F) & -0x20;
	heap_block* currentBlock = heaps[heapid].firstBlock;
	heap_block* blockToAllocate = NULL;
	u32 blockSize = 0;
	u32 alignedOffset = 0;
	
	//find the best fitting block that is free
	while(currentBlock != NULL)
	{
		blockSize = currentBlock->size;
		alignedOffset = (alignment - ((u32)(currentBlock + 1) & (alignment - 1))) & (alignment -1);
		
		if( alignedSize + alignedOffset <= blockSize && (blockToAllocate == NULL || blockSize < blockToAllocate->size))
			blockToAllocate = currentBlock;
		
		currentBlock = currentBlock->nextBlock;
		
		if( blockToAllocate != NULL && blockToAllocate->size == alignedSize + alignedOffset)
			break;
	}
	
	if(blockToAllocate == NULL)
		goto restore_and_return;
	
	heap_block* freeBlock = NULL;
	//split up the block if its big enough to do so
	if (alignedSize + alignedOffset + ALIGNED_BLOCK_HEADER_SIZE < blockSize) 
	{
		blockToAllocate->size = alignedSize + alignedOffset + ALIGNED_BLOCK_HEADER_SIZE;		
		freeBlock = (heap_block*)(((u32)blockToAllocate) + blockToAllocate->size);
		freeBlock->blockFlag = HEAP_INIT_FLAG;
		freeBlock->size = blockSize - (blockToAllocate->size);
		freeBlock->prevBlock = blockToAllocate->prevBlock;
		freeBlock->nextBlock = blockToAllocate->nextBlock;
	}
	else
		freeBlock = blockToAllocate->nextBlock;
	
	//remove from heap list
	currentBlock = blockToAllocate->prevBlock;
	if(currentBlock == NULL )
	{
		heaps[heapid].firstBlock = freeBlock;
		currentBlock = freeBlock;
	}
	else
		currentBlock->nextBlock = freeBlock;
	
	if(currentBlock->nextBlock != NULL)
		currentBlock->nextBlock->prevBlock = currentBlock;
	
	//mark block as in use & remove it from our available heap
	blockToAllocate->blockFlag = HEAP_INUSE_FLAG;
	blockToAllocate->nextBlock = NULL;
	blockToAllocate->prevBlock = NULL;
	
	//add the block header infront of the allocated space if needed (because of alignment)
	currentBlock = (heap_block*)(((u32)blockToAllocate) + alignedOffset);
	if(alignedOffset != 0)
	{
		currentBlock->blockFlag = HEAP_ALIGNED_FLAG;
		currentBlock->nextBlock = blockToAllocate;
	}
	
	//get pointer and clear it!
	ret = (u32)(currentBlock + 1);
	if(ret)
		memset8((u8*)ret, 0, size);

restore_and_return:
	irq_restore(irq_state);
	return (void*)ret;
}

int MergeNextBlockIfUnused(heap_block* parentBlock)
{
	if(parentBlock == NULL || parentBlock->nextBlock == NULL)
		return 0;
	
	u32 blockSize = parentBlock->size;
	heap_block * blockToMerge = parentBlock->nextBlock;

	if(blockToMerge != (heap_block*)(((u32)parentBlock) + blockSize))
		return 0;

	//link parent block with the tomerge's next block and vice versa
	heap_block* nextBlock = blockToMerge->nextBlock;
	parentBlock->nextBlock = nextBlock;
	if(nextBlock != NULL)
		nextBlock->prevBlock = parentBlock;
	
	//merge sizes
	parentBlock->size = blockSize + blockToMerge->size;
	return 1;
}

s32 FreeOnHeap(s32 heapid, void* ptr)
{
	s32 irq_state = irq_kill();
	s32 ret = 0;
	
	//verify incoming parameters & if the heap is in use
	if(heapid < 0 || heapid >= 0x10 || ptr == NULL || heaps[heapid].heap == NULL)
	{
		ret = -4;
		goto restore_and_return;
	}
	
	//verify the pointer address
	if( ptr < (heaps[heapid].heap + sizeof(heap_block)) || ptr >= (heaps[heapid].heap + heaps[heapid].size) )
	{
		ret = -4;
		goto restore_and_return;
	}
	
	//verify the block that the pointer belongs to
	heap_block* blockToFree = (heap_block*)(ptr-sizeof(heap_block));
	
	if(blockToFree->blockFlag == HEAP_ALIGNED_FLAG)
		blockToFree = blockToFree->nextBlock;
	
	if(blockToFree == NULL || blockToFree->blockFlag != HEAP_INUSE_FLAG)
	{
		ret = -4;
		goto restore_and_return;
	}
	
	heap_block* firstBlock = heaps[heapid].firstBlock;
	heap_block* currBlock = firstBlock;
	heap_block* nextBlock = NULL;
	blockToFree->blockFlag = HEAP_INIT_FLAG;
	
	while(currBlock != NULL)
	{
		nextBlock = currBlock->nextBlock;
		if(nextBlock == NULL || blockToFree < nextBlock)
			break;
		
		currBlock = nextBlock;
	}

	//move block to the front
	if (currBlock == NULL || blockToFree <= firstBlock)
	{
		blockToFree->nextBlock = firstBlock;
		heaps[heapid].firstBlock = blockToFree;
		blockToFree->prevBlock = NULL;
	}
	//just place the block infront of the block closest to us
	else
	{
		blockToFree->prevBlock = currBlock;
		blockToFree->nextBlock = currBlock->nextBlock;
		currBlock->nextBlock = blockToFree;
	}
	
	//link the next block if needed
	if(blockToFree->nextBlock != NULL)
		blockToFree->nextBlock->prevBlock = blockToFree;
	
	//merge blocks if we can
	MergeNextBlockIfUnused(blockToFree);
	MergeNextBlockIfUnused(blockToFree->prevBlock);

restore_and_return:
	irq_restore(irq_state);
	return ret;
}