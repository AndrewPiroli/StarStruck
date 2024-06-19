/*
	mini - a Free Software replacement for the Nintendo/BroadOn IOS.

Copyright (C) 2008, 2009	Haxx Enterprises <bushing@gmail.com>
Copyright (C) 2008, 2009	Sven Peter <svenpeter@gmail.com>
Copyright (C) 2008, 2009	Hector Martin "marcan" <marcan@marcansoft.com>
Copyright (C) 2009			Andre Heider "dhewg" <dhewg@wiibrew.org>
Copyright (C) 2009		John Kelley <wiidev@kelley.ca>

# This code is licensed to you under the terms of the GNU GPL, version 2;
# see file COPYING or http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
*/

#include <types.h>
#include <string.h>
#include <git_version.h>
#include <ios/processor.h>
#include <ios/printk.h>
#include <ios/gecko.h>
#include <ios/module.h>

#include "core/hollywood.h"
#include "core/gpio.h"
#include "core/pll.h"
#include "memory/memory.h"
#include "memory/heaps.h"
#include "memory/ahb.h"
#include "interrupt/exception.h"
#include "messaging/ipc.h"
#include "scheduler/timer.h"
#include "scheduler/threads.h"
#include "interrupt/irq.h"
#include "peripherals/usb.h"
#include "crypto/aes.h"
#include "crypto/sha.h"
#include "utils.h"
#include "elf.h"

#include "sdhc.h"
#include "ff.h"
#include "panic.h"
#include "powerpc_elf.h"
#include "crypto.h"
#include "nand.h"
#include "boot2.h"

#define PPC_BOOT_FILE "/bootmii/ppcboot.elf"
#define IN_EMULATOR

FATFS fatfs;
extern const u32 __ipc_heap_start[];
extern const u32 __ipc_heap_size[];
extern const u32 __headers_addr[];
extern const ModuleInfo __modules[];
extern const u32 __modules_size;

void DiThread()
{
	u32 messages[1];
	u32 msg;

	s32 ret = CreateMessageQueue((void**)&messages, 1);
	if(ret < 0)
		panic("Unable to create DI thread message queue: %d\n", ret);
	
	const u32 queueId = (u32)ret;
	CreateTimer(0, 2500, queueId, (void*)0xbabecafe);
	while(1)
	{
		//don't ask. i have no idea why this is here haha
		for(u32 i = 0; i < 0x1800000; i += 0x80000)
		{
			for(u32 y = 0; y < 6; y++){}
		}
		ReceiveMessage(queueId, (void **)&msg, None);
	}
}

void kernel_main( void )
{
	//volatile u32* test = (volatile u32*)0xCCCCCCCC;
	//printk("%d\n", *test);
	//create IRQ Timer handler thread
	s32 ret = CreateThread((u32)TimerHandler, NULL, NULL, 0, 0x7E, 1);
	u32 threadId = (u32)ret;
	//set thread to run as a system thread
	if(ret >= 0)
		Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;
	
	if( ret < 0 || StartThread(threadId) < 0 )
		panic("failed to start IRQ thread!\n");

	//not sure what this is about, if you know please let us know.
	u32 hardwareVersion, hardwareRevision;
	GetHollywoodVersion(&hardwareVersion,&hardwareRevision);
	if (hardwareVersion == 0)
	{
		u32 dvdConfig = read32(HW_DI_CFG);
		u32 unknownConfig = dvdConfig >> 2 & 1;
		if ((unknownConfig != 0) && ((~(dvdConfig >> 3) & 1) == 0)) 
		{
			threadId = (u32)CreateThread((u32)DiThread, NULL, NULL, 0, 0x78, unknownConfig);
			Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;
			StartThread(threadId);
		}
	}

	//create AES Engine handler thread & also set it to run as system thread
	ret = CreateThread((u32)AesEngineHandler, NULL, NULL, 0, 0x7E, 1);
	threadId = (u32)ret;
	if(ret >= 0)
		Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;

	if( ret < 0 || StartThread(threadId) < 0 )
		panic("failed to start AES thread!\n");	

	//create SHA Engine handler thread & also set it to run as system thread
	ret = CreateThread((u32)ShaEngineHandler, NULL, NULL, 0, 0x7E, 1);
	threadId = (u32)ret;
	if(ret > 0)
		Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;

	if( ret < 0 || StartThread(threadId) < 0 )
		panic("failed to start SHA thread!\n");

	/// TODO: Some function goes here, needs research

	//create IPC handler thread & also set it to run as system thread
	ret = CreateThread((u32)IpcHandler, NULL, NULL, 0, 0x5C, 1);
	threadId = (u32)ret;
	if(ret > 0)
	{
		Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;
		IpcHandlerThread = &Threads[threadId];
		IpcHandlerThreadId = (u32)threadId;
	}

	if( ret < 0 || StartThread(threadId) < 0 )
		panic("failed to start IPC thread!\n");

	//loop the program headers and map/launch all modules
	Elf32_Phdr* headers = (Elf32_Phdr*)__headers_addr;
	for(u32 index = 1; index < 0x0F; index++)
	{
		MemorySection section;
		Elf32_Phdr header = headers[index];
		if(header.p_type != PT_LOAD || (header.p_flags & 0x0FF00000) == 0 || header.p_vaddr == (u32)__headers_addr)
			continue;
		
		section.PhysicalAddress = header.p_paddr;
		section.VirtualAddress = header.p_vaddr;
		section.Domain = FLAGSTODOMAIN(header.p_flags);
		section.Size = (header.p_memsz + 0xFFF) & 0xFFFFF000;

		//set section access
		if(header.p_flags & PF_X)
			section.AccessRights = AP_ROUSER;
		else if(header.p_flags & PF_W)
			section.AccessRights = AP_RWUSER;
		else if(header.p_flags & PF_R)
			section.AccessRights = AP_ROM;
		else
			section.AccessRights = AP_ROUSER;

		section.IsCached = 1;
		s32 ret = MapMemory(&section);
		if(ret != 0)
			panic("Unable to map region %08x [%d bytes]\n", section.VirtualAddress, section.Size);
		
		//map cached version
		section.VirtualAddress |= 0x80000000;
		section.IsCached = 0;
		ret = MapMemory(&section);
		if(ret != 0)
			panic("Unable to map region %08x [%d bytes]\n", section.VirtualAddress, section.Size);
		
		printk("load segment @ [%08x, %08x] (%d bytes)\n", header.p_vaddr, header.p_vaddr + header.p_memsz, header.p_memsz);

		//clear memory that didn't have stuff loaded in from the elf
		if(header.p_filesz < header.p_memsz)
			memset((void*)(header.p_vaddr + header.p_filesz), 0, header.p_memsz - header.p_filesz);
	}

	const u32 modules_cnt = __modules_size / sizeof(ModuleInfo);
	for(u32 i = 0; i < modules_cnt;i++)
	{
		u32 main = __modules[i].EntryPoint;
		u32 stackSize = __modules[i].StackSize;
		u32 priority = __modules[i].Priority;
		u32 stackTop = __modules[i].StackAddress;
		u32 arg = __modules[i].UserId;
		 
		printk("priority = %d, stackSize = %d, stackPtr = %d\n", priority, stackSize, stackTop);
		printk("starting thread entry: 0x%x\n", main);

		threadId = (u32)CreateThread(main, (void*)arg, (u32*)stackTop, stackSize, priority, 1);
		Threads[threadId].ProcessId = arg;
		StartThread(threadId);
	}

	KernelHeapId = CreateHeap((void*)__headers_addr, 0xC0000);
	printk("$IOSVersion: IOSP: %s %s 64M $", __DATE__, __TIME__);
	SetThreadPriority(0, 0);
	SetThreadPriority(IpcHandlerThreadId, 0x5C);
	u32 vector;
	FRESULT fres = 0;

	//while(1){}
	
	crypto_initialize();
	printk("crypto support initialized\n");

	nand_initialize();
	printk("NAND initialized.\n");

	boot2_init();
	
	printk("Initializing SDHC...\n");
	sdhc_init();
	printk("Mounting SD...\n");
	fres = f_mount(&fatfs, "", 0);
	printk("Got %d from f_mount", fres);
#if 0
	printk("AP DBG nrootdir", fatfs.n_rootdir);
	FIL test;
	printk("fopen: %i\n", f_open(&test, "/test.txt", FA_READ));
	int num_read;
	u8* buf = KMalloc(128);
	int test_res = f_read(&test, &buf, 128, &num_read);
	printk("f_read: %d. Bytes read: %d\n", test_res, num_read);
	buf[128] = 0;
	printk("File contents: %s\n", buf);
#else
	DIR rd;
	printk("DBG: opendir: %d\n", f_opendir(&rd, "/"));
	FILINFO fi = {0};
	int xres;
	printk("DBG: Emulated SD Card Root Directory Listing\n");
	while (((xres = f_readdir(&rd, &fi)) == FR_OK) && fi.fname[0] != '\0') {
		printk("DBG: got file name: %s size: %ld\n", fi.fname, fi.fsize);
	}
	if (xres != FR_OK) {
		printk("DBG: readdir fail %d\n", xres);
	}
	else {
		printk("DBG: File Listing end\n");
		f_closedir(&rd);
		FIL test_txt;
		int yres = f_open(&test_txt, "/TEST.TXT", FA_READ);
		printk("DBG: trying to open TEST.TXT f_open=%d\n", yres);
		if (yres == FR_OK) {
			u8 buf = KMalloc(128);
			int bytes_read = 0;
			memset(buf, 0, 128);
			printk("DBG: TEST.TXT fread = %d\n", f_read(&test_txt, buf, 128, &bytes_read));
			printk("DBG: TEST.TXT bytes read=%d\n", bytes_read);
			printk("DBG: TEST.TXT file contents %s\n", buf);
		}
	}
#endif

#ifdef IN_EMULATOR
	// unmask IPC IRQ
	write32(HW_PPCIRQMASK, (1<<30));
	// send an ack
	write32(HW_IPC_ARMCTRL, read32(HW_IPC_ARMCTRL) | 0x08);
#endif
	asm __volatile__ ("loop:\n\
			nop\n \
			b loop");

	if (read32(HW_CLOCKS) & 2) {
		printk("GameCube compatibility mode detected...\n");
		vector = boot2_run(1, 0x101);
		goto shutdown;
	}

	if(fres != FR_OK) {
		printk("Error %d while trying to mount SD\n", fres);
		panic2(0, PANIC_MOUNT);
	}

	DisableInterrupts();
	printk("rebooting into HBC...\n");
	vector = boot2_run(0x00010001, 0x4C554C5A);
	ipc_shutdown();

shutdown:
	printk("Shutting down...\n");
	printk("interrupts...\n");
	irq_shutdown();
	printk("caches and MMU...\n");
	mem_shutdown();

	printk("Vectoring to 0x%08x...\n", vector);
	//go to whatever address we got
	asm("bx\t%0": : "r" (vector));
}

void SetStarletClock()
{
	u32 hardwareVersion = 0;
	u32 hardwareRevision = 0;
	GetHollywoodVersion(&hardwareVersion, &hardwareRevision);
	
	if(hardwareVersion < 2)
	{
		write32(HW_IOSTRCTRL0, 0x65244A);
		write32(HW_IOSTRCTRL1, 0x46A024);
	}
	else
	{
		write32(HW_IOSTRCTRL0, (read32(HW_IOSTRCTRL0) & 0xFF000000 ) | 0x292449);
		write32(HW_IOSTRCTRL1, (read32(HW_IOSTRCTRL1) & 0xFE000000) | 0x46A012);
	}
}

void InitialiseSystem( void )
{
	u32 hardwareVersion = 0;
	u32 hardwareRevision = 0;
	GetHollywoodVersion(&hardwareVersion, &hardwareRevision);
	//something to do with flipper?
	set32(HW_EXICTRL, EXICTRL_ENABLE_EXI);
	
	//enable protection on our MEM2 addresses & SRAM
	ProtectMemory(1, (void*)0x13620000, (void*)0x1FFFFFFF);
	
	//????
	write32(HW_EXICTRL, read32(HW_EXICTRL) & 0xFFFFFFEF );
	
	//set some hollywood ahb registers????
	if(hardwareVersion == 1 && hardwareRevision == 0)
		write32(HW_ARB_CFG_CPU, (read32(HW_ARB_CFG_CPU) & 0xFFFF000F) | 1);
	
	// ¯\_(ツ)_/¯
	write32(HW_AHB_10, 0);
	
	//Set boot0 B10 & B11? found in IOS58.
	set32(HW_BOOT0, 0xC00);
	
	//Configure PPL ( phase locked loop )
	ConfigureAiPLL(0, 0);
	ConfigureVideoInterfacePLL(0);
	
	//Configure USB Host
	ConfigureUsbController(hardwareRevision);
	
	//Configure GPIO pins
	ConfigureGPIO();
	ResetGPIODevices();
	
	//Set clock speed
	SetStarletClock();
	
	//reset registers
	write32(HW_GPIO1OWNER, read32(HW_GPIO1OWNER) & (( 0xFF000000 | GP_ALL ) ^ GP_DISPIN));
	write32(HW_GPIO1DIR, read32(HW_GPIO1DIR) | GP_DISPIN);
	write32(HW_ALARM, 0);
	write32(NAND_CMD, 0);
	write32(AES_CMD, 0);
	write32(SHA_CMD, 0);
	
	//Enable all ARM irq's except for 2 unknown irq's ( 0x4200 )
	write32(HW_ARMIRQFLAG, 0xFFFFBDFF);
	write32(HW_ARMIRQMASK, 0);
	write32(HW_ARMFIQMASK, 0);
	
	gecko_printf("Configuring caches and MMU...\n");
	InitializeMemory();
}

u32 _main(void)
{
	gecko_init();
	//don't use printk before our main thread started. our stackpointers are god knows were at that point & thread context isn't init yet
	gecko_printf("StarStruck %s loading\n", git_version);	
	gecko_printf("Initializing exceptions...\n");
	initializeExceptions();

	AhbFlushFrom(AHB_1);
	AhbFlushTo(AHB_1);
	
	InitialiseSystem();	

	gecko_printf("IOSflags: %08x %08x %08x\n",
		read32(0xffffff00), read32(0xffffff04), read32(0xffffff08));
	gecko_printf("          %08x %08x %08x\n",
		read32(0xffffff0c), read32(0xffffff10), read32(0xffffff14));

	IrqInit();
	IpcInit();
	
	//currently unknown if these values are used in the kernel itself.
	//if they are, these need to be replaced with actual stuff from the linker script!
	write32(MEM1_MEM2PHYSICALSIZE, 0x4000000);
	write32(MEM1_MEM2SIMULATESIZE, 0x4000000);
	write32(MEM1_MEM2INITLOW, MEM2_PHY2VIRT(0x10000800));
	write32(MEM1_MEM2INITHIGH, MEM2_PHY2VIRT(0x135e0000));
	write32(MEM1_IOSIPCLOW, MEM2_PHY2VIRT(0x135e0000));
	write32(MEM1_MEM2BAT, MEM2_PHY2VIRT((u32)__ipc_heap_start));
	write32(MEM1_IOSIPCHIGH, MEM2_PHY2VIRT((u32)__ipc_heap_start));
	write32(MEM1_IOSHEAPLOW, MEM2_PHY2VIRT((u32)__ipc_heap_start));
	write32(MEM1_IOSHEAPHIGH, MEM2_PHY2VIRT((u32)__ipc_heap_start + (u32)__ipc_heap_size));
	DCFlushRange((void*)0x00003100, 0x68);
	gecko_printf("Updated DDR settings in lomem for current map\n");
	
	//init&start main code next : 
	//-------------------------------
	//init thread context handles
	InitializeThreadContext();

	//create main kernel thread
	u32 threadId = (u32)CreateThread((u32)kernel_main, NULL, NULL, 0, 0x7F, 1);
	//set thread to run as a system thread
	Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;
	
	if( threadId != 0 || StartThread(threadId) < 0 )
		gecko_printf("failed to start kernel(%d)!\n", threadId);

	panic("\npanic!\n");
	return 0;
}

