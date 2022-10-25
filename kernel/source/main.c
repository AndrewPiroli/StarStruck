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

#include "core/hollywood.h"
#include "core/gpio.h"
#include "core/pll.h"
#include "memory/memory.h"
#include "memory/ahb.h"
#include "interrupt/exception.h"
#include "messaging/ipc.h"
#include "scheduler/timer.h"
#include "scheduler/threads.h"
#include "interrupt/irq.h"
#include "peripherals/usb.h"
#include "utils.h"

#include "sdhc.h"
#include "ff.h"
#include "panic.h"
#include "powerpc_elf.h"
#include "crypto.h"
#include "nand.h"
#include "boot2.h"

#define PPC_BOOT_FILE "/bootmii/ppcboot.elf"

FATFS fatfs;

void DiThread()
{
	u32 messages[1];
	u32 msg;
	s32 queueId = 0;

	queueId = CreateMessageQueue((void**)&messages, 1);
	if(queueId < 0)
		panic("Unable to create DI thread message queue: %d\n", queueId);

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
	//create IRQ Timer handler thread
	s32 threadId = CreateThread((s32)TimerHandler, NULL, NULL, 0, 0x7E, 1);
	//set thread to run as a system thread
	if(threadId >= 0)
		Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;
	
	if( threadId < 0 || StartThread(threadId) < 0 )
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
			threadId = CreateThread((s32)DiThread, NULL, NULL, 0, 0x78, unknownConfig);
			Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;
			StartThread(threadId);
		}
	}

	u32 vector;
	FRESULT fres = 0;
	
	crypto_initialize();
	printk("crypto support initialized\n");

	nand_initialize();
	printk("NAND initialized.\n");

	boot2_init();

	printk("Initializing IPC...\n");
	ipc_initialize();
	
	/*printk("Initializing SDHC...\n");
	sdhc_init();

	printk("Mounting SD...\n");
	fres = f_mount(0, &fatfs);*/

	if (read32(HW_CLOCKS) & 2) {
		printk("GameCube compatibility mode detected...\n");
		vector = boot2_run(1, 0x101);
		goto shutdown;
	}

	if(fres != FR_OK) {
		printk("Error %d while trying to mount SD\n", fres);
		panic2(0, PANIC_MOUNT);
	}

	ipc_ppc_boot_title(0x000100014C554C5ALL);
	printk("Going into IPC mainloop...\n");
	vector = ipc_main();
	printk("IPC mainloop done! killing IPC...\n");
	ipc_shutdown();

shutdown:
	printk("Shutting down...\ninterrupts...\n");
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
	write32(MEM1_IOSHEAPLOW, MEM2_PHY2VIRT(0x135e0000));
	write32(MEM1_MEM2BAT, MEM2_PHY2VIRT(0x13600000));
	write32(MEM1_IOSHEAPHIGH, MEM2_PHY2VIRT(0x13600000));
	write32(MEM1_3148, MEM2_PHY2VIRT(0x13600000));
	write32(MEM1_314C, MEM2_PHY2VIRT(0x13620000));
	DCFlushRange((void*)0x00003100, 0x68);
	gecko_printf("Updated DDR settings in lomem for current map\n");
	
	//init&start main code next : 
	//-------------------------------
	//init thread context handles
	InitializeThreadContext();

	//create main kernel thread
	s32 threadId = CreateThread((s32)kernel_main, NULL, NULL, 0, 0x7F, 1);
	//set thread to run as a system thread
	Threads[threadId].ThreadContext.StatusRegister |= SPSR_SYSTEM_MODE;
	
	if( threadId < 0 || StartThread(threadId) < 0 )
		gecko_printf("failed to start kernel(%d)!\n", threadId);

	panic("\npanic!\n");
	return 0;
}

