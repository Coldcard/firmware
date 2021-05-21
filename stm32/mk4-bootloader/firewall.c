//
// (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// firewall.c
//
// C-level code to enable the firewall feature. All **outside** the firewall.
//
#include <errno.h>
#include "basics.h"
#include "stm32l4xx_hal_firewall.h"
#include "stm32l4xx_hal_rcc.h"
#include "storage.h"
#include "constant_time.h"


// firewall_setup()
//
// It's best if this is outside the firewall. After we return, we'll
// jump into setup code contained inside the firewall. Called from startup.S
//
    void
firewall_setup(void)
{
    // This is critical: without the clock enabled to "SYSCFG" we
    // can't tell the FW is enabled or not! Enabling it would also not work
    __HAL_RCC_SYSCFG_CLK_ENABLE();

    if(__HAL_FIREWALL_IS_ENABLED()) {
        // After the first (POR) reset, the firewall may already be enabled, and if so
        // we can't change it anyway, so we're done.
        return;
    }

#if RELEASE
    // REMINDERS: 
    // - cannot debug anything in boot loader w/ firewall enabled (no readback, no bkpt)
    // - when RDP=2, this protection still important or else python can read pairing secret
    // - in factory mode (RDP!=2), it's nice to have this disabled so we can debug still
    // - could look at RDP level here, but it would be harder to completely reset the bag number!
    if(check_all_ones(rom_secrets->bag_number, sizeof(rom_secrets->bag_number))) {
        // ok. still virgin unit -- run w/o security
        return;
    }
#else
    // for debug builds, never enable firewall
    return;
#endif

    extern int firewall_starts;       // see startup.S ... aligned@256 (0x08000300)
    uint32_t    start = (uint32_t)&firewall_starts;
    uint32_t    len = BL_FLASH_SIZE - (start - BL_FLASH_BASE);

#if 1
    ASSERT(start);
    ASSERT(!(start & 0xff));
    ASSERT(len>256);
    ASSERT(!(len & 0xff));
#endif

    // NOTE: the "Non volatile data segment" is not executable, and so cannot
    //       overlap the "Code Segment". Not clear why it's ever useful, but
    // maybe so you can prevent execution on that section, or have it somewhere
    // else I suppose.
    //
    // - many of the bits in these registers are not-implemented and are forced to zero
    // - that prevents the firewall being used for things like protecting OTP area
    // - (Mk1-3) volatile data is SRAM1 only, so doesn't help us, since we're using SRAM2
    // - (Mk4) we are in SRAM1, so we could protect all our RAM ... but errata 2.4.2 fucks that
    // - on-chip DFU will erase up to start (0x300), which borks the reset vector 
    //   but sensitive stuff is still there (which would allow bypass)
    // - so it's important to enable option bytes to set write-protect on entire bootloader
    // - to disable debug and complete protection, must enable write-protect "level 2"
    //

    FIREWALL_InitTypeDef init = {
        .CodeSegmentStartAddress = start,
        .CodeSegmentLength = len,
        .NonVDataSegmentStartAddress = BL_NVROM_BASE,
        .NonVDataSegmentLength = BL_NVROM_SIZE,
        .VDataSegmentStartAddress = 0,
        .VDataSegmentLength = 0,
        .VolatileDataExecution = 0,
        .VolatileDataShared = 0,
    };

    int rv = HAL_FIREWALL_Config((FIREWALL_InitTypeDef *)&init);
    if(rv) {
        INCONSISTENT("fw");
    }

    __HAL_FIREWALL_PREARM_DISABLE();
    HAL_FIREWALL_EnableFirewall();
}

// EOF
