/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * Setup and talk with the ESP-PSRAM64H chip, new on Mk4.
 *
 * CAUTION: All writes must be word aligned. Unaligned read okay.
 *
 */
#include "psram.h"
#include "oled.h"
#include "clocks.h"
#include "config.h"
#include SCREENS_H
#include <string.h>
#include "delay.h"
#include "rng.h"
#include "storage.h"
#include "sigheader.h"
#include "stm32l4xx_hal.h"
#include "verify.h"
#include "console.h"
#include "faster_sha256.h"
#include "misc.h"

#undef INCL_SELFTEST

#ifdef INCL_SELFTEST
static void psram_memtest(bool simple);
#endif

// Stash some data in PSRAM to survive brief power outages
#define RECHDR_POS          (recovery_header_t *)(PSRAM_BASE + PSRAM_SIZE - 2048)
#define RECHDR_MAGIC1       0xdbcc8350
#define RECHDR_MAGIC2       0xbafcfba3
typedef struct {
    uint32_t    magic1;
    const uint8_t     *start;
    uint32_t    size;
    uint32_t    magic2;
} recovery_header_t;

// psram_send_byte()
//
    void
psram_send_byte(OSPI_HandleTypeDef  *qh, uint8_t cmd_byte, bool is_quad)
{   
    // Send single-byte commands to the PSRAM chip. Quad mode or normal SPI.

    OSPI_RegularCmdTypeDef cmd = {
        .OperationType = HAL_OSPI_OPTYPE_COMMON_CFG,
        .Instruction = cmd_byte,                    // Exit Quad Mode
        .InstructionMode = is_quad ? HAL_OSPI_INSTRUCTION_4_LINES : HAL_OSPI_INSTRUCTION_1_LINE,
        .AddressMode = HAL_OSPI_ADDRESS_NONE,
        .AlternateBytesMode = HAL_OSPI_ALTERNATE_BYTES_NONE,
        .DummyCycles = 0,
        .DataMode = HAL_OSPI_DATA_NONE,
        .NbData = 0,                        // how much to read in bytes
    };

    // Start and finish a "Indirection functional mode" request
    HAL_OSPI_Command(qh, &cmd, HAL_MAX_DELAY);
}

// psram_setup()
//
    void
psram_setup(void)
{
    // Using OSPI1 block
    OSPI_HandleTypeDef  qh = { 0 };

    // enable clocks
    __HAL_RCC_OSPI1_CLK_ENABLE();
    __HAL_RCC_GPIOE_CLK_ENABLE();

    // reset module
    __HAL_RCC_OSPI1_FORCE_RESET();
    __HAL_RCC_OSPI1_RELEASE_RESET();

   // configure pins: Port E PE10-PE15
    GPIO_InitTypeDef setup = {
        .Pin = GPIO_PIN_10 | GPIO_PIN_11 | GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15,
        .Mode = GPIO_MODE_AF_PP,            // not sure
        .Pull = GPIO_NOPULL,                // not sure
        .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
        .Alternate = GPIO_AF10_OCTOSPIM_P1,
    };
    HAL_GPIO_Init(GPIOE, &setup);


    // Config operational values
    qh.Instance = OCTOSPI1;
    qh.Init.FifoThreshold = 1;                          // ?? unused
    qh.Init.DualQuad = HAL_OSPI_DUALQUAD_DISABLE;
    qh.Init.MemoryType = HAL_OSPI_MEMTYPE_MICRON;       // want standard mode (but octo only?)
    qh.Init.DeviceSize = 24;                    // assume max size, actual is 8Mbyte
    qh.Init.ChipSelectHighTime = 1;             // 1, maxed out, seems to work
    qh.Init.DelayHoldQuarterCycle = HAL_OSPI_DHQC_ENABLE;       // maybe?
    qh.Init.FreeRunningClock = HAL_OSPI_FREERUNCLK_DISABLE;     // required!
    qh.Init.ClockMode = HAL_OSPI_CLOCK_MODE_0;  // low clock between ops (required, see errata)
#if HCLK_FREQUENCY == 80000000
    qh.Init.ClockPrescaler = 1;                 // prescaler (1=>80Mhz, 2=>40Mhz, etc)
#elif HCLK_FREQUENCY == 120000000
    qh.Init.ClockPrescaler = 2;                 // prescaler (1=>120Mhz, 2=>60Mhz, etc)
#else
#   error "testing needed"
#endif
    qh.Init.DelayBlockBypass = HAL_OSPI_DELAY_BLOCK_BYPASSED;        // dont need it?

    // ESP-PSRAM64H calls for max of 8us w/ CS low. Needs it for refresh time.
    // - stm32 datasheet says min 3 here; found 1-3 all work
    // - zero works, but CS is never released (but doesn't seem to affect operation?)
    // - (during reads) 3 => 400ns  4 => 660ns   5+ => 1us 
    // - LATER: Errata 2.8.1 => says shall not use
    qh.Init.ChipSelectBoundary = 0;

    // module init 
    HAL_StatusTypeDef rv = HAL_OSPI_Init(&qh);
    ASSERT(rv == HAL_OK);

    // do some SPI commands first

    // Exit Quad mode, to get to a known state, after first power-up
    psram_send_byte(&qh, 0xf5, true);

    // Chip Reset sequence
    psram_send_byte(&qh, 0x66, false);      // reset enable
    psram_send_byte(&qh, 0x99, false);      // reset

    // Read Electronic ID
    // - length not clear from datasheet, but repeats after 8 bytes
    uint8_t psram_chip_eid[8];

    {   OSPI_RegularCmdTypeDef cmd = {
            .OperationType = HAL_OSPI_OPTYPE_COMMON_CFG,
            .Instruction = 0x9f,                    // "read ID" command
            .InstructionMode = HAL_OSPI_INSTRUCTION_1_LINE,
            .Address = 0,                           // dont care
            .AddressSize = HAL_OSPI_ADDRESS_24_BITS,
            .AddressMode = HAL_OSPI_ADDRESS_1_LINE,
            .AlternateBytesMode = HAL_OSPI_ALTERNATE_BYTES_NONE,
            .DummyCycles = 0,
            .DataMode = HAL_OSPI_DATA_1_LINE,
            .NbData = sizeof(psram_chip_eid),                        // how much to read in bytes
        };

        // Start a "Indirection functional mode" request
        rv = HAL_OSPI_Command(&qh, &cmd, HAL_MAX_DELAY);
        if(rv != HAL_OK) goto fail;

        rv = HAL_OSPI_Receive(&qh, psram_chip_eid, HAL_MAX_DELAY);
        if(rv != HAL_OK) goto fail;
    }

    //puts2("PSRAM EID: "); 
    //hex_dump(psram_chip_eid, sizeof(psram_chip_eid));
    ASSERT(psram_chip_eid[0] == 0x0d);
    ASSERT(psram_chip_eid[1] == 0x5d);
    // .. other bits seem pretty similar between devices, they don't claim they are UUID

    // Put into Quad mode
    psram_send_byte(&qh, 0x35, false);  // 0x35 = Enter Quad Mode

    // Configure read/write cycles for mem-mapped mode
    {   OSPI_RegularCmdTypeDef cmd = {
            .OperationType = HAL_OSPI_OPTYPE_WRITE_CFG,
            .Instruction = 0x02,                    // write command
            .InstructionMode = HAL_OSPI_INSTRUCTION_4_LINES,
            .Address = 0,                           // dont care
            .AddressSize = HAL_OSPI_ADDRESS_24_BITS,
            .AddressMode = HAL_OSPI_ADDRESS_4_LINES,
            .AlternateBytesMode = HAL_OSPI_ALTERNATE_BYTES_NONE,
            .DummyCycles = 0,
            .DataMode = HAL_OSPI_DATA_4_LINES,
            .NbData = 0,                        // don't care / TBD?
        };

        // Config for write
        rv = HAL_OSPI_Command(&qh, &cmd, HAL_MAX_DELAY);
        if(rv != HAL_OK) goto fail;

        // .. for read
        OSPI_RegularCmdTypeDef cmd2 = {
            .OperationType = HAL_OSPI_OPTYPE_READ_CFG,
            .Instruction = 0xeb,                    // fast read quad command
            .InstructionMode = HAL_OSPI_INSTRUCTION_4_LINES,
            .Address = 0,                           // dont care
            .AddressSize = HAL_OSPI_ADDRESS_24_BITS,
            .AddressMode = HAL_OSPI_ADDRESS_4_LINES,
            .AlternateBytesMode = HAL_OSPI_ALTERNATE_BYTES_NONE,
            .DummyCycles = 6,
            .DataMode = HAL_OSPI_DATA_4_LINES,
            .NbData = 0,                        // don't care / TBD?
        };

        // Config for read
        rv = HAL_OSPI_Command(&qh, &cmd2, HAL_MAX_DELAY);
        if(rv != HAL_OK) goto fail;
    }

    // config for memmap
    {   OSPI_MemoryMappedTypeDef mmap = {
           // Need this so that CS lines returns to inactive sometimes.
          .TimeOutActivation = HAL_OSPI_TIMEOUT_COUNTER_ENABLE,
          .TimeOutPeriod = 16,          // no idea, max value 0xffff
        };

        rv = HAL_OSPI_MemoryMapped(&qh, &mmap);
        if(rv != HAL_OK) goto fail;
    }

#ifdef INCL_SELFTEST
    psram_memtest(1);
    psram_memtest(0);
#else
    // Only a quick operational check only here. Non-destructive.
    {   __IO uint32_t    *ptr = (uint32_t *)(PSRAM_BASE+PSRAM_SIZE-4);
        uint32_t    tmp;

        tmp = *ptr;
        *ptr = 0x55aa1234;
        if(*ptr != 0x55aa1234) goto fail;
        *ptr = tmp;
    }
#endif

    return;

fail:
    puts("PSRAM fail");

    oled_setup();
    oled_show(screen_fatal);

    LOCKUP_FOREVER();
}

// psram_wipe()
//
    void
psram_wipe(void)
{
    if(OCTOSPI1->CR == 0) return;       // PSRAM not enabled (yet?)

    // Fast! But real; maybe 150ms
    //puts2("PSRAM Wipe: ");
    memset4((uint32_t *)PSRAM_BASE, rng_sample(), PSRAM_SIZE);
    //puts("done");
}

// recover_from_psram()
//
// Try to recover from interrupt PSRAM-based firmware upgrade.
//
    bool
psram_recover_firmware(void)
{
    volatile recovery_header_t   *h = RECHDR_POS;

    // Check header is valid.
    if(    (h->magic1 != RECHDR_MAGIC1)
        || (h->magic2 != RECHDR_MAGIC2)
        || ((uint32_t)h->start < PSRAM_BASE) 
        || ((uint32_t)h->start >= PSRAM_BASE+(PSRAM_SIZE/2)) 
        || (h->size > FW_MAX_LENGTH_MK4) 
        || (h->size < FW_MIN_LENGTH)
    ) {
        puts("PSR: nada");
        return false;
    }

    // Re-verify bytes and factory signature; will catch any bitrot in our 
    // PSRAM copy of firmware
    uint8_t     world_check[32];
    bool ok = verify_firmware_in_ram(h->start, h->size, world_check);

    if(!ok) {
        puts("PSR: !check");
        return false;
    }

    // Check we have the **right** firmware, based on the world check sum
    // but don't set the light at this point.
    // - this includes check over bootrom (ourselves)
    if(!verify_world_checksum(world_check)) {
        puts("PSR: version");
        return false;
    }

    // Re-do the upgrade.
    psram_do_upgrade(h->start, h->size);

    // done
    NVIC_SystemReset();

    // not-reached
    return true;
}

// psram_do_upgrade()
//
// Copy from PSRAM to real flash, at final executable location.
// Takes just 15 seconds!
//
// NOTE: Incoming start address is typically not aligned.
//
    void
psram_do_upgrade(const uint8_t *start, uint32_t size)
{
    ASSERT(size >= FW_MIN_LENGTH);

    // In case of reset/crash, we can recover, so save
    // what we need for that -- yes, we will re-verify signatures
    volatile recovery_header_t   *h = RECHDR_POS;
    h->start = start;
    h->size = size;
    h->magic1 = RECHDR_MAGIC1;
    h->magic2 = RECHDR_MAGIC2;

    flash_setup0();
    flash_unlock();

    int rv;

    // one uint64_t at a time = 8 bytes
    uint64_t tmp;
    for(uint32_t pos=0; pos < size; pos += 8) {
        uint32_t dest = FIRMWARE_START+pos;

        if(dest % (4*FLASH_ERASE_SIZE) == 0) {
            // show some progress
            oled_show_progress(screen_upgrading, pos*100/size);
        }

        if(dest % FLASH_ERASE_SIZE == 0) {
            // page erase as we go
            rv = flash_page_erase(dest);
#if 0
            if(rv) {
                puts2("erase rv=");
                puthex2(rv);
                putchar('\n');
            }
#endif
            ASSERT(rv == 0);
        }

        memcpy(&tmp, start+pos, 8);
        rv = flash_burn(dest, tmp);
#if 0
        if(rv) {
            puts2("burn rv=");
            puthex2(rv);
            puts2(" addr=");
            puthex8(dest);
            putchar('\n');
        }
#endif
        ASSERT(rv == 0);
    }

    flash_lock();
}


#ifdef INCL_SELFTEST
// psram_memtest()
//
    static void
psram_memtest(bool simple)
{
    uint8_t         *base = (uint8_t *)PSRAM_BASE;
    const uint8_t   *end = (uint8_t *)(PSRAM_BASE+PSRAM_SIZE);
    const int sz = 32;

    uint8_t pattern[32];
    if(simple) {
        //rng_buffer(pattern, sz);
        for(int i=0; i<sz; i++) {
            pattern[i] = i;
        }
    }

    puts2("memtest: fill .. ");
    for(uint8_t *ptr = base; ptr < end-sz; ptr += sz) {
        if(!simple) {
            sha256_single((uint8_t *)&ptr, 4, pattern);
        }
        memcpy(ptr, pattern, sz);
    }

    puts2("check .. ");
    for(uint8_t *ptr = base; ptr < end-sz; ptr += sz) {
        if(!simple) {
            sha256_single((uint8_t *)&ptr, 4, pattern);
        }
        if(memcmp(pattern, ptr, sz) != 0) {
            puts2("FAIL @ ");
            puthex8((uint32_t)ptr);
            putchar('\n');

            hex_dump(ptr, sz);
            puts("should be:");
            hex_dump(pattern, sz);

            BREAKPOINT;
        }
    }

    puts("PASS");
}
#endif

// EOF

