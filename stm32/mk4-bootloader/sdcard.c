/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * Setup and read from the SD Card. Used in recovery mode only.
 *
 */
#include "oled.h"
#include "clocks.h"
#include "sigheader.h"
#include "ae.h"
#include "ae_config.h"
#include SCREENS_H
#include <string.h>
#include "delay.h"
#include "rng.h"
#include "storage.h"
#include "sigheader.h"
#include "stm32l4xx_hal.h"
#include "verify.h"
#include "console.h"
#include "misc.h"
#include "sdcard.h"
#include "psram.h"

SD_HandleTypeDef hsd;

// sdcard_light()
//
    void inline
sdcard_light(bool on)
{
    HAL_GPIO_WritePin(GPIOC, GPIO_PIN_7, !!on);    // turn LED off
}

// sdcard_setup()
//
    static void
sdcard_setup(void)
{
    // pinout setup

    __HAL_RCC_SDMMC1_CLK_ENABLE();

    // Configure pins: Port C: C8-C13, PD2=CMD
    // - C7 (light), and C13 (detect) already setup in gpio_setup
    {   GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_11 | GPIO_PIN_12,
            .Mode = GPIO_MODE_AF_PP,            // not sure
            .Pull = GPIO_PULLUP,
            .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
            .Alternate = GPIO_AF12_SDMMC1,
        };
        HAL_GPIO_Init(GPIOC, &setup);
    }

#ifdef FOR_Q1_ONLY
    // Force mux to A slot only (we don't support B here at all)
    { 
        GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_13,
            .Mode = GPIO_MODE_OUTPUT_PP,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_LOW,
        };
        HAL_GPIO_Init(GPIOC, &setup);
        HAL_GPIO_WritePin(GPIOC, GPIO_PIN_13, 0);    // select A
    }

    // PD3 = DETECT1 .. already configed in q1-bootrom/gpio.c
    // Ignore DETECT2, and ACTIVE_LED2 (port D pins) because
    // not using and default state (hiz input) will be fine.
#endif

    // PD2 = CMD
    {   GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_2,
            .Mode = GPIO_MODE_AF_PP,            // not sure
            .Pull = GPIO_PULLUP,
            .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
            .Alternate = GPIO_AF12_SDMMC1,
        };
        HAL_GPIO_Init(GPIOD, &setup);
    }

    // reset module
    __HAL_RCC_SDMMC1_FORCE_RESET();
    __HAL_RCC_SDMMC1_RELEASE_RESET();
}

// sdcard_probe()
//
    static bool
sdcard_probe(uint32_t *num_blocks)
{
    memset(&hsd, 0, sizeof(SD_HandleTypeDef));

    puts2("sdcard_probe: ");

    hsd.Instance = SDMMC1;
    hsd.Init.ClockEdge = SDMMC_CLOCK_EDGE_RISING;
    hsd.Init.ClockPowerSave = SDMMC_CLOCK_POWER_SAVE_ENABLE;
    hsd.Init.BusWide = SDMMC_BUS_WIDE_1B;
    hsd.Init.HardwareFlowControl = SDMMC_HARDWARE_FLOW_CONTROL_DISABLE;
    hsd.Init.ClockDiv = SDMMC_TRANSFER_CLK_DIV;

    int rv = HAL_SD_Init(&hsd);
    if(rv != HAL_OK) {
        puts("init fail");
        return false;
    }

    sdcard_light(true);

    rv = HAL_SD_ConfigSpeedBusOperation(&hsd, SDMMC_SPEED_MODE_AUTO);
    if(rv != HAL_OK) {
        puts("speed");
        return false;
    }

    // configure the SD bus width for 4-bit wide operation
    rv = HAL_SD_ConfigWideBusOperation(&hsd, SDMMC_BUS_WIDE_4B);
    if(rv != HAL_OK) {
        puts("wide");
        return false;
    }

    if(hsd.SdCard.BlockSize != 512) {
        puts("bsize?");
        return false;
    }

    *num_blocks = hsd.SdCard.BlockNbr;

    puts("ok");

    return true;
}

// sdcard_is_inserted()
//
    bool
sdcard_is_inserted(void)
{
#ifdef FOR_Q1_ONLY
    return !HAL_GPIO_ReadPin(GPIOD, GPIO_PIN_3);        // PD3 - inserted when low (Q)
#else
    return !!HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13);      // PC13 - inserted when high (Mk4)
#endif
}

// dfu_hdr_parse()
//
// reimplement shared/files.py:dfu_parse()
//
    static const uint8_t *
dfu_hdr_parse(const uint8_t *ptr, uint32_t *target_size)
{

    typedef struct __PACKED {
        // '<5sBIB', 'signature version size targets'
        char        signature[5];   // == "DfuSe"
        uint8_t     version;
        uint32_t    size;
        uint8_t     targets;
    } DFUFile_t;

    typedef struct __PACKED {
        // '<6sBI255s2I', 'signature altsetting named name size elements'
        char        signature[6];   // == "Target"
        uint8_t     altseting;
        uint32_t    name_len;
        char        name[255];
        uint32_t    size;
        uint32_t    elements;
    } DFUTarget_t;

    typedef struct __PACKED {
        //  '<2I', 'addr size'
        uint32_t    addr;
        uint32_t    size;
    } DFUElement_t;

    const DFUFile_t   *file = (const DFUFile_t *)ptr;
    ptr += sizeof(DFUFile_t);

    for(int idx=0; idx<file->targets; idx++) {
        const DFUTarget_t   *target = (const DFUTarget_t *)ptr;
        ptr += sizeof(DFUTarget_t);

        for(int ei=0; ei<target->elements; ei++) {
            const DFUElement_t   *elem = (const DFUElement_t *)ptr;
            ptr += sizeof(DFUElement_t);

            if(elem->addr == FIRMWARE_START) {
                *target_size = elem->size;
                return ptr;
            }
        }
    }

    // Mk3 and earlier firmwares will fail here because the load address is
    // different from Mk4 images.
    puts("DFU parse fail");

    return NULL;
}

// sdcard_try_file()
//
    void
sdcard_try_file(uint32_t blk_pos)
{
    oled_show(screen_verify);

    // read full possible file into PSRAM, assume continguous, and big enough
    uint8_t *ps = (uint8_t *)PSRAM_BASE;
    //uint8_t buf[512*8];      // half of all our SRAM 0x00002000
    uint8_t buf[512];      // slower, but works.
    
    for(uint32_t off = 0; off < FW_MAX_LENGTH_MK4; off += sizeof(buf)) {
        int rv = HAL_SD_ReadBlocks(&hsd, buf, blk_pos+(off/512), sizeof(buf)/512, 60000);
        if(rv != HAL_OK) {
            puts("long read fail");
            return;
        }
        memcpy(ps + off, buf, sizeof(buf));
    }

    // work in psram now

    // skip DFU header and find length of firmware section
    uint32_t    len = 0;
    const uint8_t *start = dfu_hdr_parse(ps, &len);
    if(!start) return;          // error already shown

    uint8_t world_check[32];
    bool ok = verify_firmware_in_ram(start, len, world_check);

    // msg already printed, if corrupt image
    if(!ok) return;

    // it is a valid, signed image
    puts("good firmware");

    // Check we have the **right** firmware, based on the world check sum
    // but don't set the light at this point.
    // - this includes check over bootrom (ourselves)
    if(!verify_world_checksum(world_check)) {
        puts("wrong world");
        return;
    }

    sdcard_light(false);

    // Do the upgrade, using PSRAM data.
    psram_do_upgrade(start, len);

    // done
    NVIC_SystemReset();
}

// sdcard_search()
//
    void
sdcard_search(void)
{
    oled_show(screen_search);

    if(!sdcard_is_inserted()) return;

    uint32_t num_blocks;

    // open card (power it) and get details, do setup
    puts2("sdcard_search: ");
    sdcard_setup();
    delay_ms(100);
    if(!sdcard_probe(&num_blocks)) return;

    uint8_t     blk[512];
    for(int pos=0; pos<num_blocks; pos += 1) {
        // read a single block
        int rv = HAL_SD_ReadBlocks(&hsd, blk, pos, 1, 60000);
        if(rv != HAL_OK) {
            puts("fail read");

            return;
        }

        if(memcmp(blk, "DfuSe", 5) == 0) {
            // candidate file found
            puts2("found @ ");
            puthex8(pos);
            putchar('\n');

            sdcard_try_file(pos);

            goto redraw;
        }

        if(pos % 128 == 0) {
        redraw:
            oled_show_progress(screen_search, pos*100 / num_blocks);
            sdcard_light(true);
        }
    }

}

// sdcard_recovery()
//
    void
sdcard_recovery(void)
{
    // Use SDCard to recover. Must be precise version they tried to
    // install before, and will be slow AF.

    puts("Recovery mode.");

    while(1) {
        // .. need them to insert a card
        
        sdcard_light(false);
        while(!sdcard_is_inserted()) {
            oled_show(screen_recovery);
            delay_ms(200);
        }
            
        // look for binary, will reset system if successful
        sdcard_light(true);
        sdcard_search();
    }
}

// EOF

