/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * Setup and read from the SD Card. Used in recovery mode only.
 *
 */
#include "oled.h"
#include "clocks.h"
#include "sigheader.h"
#include "assets/screens.h"
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

// sdcard_setup()
//
    void
sdcard_setup(void)
{
    // pinout setup

    __HAL_RCC_SDMMC1_CLK_ENABLE();

    // Configure pins: Port C: C8-C13, PD2=CMD
    // - C7 (light), and C13 (detect) setup in gpio_setup
    {   GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_8 | GPIO_PIN_9 | GPIO_PIN_10 | GPIO_PIN_11 | GPIO_PIN_12,
            .Mode = GPIO_MODE_AF_PP,            // not sure
            .Pull = GPIO_PULLUP,
            .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
            .Alternate = GPIO_AF12_SDMMC1,
        };
        HAL_GPIO_Init(GPIOC, &setup);
    }

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

    sdcard_probe();
}

    bool
sdcard_probe(void)
{
    memset(&hsd, 0, sizeof(SD_HandleTypeDef));

    puts2("SDCard: ");

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

    // configure the SD bus width for 4-bit wide operation
    rv = HAL_SD_ConfigWideBusOperation(&hsd, SDMMC_BUS_WIDE_4B);
    if(rv != HAL_OK) {
        puts("wide");
        return false;
    }


    uint8_t     blk[512];
    rv = HAL_SD_ReadBlocks(&hsd, blk, 0, 1, 60000);
    if(rv != HAL_OK) {
        puts("read fail");
        return false;
    }

    puts("ok");
    hex_dump(blk, 512);

    return true;
}

// sdcard_is_inserted()
//
    bool
sdcard_is_inserted(void)
{
    return !!HAL_GPIO_ReadPin(GPIOC, GPIO_PIN_13); 
}

// EOF

