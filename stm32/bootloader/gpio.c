/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * gpio.c -- setup and control GPIO pins (and one button)
 *
 */
#include "basics.h"
#include "gpio.h"
#include "stm32l4xx_hal.h"

// PB8 - connected DFU (boot0) line, so easier to read
#define DFU_BTN_PIN      GPIO_PIN_8
#define DFU_BTN_PORT     GPIOB

// PA0 - onewire bus for 508a
#define ONEWIRE_PIN      GPIO_PIN_0
#define ONEWIRE_PORT     GPIOA

// gpio_setup()
//
// set directions, lock critical ones, etc.
//
    void
gpio_setup(void)
{
    // NOTES:
    // - try not to limit PCB changes for future revs; leave unused unchanged.
    // - oled_setup() uses pins on PA6 thru PA8

    // enable clock to that part of chip
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();

    {   // DFU button
        GPIO_InitTypeDef setup = {
            .Pin = DFU_BTN_PIN,
            .Mode = GPIO_MODE_INPUT,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_LOW,
            .Alternate = 0,
        };

        HAL_GPIO_Init(DFU_BTN_PORT, &setup);
    }

    {   // Onewire bus pin used for ATECC508A comms
        GPIO_InitTypeDef setup = {
            .Pin = ONEWIRE_PIN,
            .Mode = GPIO_MODE_AF_OD,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_MEDIUM,
            .Alternate = GPIO_AF8_UART4,
        };

        HAL_GPIO_Init(ONEWIRE_PORT, &setup);
    }

#if 0
    {   // DEBUG only: Row1 = PB13
        GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_13,
            .Mode = GPIO_MODE_OUTPUT_PP,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_HIGH,
            .Alternate = 0,
        };

        HAL_GPIO_Init(GPIOB, &setup);
    }

    // elsewhere...
    //HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, 1);
    //HAL_GPIO_WritePin(GPIOB, GPIO_PIN_13, 0);
#endif
}

// dfu_button_pressed()
//
// sample the DFU button
//
    bool
dfu_button_pressed(void)
{
    return (HAL_GPIO_ReadPin(DFU_BTN_PORT, DFU_BTN_PIN) == GPIO_PIN_SET);
}

// EOF
