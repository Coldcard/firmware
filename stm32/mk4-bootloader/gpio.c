/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * gpio.c -- setup and control GPIO pins (and one button)
 *
 */
#include "basics.h"
#include "gpio.h"
#include "stm32l4xx_hal.h"

// PA0 - onewire bus for 508a
// PA2 - onewire bus for 508a - second SE
#define ONEWIRE_PIN      GPIO_PIN_0
#define ONEWIRE2_PIN     GPIO_PIN_2
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
    // - oled_setup() uses pins on PA4 thru PA8

    // enable clock to that part of chip
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();

    {   // Onewire bus pins used for ATECC508A comms
        GPIO_InitTypeDef setup = {
            .Pin = ONEWIRE_PIN,
            .Mode = GPIO_MODE_AF_OD,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_MEDIUM,
            .Alternate = GPIO_AF8_UART4,
        };
        HAL_GPIO_Init(ONEWIRE_PORT, &setup);

        // second SE
        setup.Pin = ONEWIRE2_PIN;
        setup.Alternate = GPIO_AF7_USART2;
        HAL_GPIO_Init(ONEWIRE_PORT, &setup);
    }

    // debug console: USART1 = PA9=Tx & PA10=Rx
    {   GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_9,
            .Mode = GPIO_MODE_AF_PP,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_MEDIUM,
            .Alternate = GPIO_AF7_USART1,
        };
        HAL_GPIO_Init(GPIOA, &setup);

        setup.Pin = GPIO_PIN_10;
        setup.Mode = GPIO_MODE_INPUT;
        setup.Pull = GPIO_PULLUP;
        HAL_GPIO_Init(GPIOA, &setup);
    }

    // SD active LED: PC7
    {   GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_7,
            .Mode = GPIO_MODE_OUTPUT_PP,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_LOW,
        };
        HAL_GPIO_Init(GPIOC, &setup);

        HAL_GPIO_WritePin(GPIOC, GPIO_PIN_7, 1);    // turn on
    }

#if 0
    __HAL_RCC_GPIOB_CLK_ENABLE();

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

// EOF
