/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * gpio.c -- setup and control GPIO pins (and one button)
 *
 */
#include "basics.h"
#include "gpio.h"
#include "stm32l4xx_hal.h"

// PA0 - onewire bus for 608a
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
    // - oled_setup() uses pins on PA4 thru PA8

    // enable clock to GPIO's ... we will be using them all at some point
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_GPIOD_CLK_ENABLE();
    __HAL_RCC_GPIOE_CLK_ENABLE();

    {   // Onewire bus pins used for ATECC608 comms
        GPIO_InitTypeDef setup = {
            .Pin = ONEWIRE_PIN,
            .Mode = GPIO_MODE_AF_OD,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_MEDIUM,
            .Alternate = GPIO_AF8_UART4,
        };
        HAL_GPIO_Init(ONEWIRE_PORT, &setup);
    }

    // Bugfix: re-init of console port pins seems to wreck
    // the mpy uart code, so avoid after first time.
    if(USART1->BRR == 0) {
        // debug console: USART1 = PA9=Tx & PA10=Rx
        GPIO_InitTypeDef setup = {
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
    // USB active LED: PC6
    {   GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_7 | GPIO_PIN_6,
            .Mode = GPIO_MODE_OUTPUT_PP,
            .Pull = GPIO_NOPULL,
            .Speed = GPIO_SPEED_FREQ_LOW,
        };
        HAL_GPIO_Init(GPIOC, &setup);

        HAL_GPIO_WritePin(GPIOC, GPIO_PIN_7|GPIO_PIN_6, 0);    // turn LEDs off
    }

    // SD card detect switch: PC13
    {   GPIO_InitTypeDef setup = {
            .Pin = GPIO_PIN_13,
            .Mode = GPIO_MODE_INPUT,
            .Pull = GPIO_PULLUP,
            .Speed = GPIO_SPEED_FREQ_LOW,
        };
        HAL_GPIO_Init(GPIOC, &setup);
    }


#if 0
    // TEST CODE -- keep
    // enable MCO=PA8 for clock watching. Conflicts w/ OLED normal use.
    GPIO_InitTypeDef mco_setup = {
        .Pin = GPIO_PIN_8,
        .Mode = GPIO_MODE_AF_PP,
        .Pull = GPIO_NOPULL,
        .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
        .Alternate = GPIO_AF0_MCO,
    };
    HAL_GPIO_Init(GPIOA, &mco_setup);

    // select a signal to view here.
    // RCC_MCO1SOURCE_SYSCLK => 120Mhz (correct)
    // RCC_MCO1SOURCE_PLLCLK  (PLL R output) => (same os SYSCLK)
    // RCC_MCO1SOURCE_HSI48  => 48Mhz
    // RCC_MCO1SOURCE_HSE => 8Mhz (correct)
    __HAL_RCC_MCO1_CONFIG(RCC_MCO1SOURCE_SYSCLK, RCC_MCODIV_1);
#endif

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
