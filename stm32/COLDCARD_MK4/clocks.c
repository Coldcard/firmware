/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, 2014 Damien P. George
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include "py/mphal.h"
#include "irq.h"

void __fatal_error(const char *msg);

void SystemInit(void)
{
    // replace code from
    // l-mpy/lib/stm32lib/CMSIS/STM32L4xx/Source/Templates/system_stm32l4xx.c

    // FPU settings 
#if (__FPU_PRESENT == 1) && (__FPU_USED == 1)
    SCB->CPACR |= ((3UL << 10*2)|(3UL << 11*2));  /* set CP10 and CP11 Full Access */
#endif

    // Leave clock details unchanged! Do not reset RCC.

    // Disable all interrupts
    RCC->CIER = 0x00000000;

    // Configure the Vector Table location add offset address
#ifdef VECT_TAB_SRAM
    SCB->VTOR = SRAM_BASE | VECT_TAB_OFFSET; /* Vector Table Relocation in Internal SRAM */
#else
    SCB->VTOR = FLASH_BASE | VECT_TAB_OFFSET; /* Vector Table Relocation in Internal FLASH */
#endif

    // This global controls the return value of HAL_RCC_GetHCLKFreq()
    // see clocks.h of bootrom ... SYSCLK in Hz = 120Mhz
    SystemCoreClock = 120000000;
}

void SystemClock_Config(void)
{
    // See code in clocks.c of bootloader for actual clock setup.

#if 0
    __PWR_CLK_ENABLE();
    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);
#endif

    // redundant/override HAL_InitTick called from stm32_main just before this
    HAL_SYSTICK_Config(HAL_RCC_GetHCLKFreq()/(1000*8));
    HAL_SYSTICK_CLKSourceConfig(SYSTICK_CLKSOURCE_HCLK_DIV8);

    NVIC_SetPriority(SysTick_IRQn, NVIC_EncodePriority(NVIC_PRIORITYGROUP_4, TICK_INT_PRIORITY, 0));

    // bugfix? why is this needed?
    enable_irq(IRQ_STATE_ENABLED);
}

// EOF
