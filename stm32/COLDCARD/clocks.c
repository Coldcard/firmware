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

void __fatal_error(const char *msg);

void SystemClock_Config(void)
{
    RCC_ClkInitTypeDef RCC_ClkInitStruct;
    RCC_OscInitTypeDef RCC_OscInitStruct;

    // Configure LSE Drive Capability
    __HAL_RCC_LSEDRIVE_CONFIG(RCC_LSEDRIVE_LOW);

    // Enable HSE Oscillator and activate PLL with HSE as source
    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;

    RCC_OscInitStruct.HSEState = RCC_HSE_ON;
    RCC_OscInitStruct.LSEState = RCC_LSE_OFF;
    RCC_OscInitStruct.MSIState = RCC_MSI_OFF;

    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;

    // Select PLL as system clock source and configure
    // the HCLK, PCLK1 and PCLK2 clocks dividers
    RCC_ClkInitStruct.ClockType = (RCC_CLOCKTYPE_SYSCLK | RCC_CLOCKTYPE_HCLK 
                                        | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2);
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;

    RCC_OscInitStruct.PLL.PLLM = MICROPY_HW_CLK_PLLM;
    RCC_OscInitStruct.PLL.PLLN = MICROPY_HW_CLK_PLLN;
    RCC_OscInitStruct.PLL.PLLP = MICROPY_HW_CLK_PLLP;
    RCC_OscInitStruct.PLL.PLLQ = MICROPY_HW_CLK_PLLQ;
    RCC_OscInitStruct.PLL.PLLR = MICROPY_HW_CLK_PLLR;

    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

    if(HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK) {
        __fatal_error("HAL_RCC_OscConfig");
    }

    if(HAL_RCC_ClockConfig(&RCC_ClkInitStruct, MICROPY_HW_FLASH_LATENCY) != HAL_OK) {
        __fatal_error("HAL_RCC_ClockConfig");
    }

    // DIS-able MSI-Hardware auto calibration mode with LSE
    HAL_RCCEx_DisableMSIPLLMode();

    RCC_PeriphCLKInitTypeDef PeriphClkInitStruct;
    PeriphClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_SAI1|RCC_PERIPHCLK_I2C1
                                              |RCC_PERIPHCLK_USB |RCC_PERIPHCLK_ADC
                                              |RCC_PERIPHCLK_SDMMC1
                                              |RCC_PERIPHCLK_RNG |RCC_PERIPHCLK_RTC;

    PeriphClkInitStruct.I2c1ClockSelection = RCC_I2C1CLKSOURCE_PCLK1;

    // PLLSAI is used to clock USB, ADC, I2C1, SDMMC1 and RNG. The frequency is
    // HSE(8MHz)/PLLM(2)*PLLSAI1N(24)/PLLSAIQ(2) = 48MHz.
    // 
    PeriphClkInitStruct.Sai1ClockSelection = RCC_SAI1CLKSOURCE_PLLSAI1;
    PeriphClkInitStruct.AdcClockSelection = RCC_ADCCLKSOURCE_PLLSAI1;
    PeriphClkInitStruct.UsbClockSelection = RCC_USBCLKSOURCE_PLLSAI1;
    PeriphClkInitStruct.RngClockSelection = RCC_RNGCLKSOURCE_PLLSAI1;
    PeriphClkInitStruct.Sdmmc1ClockSelection = RCC_SDMMC1CLKSOURCE_PLLSAI1;

    PeriphClkInitStruct.RTCClockSelection = RCC_RTCCLKSOURCE_LSE;

    PeriphClkInitStruct.PLLSAI1.PLLSAI1Source = RCC_PLLSOURCE_HSE;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1M = 2;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1N = 24;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1P = RCC_PLLP_DIV7;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1Q = RCC_PLLQ_DIV2;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1R = RCC_PLLR_DIV2;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1ClockOut = RCC_PLLSAI1_SAI1CLK
                                                 |RCC_PLLSAI1_48M2CLK
                                                 |RCC_PLLSAI1_ADC1CLK;

    // doesn't seem to matter
    //PeriphClkInitStruct.Uart4ClockSelection = RCC_UART4CLKSOURCE_SYSCLK;

    if (HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct) != HAL_OK)
    {
        __fatal_error("HAL_RCCEx_PeriphCLKConfig");
    }

    __PWR_CLK_ENABLE();

    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1);

    HAL_SYSTICK_Config(HAL_RCC_GetHCLKFreq()/1000);

    HAL_SYSTICK_CLKSourceConfig(SYSTICK_CLKSOURCE_HCLK);

    HAL_NVIC_SetPriority(SysTick_IRQn, TICK_INT_PRIORITY, 0);
}
