/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
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
#include "basics.h"
#include "clocks.h"
#include "stm32l4xx_hal.h"

// HSE is used and is 8MHz
// - doing a complete setup here, and not changing in MicroPython anymore
// - this chip is well made and can handle later changes to clocks
// - lots of internal RC osc we can use as well... HSI, MSI and HSI48

#if HCLK_FREQUENCY == 80000000
// To get 80Mhz for SYSCLK...
// 8Mhz (HSE) => /2 (M) *40 (N) /2 (R) => 80Mhz

# define CKCC_CLK_PLLM (2)
# define CKCC_CLK_PLLN (40)
# define CKCC_CLK_PLLR (2)
# define CKCC_CLK_PLLP (7)
# define CKCC_CLK_PLLQ (4)
#endif


#if HCLK_FREQUENCY == 120000000
// For for 120Mhz SYSCLK...
// 8Mhz (HSE) => /2 (M) *60 (N) /2 (R) => 120Mhz
// R output => main sysclk (target 120)
// Q output => should be 48Mhz for RNG and OCTOSPI maybe

# define CKCC_CLK_PLLM (2)
# define CKCC_CLK_PLLN (60)
# define CKCC_CLK_PLLR (2)
# define CKCC_CLK_PLLP (7)
# define CKCC_CLK_PLLQ (5)
#endif

// systick_setup()
//
    void
systick_setup(void)
{
    const uint32_t ticks = HCLK_FREQUENCY/1000;

    SysTick->LOAD = (ticks - 1);
    SysTick->VAL = 0;
    SysTick->CTRL = SYSTICK_CLKSOURCE_HCLK | SysTick_CTRL_ENABLE_Msk;
}


// from HAL/Drivers/CMSIS/Device/ST/STM32L4xx/Source/Templates/system_stm32l4xx.c
//
    void
system_init0(void)
{
#if defined(USER_VECT_TAB_ADDRESS)
  /* Configure the Vector Table location -------------------------------------*/
  SCB->VTOR = VECT_TAB_BASE_ADDRESS | VECT_TAB_OFFSET;
#endif

  /* FPU settings ------------------------------------------------------------*/
#if (__FPU_PRESENT == 1) && (__FPU_USED == 1)
  SCB->CPACR |= ((3UL << 20U)|(3UL << 22U));  /* set CP10 and CP11 Full Access */
#endif

  /* Reset the RCC clock configuration to the default reset state ------------*/
  /* Set MSION bit */
  RCC->CR |= RCC_CR_MSION;

  /* Reset CFGR register */
  RCC->CFGR = 0x00000000U;

  /* Reset HSEON, CSSON , HSION, and PLLON bits */
  RCC->CR &= 0xEAF6FFFFU;

  /* Reset PLLCFGR register */
  RCC->PLLCFGR = 0x00001000U;

  /* Reset HSEBYP bit */
  RCC->CR &= 0xFFFBFFFFU;

  /* Disable all interrupts */
  RCC->CIER = 0x00000000U;
}

// clocks_setup()
//
    void
clocks_setup(void)
{
    RCC_ClkInitTypeDef RCC_ClkInitStruct;
    RCC_OscInitTypeDef RCC_OscInitStruct;

    // setup power supplies
    HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1_BOOST);

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

    RCC_OscInitStruct.PLL.PLLM = CKCC_CLK_PLLM;
    RCC_OscInitStruct.PLL.PLLN = CKCC_CLK_PLLN;
    RCC_OscInitStruct.PLL.PLLP = CKCC_CLK_PLLP;
    RCC_OscInitStruct.PLL.PLLQ = CKCC_CLK_PLLQ;
    RCC_OscInitStruct.PLL.PLLR = CKCC_CLK_PLLR;

    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

    HAL_RCC_OscConfig(&RCC_OscInitStruct);

    HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5);

    // DIS-able MSI-Hardware auto calibration mode with LSE
    CLEAR_BIT(RCC->CR, RCC_CR_MSIPLLEN);

    RCC_PeriphCLKInitTypeDef PeriphClkInitStruct;
    PeriphClkInitStruct.PeriphClockSelection = RCC_PERIPHCLK_SAI1|RCC_PERIPHCLK_I2C2
                                              |RCC_PERIPHCLK_USB |RCC_PERIPHCLK_ADC
                                              |RCC_PERIPHCLK_RNG |RCC_PERIPHCLK_RTC;

    PeriphClkInitStruct.I2c2ClockSelection = RCC_I2C2CLKSOURCE_PCLK1;

    // PLLSAI is used to clock USB, ADC, I2C1 and RNG. The frequency is
    // HSE(8MHz)/PLLM(2)*PLLSAI1N(24)/PLLSAIQ(2) = 48MHz.
    //
    PeriphClkInitStruct.Sai1ClockSelection = RCC_SAI1CLKSOURCE_PLLSAI1;
    PeriphClkInitStruct.AdcClockSelection = RCC_ADCCLKSOURCE_PLLSAI1;
    PeriphClkInitStruct.UsbClockSelection = RCC_USBCLKSOURCE_PLLSAI1;
    PeriphClkInitStruct.RTCClockSelection = RCC_RTCCLKSOURCE_LSE;           // XXX wrong?
    PeriphClkInitStruct.RngClockSelection = RCC_RNGCLKSOURCE_PLLSAI1;

    PeriphClkInitStruct.PLLSAI1.PLLSAI1Source = RCC_PLLSOURCE_HSE;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1M = 2;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1N = 24;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1P = RCC_PLLP_DIV7;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1Q = RCC_PLLQ_DIV2;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1R = RCC_PLLR_DIV2;
    PeriphClkInitStruct.PLLSAI1.PLLSAI1ClockOut = RCC_PLLSAI1_SAI1CLK
                                                 |RCC_PLLSAI1_48M2CLK
                                                 |RCC_PLLSAI1_ADC1CLK;

    HAL_RCCEx_PeriphCLKConfig(&PeriphClkInitStruct);

    __HAL_RCC_RTC_ENABLE();
    __HAL_RCC_HASH_CLK_ENABLE();        // for SHA256
    __HAL_RCC_SPI1_CLK_ENABLE();        // for OLED
    //__HAL_RCC_SPI2_CLK_ENABLE();        // for SPI flash
    __HAL_RCC_DMAMUX1_CLK_ENABLE();     // (need this) because code missing in mpy?

    // for SE2
    __HAL_RCC_I2C2_CLK_ENABLE();
    __HAL_RCC_I2C2_FORCE_RESET();
    __HAL_RCC_I2C2_RELEASE_RESET();

    // setup SYSTICK, but we don't have the irq hooked up and not using HAL
    // but we use it in polling mode for delay_ms()
    systick_setup();

}

// EOF
