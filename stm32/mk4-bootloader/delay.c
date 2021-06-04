/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * delay.c -- Software delay loops (we have no interrupts)
 *
 */
#include "basics.h"
#include "delay.h"
#include "stm32l4xx_hal.h"

// delay_ms()
//
    void
delay_ms(int ms)
{
    // Clear the COUNTFLAG and reset value to zero
    SysTick->VAL = 0;
    //SysTick->CTRL;  

    // Wait for ticks to happen
    while(ms > 0) {
        if(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) {
            ms--;
        }
    }
}

// HAL_Delay()
//
// Replace HAL version which needs interrupts
//
    void
HAL_Delay(uint32_t Delay)
{
    delay_ms(Delay);
}

// EOF
