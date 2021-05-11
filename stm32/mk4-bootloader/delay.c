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

// delay_us()
//
    void
delay_us(int us)
{
    if(us > 1000) {
        // big round up
        delay_ms((us + 500) / 1000);

    } else {
        // XXX calibrate this
        for(volatile int i=0; i<(10000*us); i++) {
            __NOP();
        }
    }
}

// EOF
