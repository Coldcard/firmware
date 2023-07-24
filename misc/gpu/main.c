/*
 * (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include "main.h"
#include "lcd.h"

// gpio_setup()
//
    void 
gpio_setup(void)
{
    LL_GPIO_InitTypeDef init = {0};

    // see external/stm32c0xx_hal_driver/Inc/stm32c0xx_ll_gpio.h
    LL_IOP_GRP1_EnableClock(LL_IOP_GRP1_PERIPH_GPIOA);

    //LL_GPIO_SetOutputPin(GPIOA, LL_GPIO_PIN_3);

    // setup input pins
    // - make SPI stuff input at this point as well.
    init.Pin = INPUT_PINS | SPI_PINS;
    init.Mode = LL_GPIO_MODE_INPUT;
    init.Speed = LL_GPIO_SPEED_FREQ_HIGH;
    init.Pull = LL_GPIO_PULL_NO;

    LL_GPIO_Init(GPIOA, &init);

    // setup shared open-drain pins
    init.Pin = OUTPUT_OD_PINS;
    init.Mode = LL_GPIO_MODE_OUTPUT;
    init.OutputType = LL_GPIO_OUTPUT_OPENDRAIN;
    init.Speed = LL_GPIO_SPEED_FREQ_HIGH;
    init.Pull = LL_GPIO_PULL_NO;

    LL_GPIO_Init(GPIOA, &init);
}

// mainloop()
//
    void __attribute__((noreturn))
mainloop(void)
{
    // TODO: add naked attr and debug why that kills the code

    // from https://github.com/STMicroelectronics/STM32CubeC0/blob/main/Projects/
    //                STM32C0316-DK/Examples_LL/GPIO/GPIO_InfiniteLedToggling_Init/Src/main.c

    // Reset & enable of all peripherals we are using.
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_SYSCFG | LL_APB2_GRP1_PERIPH_SPI1);
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_PWR | LL_APB1_GRP1_PERIPH_I2C1);

    // Setup clocks
    SystemCoreClockUpdate();

    gpio_setup();
    lcd_setup();

    while(1) {
        if(!LL_GPIO_IsInputPinSet(GPIOA, PIN_G_CTRL)) {
            lcd_test();
            break;
        }
    }

    while(1) ;

    //return 0;
}

/*
void __attribute__((noreturn)) exit(int unused)
{
    while(1) ;
}
*/