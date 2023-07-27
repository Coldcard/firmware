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

    // Setup input pins -- which is all!
    // - make SPI stuff input at this point as well.
    init.Pin = INPUT_PINS | SPI_PINS | SPI_CTRL_PINS;
    init.Mode = LL_GPIO_MODE_INPUT;
    init.Speed = LL_GPIO_SPEED_FREQ_HIGH;
    init.Pull = LL_GPIO_PULL_NO;

    LL_GPIO_Init(GPIOA, &init);

#if 0
    // setup shared open-drain pins
    init.Pin = OUTPUT_OD_PINS;
    init.Mode = LL_GPIO_MODE_OUTPUT;
    init.OutputType = LL_GPIO_OUTPUT_OPENDRAIN;
    init.Speed = LL_GPIO_SPEED_FREQ_HIGH;
    init.Pull = LL_GPIO_PULL_NO;

    LL_GPIO_Init(GPIOA, &init);
#endif
}

// i2c_setup()
//
    void
i2c_setup(void)
{
    // useful <https://github.com/STMicroelectronics/STM32CubeG0/blob/ae31d181b3244190d7d5bc0d91e66a82ce4270ce/Projects/NUCLEO-G031K8/Examples_LL/I2C/I2C_TwoBoards_MasterRx_SlaveTx_IT_Init/Src/main.c#L205>

    LL_RCC_SetI2CClockSource(LL_RCC_I2C1_CLKSOURCE_PCLK1);
    LL_IOP_GRP1_EnableClock(LL_IOP_GRP1_PERIPH_GPIOB);
    //LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_I2C1);

    {
        // setup pins PB6/7
        LL_GPIO_InitTypeDef init = {0};

        init.Pin = I2C_PINS;
        init.Mode = LL_GPIO_MODE_ALTERNATE;
        init.Speed = LL_GPIO_SPEED_FREQ_LOW;
        init.OutputType = LL_GPIO_OUTPUT_OPENDRAIN;
        init.Pull = LL_GPIO_PULL_NO;
        init.Alternate = LL_GPIO_AF_6;

        LL_GPIO_Init(GPIOB, &init);
    }

    {
        LL_I2C_InitTypeDef  init = {0};

        init.PeripheralMode = LL_I2C_MODE_I2C;

        // from MXCube w/ FastMode @ 12Mhz main micro
        init.Timing = 0x00100413;

        init.AnalogFilter = LL_I2C_ANALOGFILTER_ENABLE;
        init.DigitalFilter = 0x0;           // disabled
        init.OwnAddress1 = 0x65;
        init.TypeAcknowledge = LL_I2C_ACK;
        init.OwnAddrSize = LL_I2C_OWNADDRESS1_7BIT;

        LL_I2C_Init(I2C1, &init);

        LL_I2C_EnableAutoEndMode(I2C1);
        LL_I2C_SetOwnAddress2(I2C1, 0, LL_I2C_OWNADDRESS2_NOMASK);
        LL_I2C_DisableOwnAddress2(I2C1);
        LL_I2C_DisableGeneralCall(I2C1);
        LL_I2C_EnableClockStretching(I2C1);
    }
}

// i2c_poll()
//
    void
i2c_poll(void)
{
    // do we have work from I2C port?
    
}

// clock_setup()
//
    void
clock_setup(void)
{
    // HSI configuration and activation
    LL_RCC_HSI_Enable();
    while(LL_RCC_HSI_IsReady() != 1) 
        ;

    LL_RCC_HSI_SetCalibTrimming(64);
    LL_RCC_SetHSIDiv(LL_RCC_HSI_DIV_4);
    LL_RCC_SetAHBPrescaler(LL_RCC_HCLK_DIV_1);

    // Sysclk activation on the HSI
    LL_RCC_SetSysClkSource(LL_RCC_SYS_CLKSOURCE_HSI);
    while(LL_RCC_GetSysClkSource() != LL_RCC_SYS_CLKSOURCE_STATUS_HSI) 
        ;

    // Set APB1 prescaler
    LL_RCC_SetAPB1Prescaler(LL_RCC_APB1_DIV_1);
    LL_Init1msTick(12000000);

    // Update CMSIS variable (which can be updated also through SystemCoreClockUpdate function)
    LL_SetSystemCoreClock(12000000);
}

// mainloop()
//
    void __attribute__((noreturn))
mainloop(void)
{
    // TODO: add naked attr and debug why that kills the code, or waste stack space forever
    SCB->VTOR = FLASH_BASE;         // Vector Table Relocation in Internal FLASH

    // Setup clocks
    clock_setup();

    // Reset & enable of all peripherals we are using.
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_SYSCFG | LL_APB2_GRP1_PERIPH_SPI1);
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_PWR | LL_APB1_GRP1_PERIPH_I2C1);


    // Our setup code.
    gpio_setup();
    lcd_setup();
    i2c_setup();

    while(1) {
        i2c_poll();

        // G_CTRL must be low, and TEAR high, and if so we do progress bar
        if(!LL_GPIO_IsInputPinSet(GPIOA, PIN_G_CTRL)
                 && LL_GPIO_IsInputPinSet(GPIOA, PIN_TEAR)
        ) {
            lcd_animate();

            // wait until start of next frame before looking again
            while(LL_GPIO_IsInputPinSet(GPIOA, PIN_TEAR)) {
                i2c_poll();
            }
        } 
    }

    //return 0;
}

// EOF
