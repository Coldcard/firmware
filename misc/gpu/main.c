#include "main.h"

int main(void)
{

    // from https://github.com/STMicroelectronics/STM32CubeC0/blob/main/Projects/STM32C0316-DK/Examples_LL/GPIO/GPIO_InfiniteLedToggling_Init/Src/main.c
    /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
    LL_APB2_GRP1_EnableClock(LL_APB2_GRP1_PERIPH_SYSCFG);
    LL_APB1_GRP1_EnableClock(LL_APB1_GRP1_PERIPH_PWR);

    SystemCoreClockUpdate();


    while(1) ;

    return 0;
}

void exit(int unused)
{
    while(1) ;
}
