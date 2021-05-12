#include "stm32l4xx_hal.h"

// HAL support garbage
const uint8_t  AHBPrescTable[16] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 6, 7, 8, 9};
const uint8_t  APBPrescTable[8] =  {0, 0, 0, 0, 1, 2, 3, 4};
const uint32_t MSIRangeTable[12] = {100000, 200000, 400000, 800000, 1000000, 2000000, \
                                  4000000, 8000000, 16000000, 24000000, 32000000, 48000000};
uint32_t SystemCoreClock;

// TODO: cleanup HAL stuff to not use this
uint32_t HAL_GetTick(void) { return 53; }
uint32_t uwTickPrio = 0;            /* (1UL << __NVIC_PRIO_BITS); * Invalid priority */

// unwanted junk from stm32l4xx_hal_rcc.c
HAL_StatusTypeDef HAL_InitTick (uint32_t TickPriority) { return 0; }


/**
  * @brief Return Voltage Scaling Range.
  * @retval VOS bit field (PWR_REGULATOR_VOLTAGE_SCALE1 or PWR_REGULATOR_VOLTAGE_SCALE2
  *         or PWR_REGULATOR_VOLTAGE_SCALE1_BOOST when applicable)
  */
uint32_t HAL_PWREx_GetVoltageRange(void)
{
#if defined(PWR_CR5_R1MODE)
    if (READ_BIT(PWR->CR1, PWR_CR1_VOS) == PWR_REGULATOR_VOLTAGE_SCALE2)
    {
      return PWR_REGULATOR_VOLTAGE_SCALE2;
    }
    else if (READ_BIT(PWR->CR5, PWR_CR5_R1MODE) == PWR_CR5_R1MODE)
    {
      /* PWR_CR5_R1MODE bit set means that Range 1 Boost is disabled */
      return PWR_REGULATOR_VOLTAGE_SCALE1;
    }
    else
    {
      return PWR_REGULATOR_VOLTAGE_SCALE1_BOOST;
    }
#else
  return  (PWR->CR1 & PWR_CR1_VOS);
#endif
}



