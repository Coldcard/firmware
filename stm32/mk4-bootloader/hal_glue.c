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
      // NOTE: this is expected value for this project.
      return PWR_REGULATOR_VOLTAGE_SCALE1_BOOST;
    }
#else
  return  (PWR->CR1 & PWR_CR1_VOS);
#endif
}


/**
  * @brief Configure the main internal regulator output voltage.
  * @param  VoltageScaling specifies the regulator output voltage to achieve
  *         a tradeoff between performance and power consumption.
  *          This parameter can be one of the following values:
  @if STM32L4S9xx
  *            @arg @ref PWR_REGULATOR_VOLTAGE_SCALE1_BOOST when available, Regulator voltage output range 1 boost mode,
  *                                                typical output voltage at 1.2 V,
  *                                                system frequency up to 120 MHz.
  @endif
  *            @arg @ref PWR_REGULATOR_VOLTAGE_SCALE1 Regulator voltage output range 1 mode,
  *                                                typical output voltage at 1.2 V,
  *                                                system frequency up to 80 MHz.
  *            @arg @ref PWR_REGULATOR_VOLTAGE_SCALE2 Regulator voltage output range 2 mode,
  *                                                typical output voltage at 1.0 V,
  *                                                system frequency up to 26 MHz.
  * @note  When moving from Range 1 to Range 2, the system frequency must be decreased to
  *        a value below 26 MHz before calling HAL_PWREx_ControlVoltageScaling() API.
  *        When moving from Range 2 to Range 1, the system frequency can be increased to
  *        a value up to 80 MHz after calling HAL_PWREx_ControlVoltageScaling() API. For
  *        some devices, the system frequency can be increased up to 120 MHz.
  * @note  When moving from Range 2 to Range 1, the API waits for VOSF flag to be
  *        cleared before returning the status. If the flag is not cleared within
  *        50 microseconds, HAL_TIMEOUT status is reported.
  * @retval HAL Status
  */
#define PWR_FLAG_SETTING_DELAY_US                      50UL   /*!< Time out value for REGLPF and VOSF flags setting */
HAL_StatusTypeDef HAL_PWREx_ControlVoltageScaling(uint32_t VoltageScaling)
{
  uint32_t wait_loop_index;

  assert_param(IS_PWR_VOLTAGE_SCALING_RANGE(VoltageScaling));

#if defined(PWR_CR5_R1MODE)
  if (VoltageScaling == PWR_REGULATOR_VOLTAGE_SCALE1_BOOST)
  {
    /* If current range is range 2 */
    if (READ_BIT(PWR->CR1, PWR_CR1_VOS) == PWR_REGULATOR_VOLTAGE_SCALE2)
    {
      /* Make sure Range 1 Boost is enabled */
      CLEAR_BIT(PWR->CR5, PWR_CR5_R1MODE);

      /* Set Range 1 */
      MODIFY_REG(PWR->CR1, PWR_CR1_VOS, PWR_REGULATOR_VOLTAGE_SCALE1);

      /* Wait until VOSF is cleared */
      wait_loop_index = ((PWR_FLAG_SETTING_DELAY_US * SystemCoreClock) / 1000000U) + 1;
      while ((HAL_IS_BIT_SET(PWR->SR2, PWR_SR2_VOSF)) && (wait_loop_index != 0U))
      {
        wait_loop_index--;
      }
      if (HAL_IS_BIT_SET(PWR->SR2, PWR_SR2_VOSF))
      {
        return HAL_TIMEOUT;
      }
    }
    /* If current range is range 1 normal or boost mode */
    else
    {
      /* Enable Range 1 Boost (no issue if bit already reset) */
      CLEAR_BIT(PWR->CR5, PWR_CR5_R1MODE);
    }
  }
  else if (VoltageScaling == PWR_REGULATOR_VOLTAGE_SCALE1)
  {
    /* If current range is range 2 */
    if (READ_BIT(PWR->CR1, PWR_CR1_VOS) == PWR_REGULATOR_VOLTAGE_SCALE2)
    {
      /* Make sure Range 1 Boost is disabled */
      SET_BIT(PWR->CR5, PWR_CR5_R1MODE);

      /* Set Range 1 */
      MODIFY_REG(PWR->CR1, PWR_CR1_VOS, PWR_REGULATOR_VOLTAGE_SCALE1);

      /* Wait until VOSF is cleared */
      wait_loop_index = ((PWR_FLAG_SETTING_DELAY_US * SystemCoreClock) / 1000000U) + 1;
      while ((HAL_IS_BIT_SET(PWR->SR2, PWR_SR2_VOSF)) && (wait_loop_index != 0U))
      {
        wait_loop_index--;
      }
      if (HAL_IS_BIT_SET(PWR->SR2, PWR_SR2_VOSF))
      {
        return HAL_TIMEOUT;
      }
    }
     /* If current range is range 1 normal or boost mode */
    else
    {
      /* Disable Range 1 Boost (no issue if bit already set) */
      SET_BIT(PWR->CR5, PWR_CR5_R1MODE);
    }
  }
  else
  {
    /* Set Range 2 */
    MODIFY_REG(PWR->CR1, PWR_CR1_VOS, PWR_REGULATOR_VOLTAGE_SCALE2);
    /* No need to wait for VOSF to be cleared for this transition */
    /* PWR_CR5_R1MODE bit setting has no effect in Range 2        */
  }

#else

  /* If Set Range 1 */
  if (VoltageScaling == PWR_REGULATOR_VOLTAGE_SCALE1)
  {
    if (READ_BIT(PWR->CR1, PWR_CR1_VOS) != PWR_REGULATOR_VOLTAGE_SCALE1)
    {
      /* Set Range 1 */
      MODIFY_REG(PWR->CR1, PWR_CR1_VOS, PWR_REGULATOR_VOLTAGE_SCALE1);

      /* Wait until VOSF is cleared */
      wait_loop_index = ((PWR_FLAG_SETTING_DELAY_US * SystemCoreClock) / 1000000U) + 1U;
      while ((HAL_IS_BIT_SET(PWR->SR2, PWR_SR2_VOSF)) && (wait_loop_index != 0U))
      {
        wait_loop_index--;
      }
      if (HAL_IS_BIT_SET(PWR->SR2, PWR_SR2_VOSF))
      {
        return HAL_TIMEOUT;
      }
    }
  }
  else
  {
    if (READ_BIT(PWR->CR1, PWR_CR1_VOS) != PWR_REGULATOR_VOLTAGE_SCALE2)
    {
      /* Set Range 2 */
      MODIFY_REG(PWR->CR1, PWR_CR1_VOS, PWR_REGULATOR_VOLTAGE_SCALE2);
      /* No need to wait for VOSF to be cleared for this transition */
    }
  }
#endif

  return HAL_OK;
}

__weak void HAL_SDEx_DriveTransceiver_1_8V_Callback(FlagStatus status)
{
    // unused?
}


