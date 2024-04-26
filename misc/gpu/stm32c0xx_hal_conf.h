
// TBD?

/**
  ******************************************************************************
  * @file    stm32c0116_discovery.h
  * @author  MCD Application Team
  * @brief   This file contains definitions for STM32C0116_DK's LEDs,
  *          push-buttons hardware resources (MB1684).
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2022 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */

/* Define to prevent recursive inclusion -------------------------------------*/
#ifndef STM32C0116_DK_H
#define STM32C0116_DK_H

#ifdef __cplusplus
extern "C" {
#endif

/* Includes ------------------------------------------------------------------*
#include "stm32c0116_discovery_conf.h"
#include "stm32c0116_discovery_errno.h"
*/

#if (USE_BSP_COM_FEATURE > 0)
  #if (USE_COM_LOG > 0)
    #ifndef __GNUC__
      #include "stdio.h"
    #endif
  #endif
#endif
/** @defgroup BSP BSP
  * @{
  */

/** @defgroup STM32C0116_DK STM32C0116 DK
  * @{
  */

/** @defgroup STM32C0116_DK_LOW_LEVEL LOW LEVEL
  * @{
  */

/** @defgroup STM32C0116_DK_LOW_LEVEL_Exported_Types LOW LEVEL Exported Types
  * @{
  */
typedef enum
{
  LED3 = 0U,
  LED_GREEN = LED3,
  LEDn
} Led_TypeDef;

typedef enum
{
  BUTTON_USER = 0U,
  BUTTONn
} Button_TypeDef;

typedef enum
{
  BUTTON_MODE_GPIO = 0U,
  BUTTON_MODE_EXTI = 1U
} ButtonMode_TypeDef;

#if (USE_BSP_JOY_FEATURE > 0)
typedef enum
{
  JOY_MODE_GPIO = 0U,
  JOY_MODE_EXTI = 1U
}JOYMode_TypeDef;

typedef enum
{
  JOY1 = 0U,
  JOYn
}JOY_TypeDef;

typedef enum
{
 JOY_NONE  = 0x00U,
 JOY_SEL   = 0x01U,
 JOY_DOWN  = 0x02U,
 JOY_LEFT  = 0x04U,
 JOY_RIGHT = 0x08U,
 JOY_UP    = 0x10U,
 JOY_ALL   = 0x1FU
}JOYPin_TypeDef;
#endif /* USE_BSP_JOY_FEATURE */

#if (USE_HAL_ADC_REGISTER_CALLBACKS == 1)
typedef struct
{
  void (* pMspInitCb)(ADC_HandleTypeDef *);
  void (* pMspDeInitCb)(ADC_HandleTypeDef *);
}BSP_JOY_Cb_t;
#endif /* (USE_HAL_ADC_REGISTER_CALLBACKS == 1) */

#if (USE_BSP_COM_FEATURE > 0)
typedef enum
{
  COM1 = 0U,
  COMn
} COM_TypeDef;

typedef enum
{
  COM_STOPBITS_1     =   UART_STOPBITS_1,
} COM_StopBitsTypeDef;

typedef enum
{
  COM_PARITY_NONE     =  UART_PARITY_NONE,
  COM_PARITY_EVEN     =  UART_PARITY_EVEN,
  COM_PARITY_ODD      =  UART_PARITY_ODD,
} COM_ParityTypeDef;

typedef enum
{
  COM_HWCONTROL_NONE    =  UART_HWCONTROL_NONE,
  COM_HWCONTROL_RTS     =  UART_HWCONTROL_RTS,
  COM_HWCONTROL_CTS     =  UART_HWCONTROL_CTS,
  COM_HWCONTROL_RTS_CTS =  UART_HWCONTROL_RTS_CTS,
} COM_HwFlowCtlTypeDef;

typedef enum
{
  COM_WORDLENGTH_7B = UART_WORDLENGTH_7B,
  COM_WORDLENGTH_8B = UART_WORDLENGTH_8B,
  COM_WORDLENGTH_9B = UART_WORDLENGTH_9B,
} COM_WordLengthTypeDef;

typedef struct
{
  uint32_t              BaudRate;
  COM_WordLengthTypeDef WordLength;
  COM_StopBitsTypeDef   StopBits;
  COM_ParityTypeDef     Parity;
  COM_HwFlowCtlTypeDef  HwFlowCtl;
} COM_InitTypeDef;

#define MX_UART_InitTypeDef COM_InitTypeDef

#endif /* (USE_BSP_COM_FEATURE > 0) */
#if (USE_HAL_UART_REGISTER_CALLBACKS == 1)
typedef struct
{
  void (* pMspInitCb)(UART_HandleTypeDef *);
  void (* pMspDeInitCb)(UART_HandleTypeDef *);
} BSP_COM_Cb_t;
#endif /* (USE_HAL_UART_REGISTER_CALLBACKS == 1) */

/**
  * @}
  */

/** @defgroup STM32C0116_DK_LOW_LEVEL_Exported_Constants LOW LEVEL Exported Constants
  * @{
  */
/**
  * @brief  Define for STM32C0116_DK board
  */
#if !defined (USE_STM32C0116_DK)
#define USE_STM32C0116_DK
#endif /* USE_STM32C0116_DK */

/**
  * @brief STM32C0116_DK BSP Driver version number V1.0.0
  */
#define STM32C0116_DK_BSP_VERSION_MAIN   (uint32_t)(0x01) /*!< [31:24] main version */
#define STM32C0116_DK_BSP_VERSION_SUB1   (uint32_t)(0x00) /*!< [23:16] sub1 version */
#define STM32C0116_DK_BSP_VERSION_SUB2   (uint32_t)(0x00) /*!< [15:8]  sub2 version */
#define STM32C0116_DK_BSP_VERSION_RC     (uint32_t)(0x00) /*!< [7:0]  release candidate */
#define STM32C0116_DK_BSP_VERSION        ((STM32C0116_DK_BSP_VERSION_MAIN << 24)\
                                           |(STM32C0116_DK_BSP_VERSION_SUB1 << 16)\
                                           |(STM32C0116_DK_BSP_VERSION_SUB2 << 8 )\
                                           |(STM32C0116_DK_BSP_VERSION_RC))

#define STM32C0116_DK_BSP_BOARD_NAME  "STM32C0116-DK";
#define STM32C0116_DK_BSP_BOARD_ID    "MB1684A";

/** @defgroup STM32C0116_DK_LOW_LEVEL_LED LOW LEVEL LED
  * @{
  */
#define LED3_GPIO_PORT                   GPIOB
#define LED3_GPIO_CLK_ENABLE()           __HAL_RCC_GPIOB_CLK_ENABLE()
#define LED3_GPIO_CLK_DISABLE()          __HAL_RCC_GPIOB_CLK_DISABLE()
#define LED3_PIN                         GPIO_PIN_6

/**
  * @}
  */
/** @defgroup STM32C0116_DK_LOW_LEVEL_BUTTON LOW LEVEL BUTTON
  * @{
  */
/* Button state */
#define BUTTON_RELEASED                    0U
#define BUTTON_PRESSED                     1U

/**
  * @brief User push-button
  */
#define BUTTON_USER_PIN                       GPIO_PIN_8
#define BUTTON_USER_GPIO_PORT                 GPIOA
#define BUTTON_USER_GPIO_CLK_ENABLE()         __HAL_RCC_GPIOA_CLK_ENABLE()
#define BUTTON_USER_GPIO_CLK_DISABLE()        __HAL_RCC_GPIOA_CLK_DISABLE()
#define BUTTON_USER_EXTI_IRQn                 EXTI4_15_IRQn
#define BUTTON_USER_EXTI_LINE                 GPIO_PIN_8
/**
  * @}
  */

/** @defgroup STM32C0116_DK_LOW_LEVEL_COM LOW LEVEL COM
  * @{
  */

#if (USE_BSP_COM_FEATURE > 0)
/**
  * @brief Definition for COM port1, connected to USART2
  */
#define COM1_UART                     USART2
#define COM1_CLK_ENABLE()             __HAL_RCC_USART2_CLK_ENABLE()
#define COM1_CLK_DISABLE()            __HAL_RCC_USART2_CLK_DISABLE()

#define COM1_TX_PIN                   GPIO_PIN_2
#define COM1_TX_GPIO_PORT             GPIOA
#define COM1_TX_GPIO_CLK_ENABLE()     __HAL_RCC_GPIOA_CLK_ENABLE()
#define COM1_TX_GPIO_CLK_DISABLE()    __HAL_RCC_GPIOA_CLK_DISABLE()
#define COM1_TX_AF                    GPIO_AF1_USART2

#define COM1_RX_PIN                   GPIO_PIN_3
#define COM1_RX_GPIO_PORT             GPIOA
#define COM1_RX_GPIO_CLK_ENABLE()     __HAL_RCC_GPIOA_CLK_ENABLE()
#define COM1_RX_GPIO_CLK_DISABLE()    __HAL_RCC_GPIOA_CLK_DISABLE()
#define COM1_RX_AF                    GPIO_AF1_USART2

#define COM_POLL_TIMEOUT              1000U
#endif /* (USE_BSP_COM_FEATURE > 0) */
/**
  * @}
  */
/** @defgroup STM32C0116_DK_LOW_LEVEL_JOYSTICK LOW LEVEL JOYSTICK
  * @{
  */
/* Joystick Pins definition */
#define JOY_KEY_NUMBER                     5U

#define JOY1_SEL_PIN                       GPIO_PIN_8
#define JOY1_SEL_GPIO_PORT                 GPIOA
#define JOY1_SEL_GPIO_CLK_ENABLE()         __HAL_RCC_GPIOA_CLK_ENABLE()
#define JOY1_SEL_GPIO_CLK_DISABLE()        __HAL_RCC_GPIOA_CLK_DISABLE()
#define JOY1_SEL_EXTI_IRQn                 EXTI4_15_IRQn
#define JOY1_SEL_EXTI_LINE                 GPIO_PIN_8

#define JOY1_DOWN_PIN                      GPIO_PIN_8
#define JOY1_DOWN_GPIO_PORT                GPIOA
#define JOY1_DOWN_GPIO_CLK_ENABLE()        __HAL_RCC_GPIOA_CLK_ENABLE()
#define JOY1_DOWN_GPIO_CLK_DISABLE()       __HAL_RCC_GPIOA_CLK_DISABLE()
#define JOY1_DOWN_EXTI_IRQn                EXTI4_15_IRQn
#define JOY1_DOWN_EXTI_LINE                GPIO_PIN_8

#define JOY1_LEFT_PIN                      GPIO_PIN_8
#define JOY1_LEFT_GPIO_PORT                GPIOA
#define JOY1_LEFT_GPIO_CLK_ENABLE()        __HAL_RCC_GPIOA_CLK_ENABLE()
#define JOY1_LEFT_GPIO_CLK_DISABLE()       __HAL_RCC_GPIOA_CLK_DISABLE()
#define JOY1_LEFT_EXTI_IRQn                EXTI4_15_IRQn
#define JOY1_LEFT_EXTI_LINE                GPIO_PIN_8

#define JOY1_RIGHT_PIN                     GPIO_PIN_8
#define JOY1_RIGHT_GPIO_PORT               GPIOA
#define JOY1_RIGHT_GPIO_CLK_ENABLE()       __HAL_RCC_GPIOA_CLK_ENABLE()
#define JOY1_RIGHT_GPIO_CLK_DISABLE()      __HAL_RCC_GPIOA_CLK_DISABLE()
#define JOY1_RIGHT_EXTI_IRQn               EXTI4_15_IRQn
#define JOY1_RIGHT_EXTI_LINE               GPIO_PIN_8

#define JOY1_UP_PIN                        GPIO_PIN_8
#define JOY1_UP_GPIO_PORT                  GPIOA
#define JOY1_UP_GPIO_CLK_ENABLE()          __HAL_RCC_GPIOA_CLK_ENABLE()
#define JOY1_UP_GPIO_CLK_DISABLE()         __HAL_RCC_GPIOA_CLK_DISABLE()
#define JOY1_UP_EXTI_IRQn                  EXTI4_15_IRQn
#define JOY1_UP_EXTI_LINE                  GPIO_PIN_8

/**
  * @brief Definition for Joystick, connected to ADC1
  */
#define JOY1_ADC                       ADC1
#define JOY1_CLK_ENABLE()               __HAL_RCC_ADC_CLK_ENABLE()
#define JOY1_CLK_DISABLE()              __HAL_RCC_ADC_CLK_DISABLE()
#define JOY1_CHANNEL_GPIO_CLK_ENABLE()  __HAL_RCC_GPIOA_CLK_ENABLE()
#define JOY1_FORCE_RESET()              __HAL_RCC_ADC_FORCE_RESET()
#define JOY1_RELEASE_RESET()            __HAL_RCC_ADC_RELEASE_RESET()

/* Definition for ADCx Channel Pin */
#define JOY1_CHANNEL_GPIO_PIN           GPIO_PIN_8
#define JOY1_CHANNEL_GPIO_PORT          GPIOA

/* Definition for ADCx's Channel */
#define JOY1_ADC_CHANNEL                ADC_CHANNEL_8
#define JOY1_SAMPLING_TIME              ADC_SAMPLETIME_39CYCLES_5
#define JOY1_PRESCALER                  ADC_CLOCK_SYNC_PCLK_DIV4
#define JOY_ADC_POLL_TIMEOUT            10U

/**
  * @}
  */
  
/**
  * @}
  */

/** @addtogroup STM32C0116_DK_LOW_LEVEL_Exported_Variables
  * @{
  */
extern EXTI_HandleTypeDef hpb_exti[];
#if (USE_BSP_COM_FEATURE > 0)
extern UART_HandleTypeDef hcom_uart[];
extern USART_TypeDef *COM_UART[];
#endif /* USE_BSP_COM_FEATURE */
/**
  * @}
  */

/** @addtogroup STM32C0116_DK_LOW_LEVEL_Exported_Functions
  * @{
  */
int32_t  BSP_GetVersion(void);
const uint8_t *BSP_GetBoardName(void);
const uint8_t *BSP_GetBoardID(void);

int32_t  BSP_LED_Init(Led_TypeDef Led);
int32_t  BSP_LED_DeInit(Led_TypeDef Led);
int32_t  BSP_LED_On(Led_TypeDef Led);
int32_t  BSP_LED_Off(Led_TypeDef Led);
int32_t  BSP_LED_Toggle(Led_TypeDef Led);
int32_t  BSP_LED_GetState(Led_TypeDef Led);

int32_t  BSP_PB_Init(Button_TypeDef Button, ButtonMode_TypeDef ButtonMode);
int32_t  BSP_PB_DeInit(Button_TypeDef Button);
int32_t  BSP_PB_GetState(Button_TypeDef Button);
void     BSP_PB_Callback(Button_TypeDef Button);
void     BSP_PB_IRQHandler(Button_TypeDef Button);

#if (USE_BSP_COM_FEATURE > 0)
int32_t  BSP_COM_Init(COM_TypeDef COM, COM_InitTypeDef *COM_Init);
int32_t  BSP_COM_DeInit(COM_TypeDef COM);
#if (USE_COM_LOG > 0)
int32_t  BSP_COM_SelectLogPort(COM_TypeDef COM);
#endif /* USE_COM_LOG */

#if (USE_HAL_UART_REGISTER_CALLBACKS > 0)
int32_t BSP_COM_RegisterDefaultMspCallbacks(COM_TypeDef COM);
int32_t BSP_COM_RegisterMspCallbacks(COM_TypeDef COM, BSP_COM_Cb_t *Callback);
#endif /* USE_HAL_UART_REGISTER_CALLBACKS */
HAL_StatusTypeDef MX_USART6_Init(UART_HandleTypeDef *huart, MX_UART_InitTypeDef *COM_Init);
#endif /* USE_BSP_COM_FEATURE */

#if (USE_BSP_JOY_FEATURE > 0)
int32_t  BSP_JOY_Init(JOY_TypeDef JOY, JOYMode_TypeDef JoyMode,  JOYPin_TypeDef JoyPins);
int32_t  BSP_JOY_DeInit(JOY_TypeDef JOY,  JOYPin_TypeDef JoyPins);
int32_t  BSP_JOY_GetState(JOY_TypeDef JOY);	
#endif /* USE_BSP_JOY_FEATURE */
/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

/**
  * @}
  */

#ifdef __cplusplus
}
#endif

#endif /* STM32C0116_DK_H */
