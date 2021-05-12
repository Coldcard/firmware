/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * console.c -- simple debug on uart stuff
 *
 */
#include "basics.h"
#include "console.h"
#include "stm32l4xx_hal.h"
#include <string.h>

// mk4 has USART1 on header pins: RGT = Rx Gnd Tx
#define MY_UART        USART1

static const char hexmap[16] = "0123456789abcdef";
static const char *CRLF = "\r\n";

static USART_HandleTypeDef con;

void console_setup(void)
{
    // enable clock to that part of chip
    __HAL_RCC_USART1_CONFIG(RCC_USART1CLKSOURCE_SYSCLK);
    __HAL_RCC_USART1_CLK_ENABLE();

    // TODO: replace shit HAL code w/ barebones we need

    // config for 115200 8N1
    memset(&con, 0, sizeof(con));
    con.Instance = MY_UART;
    con.Init.BaudRate = 115200;
    con.Init.WordLength = USART_WORDLENGTH_8B;
    con.Init.Parity = USART_PARITY_NONE;
    con.Init.StopBits = USART_STOPBITS_1;
    con.Init.Mode = USART_MODE_TX_RX;

    HAL_StatusTypeDef rv = HAL_USART_Init(&con);
    ASSERT(rv == HAL_OK);
}

// puthex2()
//
	void
puthex2(uint8_t b)
{
	putchar(hexmap[(b>>4) & 0xf]);
	putchar(hexmap[(b>>0) & 0xf]);
}

// puthex4()
//
	void
puthex4(uint16_t w)
{
	putchar(hexmap[(w>>12) & 0xf]);
	putchar(hexmap[(w>>8) & 0xf]);
	putchar(hexmap[(w>>4) & 0xf]);
	putchar(hexmap[(w>>0) & 0xf]);
}

// puts2()
//
	void
puts2(const char *msg)
{
	// output string with NO newline.
    HAL_USART_Transmit(&con, (uint8_t *)msg, strlen(msg), HAL_MAX_DELAY);
}


// strcat_hex()
//
	void
strcat_hex(char *msg, const void *d, int len)
{
	char *p = msg+strlen(msg);
	const uint8_t *h = (const uint8_t *)d;

	for(; len; len--, h++) {
		*(p++) = hexmap[(*h>>4) & 0xf];
		*(p++) = hexmap[(*h>>0) & 0xf];
	}

	*(p++) = 0;
}

// putchar()
//
	int
putchar(int c)
{
    uint8_t cb = c;

    if(cb != '\n') {
        HAL_USART_Transmit(&con, &cb, 1, HAL_MAX_DELAY);
    } else {
        HAL_USART_Transmit(&con, (uint8_t *)CRLF, 2, HAL_MAX_DELAY);
    }

    return c;
}

// puts()
//
    int
puts(const char *msg)
{
    int ln = strlen(msg);
    if(ln) HAL_USART_Transmit(&con, (uint8_t *)msg, ln, HAL_MAX_DELAY);
    HAL_USART_Transmit(&con, (uint8_t *)CRLF, 2, HAL_MAX_DELAY);

    return 1;
}

// getchar()
//
    int
getchar(void)
{
    uint8_t rv = 0;

    HAL_USART_Receive(&con, &rv, 1, HAL_MAX_DELAY);

    return rv;
}

// is_print()
//
    static inline bool
is_print(uint8_t c)
{
    return (c >= 0x20) && (c < 128);
}

// hex_dump()
//
    void
hex_dump(const void *d, int len)
{
    int i,j;
	const uint8_t *data = (const uint8_t *)d;

    for(i=0; i<len;) {
		puthex4(i);
		putchar(':');
		putchar(' ');

		if(data == NULL) {
			puts("<NULL>");
			return;
		}
		if(((int32_t)data) == -1) {
			puts("<-1>");
			return;
		}

        // hex part
        for(j=0; j<16 && (i+j)<len; j++) {
			puthex2(data[i+j]);
			putchar(' ');
            if(j==7) {
				puts2("- ");
			}
        }
        // maybe some extra spaces (if (i+16)>len)
        for(; j<16; j++) {
			puts2("   ");
			if(j==7) puts2("  ");
		}

        // text version.
		puts2("  ");
        for(j=0; j<16 && (i+j)<len; j++) {
			uint8_t	c = data[i+j];
			putchar((is_print(c)&&(c<0x80)) ? c : '.');
        }
        putchar('\n');
        i += j;
    }
}

// Copied parts of stm32l4xx_hal_usart.c

#if defined(USART_CR1_FIFOEN)
#define USART_CR1_FIELDS          ((uint32_t)(USART_CR1_M |  USART_CR1_PCE | USART_CR1_PS    | \
                                              USART_CR1_TE | USART_CR1_RE  | USART_CR1_OVER8 | \
                                              USART_CR1_FIFOEN ))                                  /*!< USART CR1 fields of parameters set by USART_SetConfig API */

#define USART_CR2_FIELDS          ((uint32_t)(USART_CR2_CPHA | USART_CR2_CPOL | USART_CR2_CLKEN | \
                                              USART_CR2_LBCL | USART_CR2_STOP | USART_CR2_SLVEN | \
                                              USART_CR2_DIS_NSS))                                  /*!< USART CR2 fields of parameters set by USART_SetConfig API */

#define USART_CR3_FIELDS          ((uint32_t)(USART_CR3_TXFTCFG | USART_CR3_RXFTCFG ))             /*!< USART or USART CR3 fields of parameters set by USART_SetConfig API */
#else
#define USART_CR1_FIELDS          ((uint32_t)(USART_CR1_M | USART_CR1_PCE | USART_CR1_PS | \
                                              USART_CR1_TE | USART_CR1_RE  | USART_CR1_OVER8))    /*!< USART CR1 fields of parameters set by USART_SetConfig API */
#define USART_CR2_FIELDS          ((uint32_t)(USART_CR2_CPHA | USART_CR2_CPOL | \
                                              USART_CR2_CLKEN | USART_CR2_LBCL | USART_CR2_STOP)) /*!< USART CR2 fields of parameters set by USART_SetConfig API */
#endif /* USART_CR1_FIFOEN */

#define USART_BRR_MIN    0x10U        /* USART BRR minimum authorized value */
#define USART_BRR_MAX    0xFFFFU      /* USART BRR maximum authorized value */
#define USART_TEACK_REACK_TIMEOUT             1000U             /*!< USART TX or RX enable acknowledge time-out value */
#define USART_DUMMY_DATA          ((uint16_t) 0xFFFF)           /*!< USART transmitted dummy data                     */

/**
  * @brief  Handle USART Communication Timeout.
  * @param  husart USART handle.
  * @param  Flag Specifies the USART flag to check.
  * @param  Status the Flag status (SET or RESET).
  * @param  Tickstart Tick start value
  * @param  Timeout timeout duration.
  * @retval HAL status
  */
static HAL_StatusTypeDef USART_WaitOnFlagUntilTimeout(USART_HandleTypeDef *husart, uint32_t Flag, FlagStatus Status,
                                                      uint32_t Tickstart, uint32_t Timeout)
{
  /* Wait until flag is set */
  while ((__HAL_USART_GET_FLAG(husart, Flag) ? SET : RESET) == Status)
  {
    /* Check for the Timeout */
    if (Timeout != HAL_MAX_DELAY)
    {
      if (((HAL_GetTick() - Tickstart) > Timeout) || (Timeout == 0U))
      {
        husart->State = HAL_USART_STATE_READY;

        /* Process Unlocked */
        __HAL_UNLOCK(husart);

        return HAL_TIMEOUT;
      }
    }
  }
  return HAL_OK;
}

/**
  * @brief Configure the USART peripheral.
  * @param husart USART handle.
  * @retval HAL status
  */
static HAL_StatusTypeDef USART_SetConfig(USART_HandleTypeDef *husart)
{
  uint32_t tmpreg;
  USART_ClockSourceTypeDef clocksource;
  HAL_StatusTypeDef ret                = HAL_OK;
  uint16_t brrtemp;
  uint32_t usartdiv                    = 0x00000000;
  uint32_t pclk;

  /* Check the parameters */
  assert_param(IS_USART_POLARITY(husart->Init.CLKPolarity));
  assert_param(IS_USART_PHASE(husart->Init.CLKPhase));
  assert_param(IS_USART_LASTBIT(husart->Init.CLKLastBit));
  assert_param(IS_USART_BAUDRATE(husart->Init.BaudRate));
  assert_param(IS_USART_WORD_LENGTH(husart->Init.WordLength));
  assert_param(IS_USART_STOPBITS(husart->Init.StopBits));
  assert_param(IS_USART_PARITY(husart->Init.Parity));
  assert_param(IS_USART_MODE(husart->Init.Mode));
#if defined(USART_PRESC_PRESCALER)
  assert_param(IS_USART_PRESCALER(husart->Init.ClockPrescaler));
#endif /* USART_PRESC_PRESCALER */

  /*-------------------------- USART CR1 Configuration -----------------------*/
  /* Clear M, PCE, PS, TE and RE bits and configure
  *  the USART Word Length, Parity and Mode:
  *  set the M bits according to husart->Init.WordLength value
  *  set PCE and PS bits according to husart->Init.Parity value
  *  set TE and RE bits according to husart->Init.Mode value
  *  force OVER8 to 1 to allow to reach the maximum speed (Fclock/8) */
  tmpreg = (uint32_t)husart->Init.WordLength | husart->Init.Parity | husart->Init.Mode | USART_CR1_OVER8;
  MODIFY_REG(husart->Instance->CR1, USART_CR1_FIELDS, tmpreg);

  /*---------------------------- USART CR2 Configuration ---------------------*/
  /* Clear and configure the USART Clock, CPOL, CPHA, LBCL STOP and SLVEN bits:
   * set CPOL bit according to husart->Init.CLKPolarity value
   * set CPHA bit according to husart->Init.CLKPhase value
   * set LBCL bit according to husart->Init.CLKLastBit value (used in SPI master mode only)
   * set STOP[13:12] bits according to husart->Init.StopBits value */
  tmpreg = (uint32_t)(USART_CLOCK_ENABLE);
  tmpreg |= (uint32_t)husart->Init.CLKLastBit;
  tmpreg |= ((uint32_t)husart->Init.CLKPolarity | (uint32_t)husart->Init.CLKPhase);
  tmpreg |= (uint32_t)husart->Init.StopBits;
  MODIFY_REG(husart->Instance->CR2, USART_CR2_FIELDS, tmpreg);

#if defined(USART_PRESC_PRESCALER)
  /*-------------------------- USART PRESC Configuration -----------------------*/
  /* Configure
   * - USART Clock Prescaler : set PRESCALER according to husart->Init.ClockPrescaler value */
  MODIFY_REG(husart->Instance->PRESC, USART_PRESC_PRESCALER, husart->Init.ClockPrescaler);
#endif /* USART_PRESC_PRESCALER */

  /*-------------------------- USART BRR Configuration -----------------------*/
  /* BRR is filled-up according to OVER8 bit setting which is forced to 1     */
  USART_GETCLOCKSOURCE(husart, clocksource);

  switch (clocksource)
  {
    case USART_CLOCKSOURCE_PCLK1:
      pclk = HAL_RCC_GetPCLK1Freq();
#if defined(USART_PRESC_PRESCALER)
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(pclk, husart->Init.BaudRate, husart->Init.ClockPrescaler));
#else
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(pclk, husart->Init.BaudRate));
#endif /* USART_PRESC_PRESCALER */
      break;
    case USART_CLOCKSOURCE_PCLK2:
      pclk = HAL_RCC_GetPCLK2Freq();
#if defined(USART_PRESC_PRESCALER)
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(pclk, husart->Init.BaudRate, husart->Init.ClockPrescaler));
#else
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(pclk, husart->Init.BaudRate));
#endif /* USART_PRESC_PRESCALER */
      break;
    case USART_CLOCKSOURCE_HSI:
#if defined(USART_PRESC_PRESCALER)
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(HSI_VALUE, husart->Init.BaudRate, husart->Init.ClockPrescaler));
#else
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(HSI_VALUE, husart->Init.BaudRate));
#endif /* USART_PRESC_PRESCALER */
      break;
    case USART_CLOCKSOURCE_SYSCLK:
      pclk = HAL_RCC_GetSysClockFreq();
#if defined(USART_PRESC_PRESCALER)
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(pclk, husart->Init.BaudRate, husart->Init.ClockPrescaler));
#else
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(pclk, husart->Init.BaudRate));
#endif /* USART_PRESC_PRESCALER */
      break;
    case USART_CLOCKSOURCE_LSE:
#if defined(USART_PRESC_PRESCALER)
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(LSE_VALUE, husart->Init.BaudRate, husart->Init.ClockPrescaler));
#else
      usartdiv = (uint32_t)(USART_DIV_SAMPLING8(LSE_VALUE, husart->Init.BaudRate));
#endif /* USART_PRESC_PRESCALER */
      break;
    default:
      ret = HAL_ERROR;
      break;
  }

  /* USARTDIV must be greater than or equal to 0d16 and smaller than or equal to ffff */
  if ((usartdiv >= USART_BRR_MIN) && (usartdiv <= USART_BRR_MAX))
  {
    brrtemp = (uint16_t)(usartdiv & 0xFFF0U);
    brrtemp |= (uint16_t)((usartdiv & (uint16_t)0x000FU) >> 1U);
    husart->Instance->BRR = brrtemp;
  }
  else
  {
    ret = HAL_ERROR;
  }

#if defined(USART_CR1_FIFOEN)
  /* Initialize the number of data to process during RX/TX ISR execution */
  husart->NbTxDataToProcess = 1U;
  husart->NbRxDataToProcess = 1U;
#endif /* USART_CR1_FIFOEN */

  /* Clear ISR function pointers */
  husart->RxISR   = NULL;
  husart->TxISR   = NULL;

  return ret;
}

/**
  * @brief Check the USART Idle State.
  * @param husart USART handle.
  * @retval HAL status
  */
static HAL_StatusTypeDef USART_CheckIdleState(USART_HandleTypeDef *husart)
{
  uint32_t tickstart;

  /* Initialize the USART ErrorCode */
  husart->ErrorCode = HAL_USART_ERROR_NONE;

  /* Init tickstart for timeout management */
  tickstart = HAL_GetTick();

  /* Check if the Transmitter is enabled */
  if ((husart->Instance->CR1 & USART_CR1_TE) == USART_CR1_TE)
  {
    /* Wait until TEACK flag is set */
    if (USART_WaitOnFlagUntilTimeout(husart, USART_ISR_TEACK, RESET, tickstart, USART_TEACK_REACK_TIMEOUT) != HAL_OK)
    {
      /* Timeout occurred */
      return HAL_TIMEOUT;
    }
  }
  /* Check if the Receiver is enabled */
  if ((husart->Instance->CR1 & USART_CR1_RE) == USART_CR1_RE)
  {
    /* Wait until REACK flag is set */
    if (USART_WaitOnFlagUntilTimeout(husart, USART_ISR_REACK, RESET, tickstart, USART_TEACK_REACK_TIMEOUT) != HAL_OK)
    {
      /* Timeout occurred */
      return HAL_TIMEOUT;
    }
  }

  /* Initialize the USART state*/
  husart->State = HAL_USART_STATE_READY;

  /* Process Unlocked */
  __HAL_UNLOCK(husart);

  return HAL_OK;
}



/**
  * @brief  Initialize the USART mode according to the specified
  *         parameters in the USART_InitTypeDef and initialize the associated handle.
  * @param  husart USART handle.
  * @retval HAL status
  */
HAL_StatusTypeDef HAL_USART_Init(USART_HandleTypeDef *husart)
{
  /* Check the USART handle allocation */
  if (husart == NULL)
  {
    return HAL_ERROR;
  }

  /* Check the parameters */
  assert_param(IS_USART_INSTANCE(husart->Instance));

  if (husart->State == HAL_USART_STATE_RESET)
  {
    /* Allocate lock resource and initialize it */
    husart->Lock = HAL_UNLOCKED;
  }

  husart->State = HAL_USART_STATE_BUSY;

  /* Disable the Peripheral */
  __HAL_USART_DISABLE(husart);

  /* Set the Usart Communication parameters */
  if (USART_SetConfig(husart) == HAL_ERROR)
  {
    return HAL_ERROR;
  }

  /* In Synchronous mode, the following bits must be kept cleared:
  - LINEN bit in the USART_CR2 register
  - HDSEL, SCEN and IREN bits in the USART_CR3 register.*/
  husart->Instance->CR2 &= ~USART_CR2_LINEN;
  husart->Instance->CR3 &= ~(USART_CR3_SCEN | USART_CR3_HDSEL | USART_CR3_IREN);

  /* Enable the Peripheral */
  __HAL_USART_ENABLE(husart);

  /* TEACK and/or REACK to check before moving husart->State to Ready */
  return (USART_CheckIdleState(husart));
}

/**
  * @brief  Simplex send an amount of data in blocking mode.
  * @note   When USART parity is not enabled (PCE = 0), and Word Length is configured to 9 bits (M1-M0 = 01),
  *         the sent data is handled as a set of u16. In this case, Size must indicate the number
  *         of u16 provided through pTxData.
  * @param  husart USART handle.
  * @param  pTxData Pointer to data buffer (u8 or u16 data elements).
  * @param  Size Amount of data elements (u8 or u16) to be sent.
  * @param  Timeout Timeout duration.
  * @retval HAL status
  */
HAL_StatusTypeDef HAL_USART_Transmit(USART_HandleTypeDef *husart, uint8_t *pTxData, uint16_t Size, uint32_t Timeout)
{
  uint8_t  *ptxdata8bits;
  uint16_t *ptxdata16bits;
  uint32_t tickstart;

  if (husart->State == HAL_USART_STATE_READY)
  {
    if ((pTxData == NULL) || (Size == 0U))
    {
      return  HAL_ERROR;
    }

    /* Process Locked */
    __HAL_LOCK(husart);

    husart->ErrorCode = HAL_USART_ERROR_NONE;
    husart->State = HAL_USART_STATE_BUSY_TX;

    /* Init tickstart for timeout management */
    tickstart = HAL_GetTick();

    husart->TxXferSize = Size;
    husart->TxXferCount = Size;

    /* In case of 9bits/No Parity transfer, pTxData needs to be handled as a uint16_t pointer */
    if ((husart->Init.WordLength == USART_WORDLENGTH_9B) && (husart->Init.Parity == USART_PARITY_NONE))
    {
      ptxdata8bits  = NULL;
      ptxdata16bits = (uint16_t *) pTxData;
    }
    else
    {
      ptxdata8bits  = pTxData;
      ptxdata16bits = NULL;
    }

    /* Check the remaining data to be sent */
    while (husart->TxXferCount > 0U)
    {
      if (USART_WaitOnFlagUntilTimeout(husart, USART_FLAG_TXE, RESET, tickstart, Timeout) != HAL_OK)
      {
        return HAL_TIMEOUT;
      }
      if (ptxdata8bits == NULL)
      {
        husart->Instance->TDR = (uint16_t)(*ptxdata16bits & 0x01FFU);
        ptxdata16bits++;
      }
      else
      {
        husart->Instance->TDR = (uint8_t)(*ptxdata8bits & 0xFFU);
        ptxdata8bits++;
      }

      husart->TxXferCount--;
    }

    if (USART_WaitOnFlagUntilTimeout(husart, USART_FLAG_TC, RESET, tickstart, Timeout) != HAL_OK)
    {
      return HAL_TIMEOUT;
    }

    /* Clear Transmission Complete Flag */
    __HAL_USART_CLEAR_FLAG(husart, USART_CLEAR_TCF);

    /* Clear overrun flag and discard the received data */
    __HAL_USART_CLEAR_OREFLAG(husart);
    __HAL_USART_SEND_REQ(husart, USART_RXDATA_FLUSH_REQUEST);
    __HAL_USART_SEND_REQ(husart, USART_TXDATA_FLUSH_REQUEST);

    /* At end of Tx process, restore husart->State to Ready */
    husart->State = HAL_USART_STATE_READY;

    /* Process Unlocked */
    __HAL_UNLOCK(husart);

    return HAL_OK;
  }
  else
  {
    return HAL_BUSY;
  }
}


/**
  * @brief Receive an amount of data in blocking mode.
  * @note   To receive synchronous data, dummy data are simultaneously transmitted.
  * @note   When USART parity is not enabled (PCE = 0), and Word Length is configured to 9 bits (M1-M0 = 01),
  *         the received data is handled as a set of u16. In this case, Size must indicate the number
  *         of u16 available through pRxData.
  * @param husart USART handle.
  * @param pRxData Pointer to data buffer (u8 or u16 data elements).
  * @param Size Amount of data elements (u8 or u16) to be received.
  * @param Timeout Timeout duration.
  * @retval HAL status
  */
HAL_StatusTypeDef HAL_USART_Receive(USART_HandleTypeDef *husart, uint8_t *pRxData, uint16_t Size, uint32_t Timeout)
{
  uint8_t  *prxdata8bits;
  uint16_t *prxdata16bits;
  uint16_t uhMask;
  uint32_t tickstart;

  if (husart->State == HAL_USART_STATE_READY)
  {
    if ((pRxData == NULL) || (Size == 0U))
    {
      return  HAL_ERROR;
    }

    /* Process Locked */
    __HAL_LOCK(husart);

    husart->ErrorCode = HAL_USART_ERROR_NONE;
    husart->State = HAL_USART_STATE_BUSY_RX;

    /* Init tickstart for timeout management */
    tickstart = HAL_GetTick();

    husart->RxXferSize = Size;
    husart->RxXferCount = Size;

    /* Computation of USART mask to apply to RDR register */
    USART_MASK_COMPUTATION(husart);
    uhMask = husart->Mask;

    /* In case of 9bits/No Parity transfer, pRxData needs to be handled as a uint16_t pointer */
    if ((husart->Init.WordLength == USART_WORDLENGTH_9B) && (husart->Init.Parity == USART_PARITY_NONE))
    {
      prxdata8bits  = NULL;
      prxdata16bits = (uint16_t *) pRxData;
    }
    else
    {
      prxdata8bits  = pRxData;
      prxdata16bits = NULL;
    }

    /* as long as data have to be received */
    while (husart->RxXferCount > 0U)
    {
#if defined(USART_CR2_SLVEN)
      if (husart->SlaveMode == USART_SLAVEMODE_DISABLE)
#endif /* USART_CR2_SLVEN */
      {
        /* Wait until TXE flag is set to send dummy byte in order to generate the
        * clock for the slave to send data.
        * Whatever the frame length (7, 8 or 9-bit long), the same dummy value
        * can be written for all the cases. */
        if (USART_WaitOnFlagUntilTimeout(husart, USART_FLAG_TXE, RESET, tickstart, Timeout) != HAL_OK)
        {
          return HAL_TIMEOUT;
        }
        husart->Instance->TDR = (USART_DUMMY_DATA & (uint16_t)0x0FF);
      }

      /* Wait for RXNE Flag */
      if (USART_WaitOnFlagUntilTimeout(husart, USART_FLAG_RXNE, RESET, tickstart, Timeout) != HAL_OK)
      {
        return HAL_TIMEOUT;
      }

      if (prxdata8bits == NULL)
      {
        *prxdata16bits = (uint16_t)(husart->Instance->RDR & uhMask);
        prxdata16bits++;
      }
      else
      {
        *prxdata8bits = (uint8_t)(husart->Instance->RDR & (uint8_t)(uhMask & 0xFFU));
        prxdata8bits++;
      }

      husart->RxXferCount--;

    }

#if defined(USART_CR2_SLVEN)
    /* Clear SPI slave underrun flag and discard transmit data */
    if (husart->SlaveMode == USART_SLAVEMODE_ENABLE)
    {
      __HAL_USART_CLEAR_UDRFLAG(husart);
      __HAL_USART_SEND_REQ(husart, USART_TXDATA_FLUSH_REQUEST);
    }
#endif /* USART_CR2_SLVEN */

    /* At end of Rx process, restore husart->State to Ready */
    husart->State = HAL_USART_STATE_READY;

    /* Process Unlocked */
    __HAL_UNLOCK(husart);

    return HAL_OK;
  }
  else
  {
    return HAL_BUSY;
  }
}



// EOF
