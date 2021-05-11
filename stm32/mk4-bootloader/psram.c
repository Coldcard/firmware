/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * Setup and talk with the ESP-PSRAM64H chip, new on Mk4.
 * See stm32l4xx_hal_qspi.h
 *
 */
#include "psram.h"
#include <string.h>
#include "delay.h"
#include "stm32l4xx_hal.h"
#include "console.h"

static QSPI_HandleTypeDef  qh;

    void
psram_setup(void)
{
    // enable clocks
    __HAL_RCC_QSPI_CLK_ENABLE();
    __HAL_RCC_GPIOE_CLK_ENABLE();

    // reset module
    __HAL_RCC_QSPI_FORCE_RESET();
    __HAL_RCC_QSPI_RELEASE_RESET();

   // configure pins: Port E PE10-PE15
    GPIO_InitTypeDef setup = {
        .Pin = GPIO_PIN_10 | GPIO_PIN_11 | GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15,
        .Mode = GPIO_MODE_AF_PP,            // not sure
        .Pull = GPIO_NOPULL,                // not sure
        .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
        .Alternate = GPIO_AF10_QUADSPI,
    };
    HAL_GPIO_Init(GPIOE, &setup);

#if 0
  QUADSPI_TypeDef            *Instance;        /* QSPI registers base address        */
  QSPI_InitTypeDef           Init;             /* QSPI communication parameters      */
  uint8_t                    *pTxBuffPtr;      /* Pointer to QSPI Tx transfer Buffer */
  __IO uint32_t              TxXferSize;       /* QSPI Tx Transfer size              */
  __IO uint32_t              TxXferCount;      /* QSPI Tx Transfer Counter           */
  uint8_t                    *pRxBuffPtr;      /* Pointer to QSPI Rx transfer Buffer */
  __IO uint32_t              RxXferSize;       /* QSPI Rx Transfer size              */
  __IO uint32_t              RxXferCount;      /* QSPI Rx Transfer Counter           */
  DMA_HandleTypeDef          *hdma;            /* QSPI Rx/Tx DMA Handle parameters   */
  __IO HAL_LockTypeDef       Lock;             /* Locking object                     */
  __IO HAL_QSPI_StateTypeDef State;            /* QSPI communication state           */
  __IO uint32_t              ErrorCode;        /* QSPI Error code                    */
  uint32_t                   Timeout;          /* Timeout for the QSPI memory access */
#endif

    memset(&qh, 0, sizeof(qh));

    qh.Instance = QUADSPI;
    qh.Init.ClockPrescaler = 64;        // conservative starting value
    qh.Init.FifoThreshold = 4;          // indirect mode only
    qh.Init.FlashSize = 23;
    qh.Init.ChipSelectHighTime = QSPI_CS_HIGH_TIME_8_CYCLE;     // maxed for now
    qh.Init.ClockMode = QSPI_CLOCK_MODE_0;                      // low clock between ops
    qh.Init.FlashID = QSPI_FLASH_ID_1;
    qh.Init.DualFlash = QSPI_DUALFLASH_DISABLE;

    // module init 
    HAL_StatusTypeDef rv = HAL_QSPI_Init(&qh);
    ASSERT(rv == HAL_OK);

    // do some SPI commands first

    QSPI_CommandTypeDef cmd = {
        .Instruction = 0x9f,                    // "read ID" command
        .InstructionMode = QSPI_INSTRUCTION_1_LINE,
        .Address = 0,                           // dont care
        .AddressSize = QSPI_ADDRESS_24_BITS,
        .AddressMode = QSPI_ADDRESS_1_LINE,
        .AlternateByteMode = QSPI_ALTERNATE_BYTES_NONE,
        .DummyCycles = 0,
        .DataMode = QSPI_DATA_1_LINE,
        .NbData = 8,                                // how much to read in bytes
        .DdrMode = QSPI_DDR_MODE_DISABLE,           // normal
        .SIOOMode = QSPI_SIOO_INST_EVERY_CMD,       // normal
    };

    // Start "Indirection functional mode"
    uint8_t buf[8];
    rv = HAL_QSPI_Command(&qh, &cmd, HAL_MAX_DELAY);
    ASSERT(rv == HAL_OK);

    rv = HAL_QSPI_Receive(&qh, buf, HAL_MAX_DELAY);

    puts2("HAL_QSPI_Receive "); puthex2(rv); putchar('\n');
    hex_dump(buf, sizeof(buf));

#if 0
    QSPI_MemoryMappedTypeDef mmap = {
    };

    rv = HAL_QSPI_MemoryMapped(&qh, &cmd, &mmap);
    ASSERT(rv == HAL_OK);
#endif
}

// EOF
