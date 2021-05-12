/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * Setup and talk with the ESP-PSRAM64H chip, new on Mk4.
 * See stm32l4xx_hal_qspi.h
 *
 */
#include "psram.h"
#include "oled.h"
#include "assets/screens.h"
#include <string.h>
#include "delay.h"
#include "stm32l4xx_hal.h"
#include "console.h"

uint8_t psram_chip_eid[8];

static OSPI_HandleTypeDef  qh;

    void
psram_setup(void)
{
    // Using OSPI1 block

    // enable clocks
    __HAL_RCC_OSPI1_CLK_ENABLE();
    __HAL_RCC_GPIOE_CLK_ENABLE();

    // reset module
    __HAL_RCC_OSPI1_FORCE_RESET();
    __HAL_RCC_OSPI1_RELEASE_RESET();

   // configure pins: Port E PE10-PE15
    GPIO_InitTypeDef setup = {
        .Pin = GPIO_PIN_10 | GPIO_PIN_11 | GPIO_PIN_12 | GPIO_PIN_13 | GPIO_PIN_14 | GPIO_PIN_15,
        .Mode = GPIO_MODE_AF_PP,            // not sure
        .Pull = GPIO_NOPULL,                // not sure
        .Speed = GPIO_SPEED_FREQ_VERY_HIGH,
        .Alternate = GPIO_AF10_OCTOSPIM_P1,
    };
    HAL_GPIO_Init(GPIOE, &setup);

#if 0
  uint32_t FifoThreshold;             /*!< This is the threshold used by the Peripheral to generate the interrupt
                                           indicating that data are available in reception or free place
                                           is available in transmission.
                                           This parameter can be a value between 1 and 32 */
  uint32_t DualQuad;                  /*!< It enables or not the dual-quad mode which allow to access up to
                                           quad mode on two different devices to increase the throughput.
                                           This parameter can be a value of @ref OSPI_DualQuad */
  uint32_t MemoryType;                /*!< It indicates the external device type connected to the OSPI.
                                           This parameter can be a value of @ref OSPI_MemoryType */
  uint32_t DeviceSize;                /*!< It defines the size of the external device connected to the OSPI,
                                           it corresponds to the number of address bits required to access
                                           the external device.
                                           This parameter can be a value between 1 and 32 */
  uint32_t ChipSelectHighTime;        /*!< It defines the minimun number of clocks which the chip select
                                           must remain high between commands.
                                           This parameter can be a value between 1 and 8 */
  uint32_t FreeRunningClock;          /*!< It enables or not the free running clock.
                                           This parameter can be a value of @ref OSPI_FreeRunningClock */
  uint32_t ClockMode;                 /*!< It indicates the level of clock when the chip select is released.
                                           This parameter can be a value of @ref OSPI_ClockMode */
  uint32_t ClockPrescaler;            /*!< It specifies the prescaler factor used for generating
                                           the external clock based on the AHB clock.
                                           This parameter can be a value between 1 and 256 */
  uint32_t SampleShifting;            /*!< It allows to delay to 1/2 cycle the data sampling in order
                                           to take in account external signal delays.
                                           This parameter can be a value of @ref OSPI_SampleShifting */
  uint32_t DelayHoldQuarterCycle;     /*!< It allows to hold to 1/4 cycle the data.
                                           This parameter can be a value of @ref OSPI_DelayHoldQuarterCycle */
  uint32_t ChipSelectBoundary;        /*!< It enables the transaction boundary feature and
                                           defines the boundary of bytes to release the chip select.
                                           This parameter can be a value between 0 and 31 */
  uint32_t DelayBlockBypass;          /*!< It enables the delay block bypass, so the sampling is not affected
                                           by the delay block.
                                           This parameter can be a value of @ref OSPI_DelayBlockBypass */
#if   defined (OCTOSPI_DCR3_MAXTRAN)
  uint32_t MaxTran;                   /*!< It enables the communication regulation feature. The chip select is
                                           released every MaxTran+1 bytes when the other OctoSPI request the access
                                           to the bus.
                                           This parameter can be a value between 0 and 255 */
#endif
#if   defined (OCTOSPI_DCR4_REFRESH)
  uint32_t Refresh;                   /*!< It enables the refresh rate feature. The chip select is released every
                                           Refresh+1 clock cycles.
                                           This parameter can be a value between 0 and 0xFFFFFFFF */
#endif
#endif

    memset(&qh, 0, sizeof(qh));

    qh.Instance = OCTOSPI1;
    qh.Init.FifoThreshold = 4;                          // ??
    qh.Init.DualQuad = HAL_OSPI_DUALQUAD_DISABLE;
    qh.Init.MemoryType = HAL_OSPI_MEMTYPE_MICRON;       // seems like 8-bit mode stuff?
    qh.Init.DeviceSize = 23;
    qh.Init.ChipSelectHighTime = 8;             // maxed out to start
    qh.Init.FreeRunningClock = HAL_OSPI_FREERUNCLK_DISABLE; 
    qh.Init.ClockMode = HAL_OSPI_CLOCK_MODE_0;                      // low clock between ops
    qh.Init.ClockPrescaler = 16;                 // prescaller, decrease me

    qh.Init.ChipSelectBoundary = 0;            // set for 1024-byte block size?


    // module init 
    HAL_StatusTypeDef rv = HAL_OSPI_Init(&qh);
    ASSERT(rv == HAL_OK);

    // do some SPI commands first

    // Read Electronic ID
    // - length not clear from datasheet, but bits repeat after 8 bytes

    OSPI_RegularCmdTypeDef cmd = {
        .OperationType = HAL_OSPI_OPTYPE_COMMON_CFG,
        .Instruction = 0x9f,                    // "read ID" command
        .InstructionMode = HAL_OSPI_INSTRUCTION_1_LINE,
        .Address = 0,                           // dont care
        .AddressSize = HAL_OSPI_ADDRESS_24_BITS,
        .AddressMode = HAL_OSPI_ADDRESS_1_LINE,
        .AlternateBytesMode = HAL_OSPI_ALTERNATE_BYTES_NONE,
        .DummyCycles = 0,
        .DataMode = HAL_OSPI_DATA_1_LINE,
        .NbData = sizeof(psram_chip_eid),                        // how much to read in bytes
    };

    // Start "Indirection functional mode"
    rv = HAL_OSPI_Command(&qh, &cmd, HAL_MAX_DELAY);
    if(rv != HAL_OK) goto fail;

    rv = HAL_OSPI_Receive(&qh, psram_chip_eid, HAL_MAX_DELAY);
    if(rv != HAL_OK) goto fail;

    puts2("PSRAM EID: "); 
    hex_dump(psram_chip_eid, sizeof(psram_chip_eid));
    ASSERT(psram_chip_eid[0] == 0x0d);
    ASSERT(psram_chip_eid[1] == 0x5d);

#if 0
    OSPI_MemoryMappedTypeDef mmap = {
    };

    rv = HAL_OSPI_MemoryMapped(&qh, &cmd, &mmap);
    ASSERT(rv == HAL_OK);
#endif

    return;

fail:
    puts("PSRAM fail");

    oled_setup();
    oled_show(screen_fatal);

    LOCKUP_FOREVER();
}

// EOF
