/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#include "oled.h"
#include "delay.h"
#include "stm32l4xx_hal_gpio.h"
#include "stm32l4xx_hal_rcc.h"
#include "stm32l4xx_hal_dma.h"
#include "stm32l4xx_hal_spi.h"
#include <string.h>

// Reset and config sequence.
//
// As measured! No attempt to understand them here.
static const uint8_t reset_commands[] = {
    0xae,               // display off
    0x20, 0x00,         // horz addr-ing mode
    0x40,               // ram display start line: 0
    0xa1,               // cold addr 127 mapped to seg0
    0xa8, 0x3f,         // set multiplex ratio: 64
    0xc8,               // remapped mode: scan from COMn to COM0
    0xd3, 0x00,         // display offset (vertical shift): 0
    0xda, 0x12,         // seq com pin conf: alt com pin
    0xd5, 0x80,         // set display clock divide ratio
    0xd9, 0xf1,         // set pre-change period
    0xdb, 0x30,         // Cvomh deselect level
    0x81, 0xff,         // Contrast: max
    0xa4,               // display ram contents (not all on)
    0xa6,               // normal not inverted
    0x8d, 0x14,         // enable charge pump
    0xaf                // display on
};

// Bytes to send before sending the 1024 bytes of pixel data.
//
static const uint8_t before_show[] = { 
    0x21, 0x00, 0x7f,       // setup column address range (start, end): 9-127
    0x22, 0x00, 0x07        // setup page start/end address: 0 - 7
};

// OLED connections: 
// - all on port A
// - all push/pull outputs
//
#define RESET_PIN       GPIO_PIN_6
#define DC_PIN          GPIO_PIN_8
#define CS_PIN          GPIO_PIN_4
#define SPI_SCK         GPIO_PIN_5
#define SPI_MOSI        GPIO_PIN_7

HAL_StatusTypeDef HAL_SPI_Transmit(SPI_HandleTypeDef *hspi, uint8_t *pData, uint16_t Size, uint32_t Timeout);

static SPI_HandleTypeDef   spi_port;

// write_bytes()
//
    static inline void
write_bytes(int len, const uint8_t *buf)
{
    // send via SPI(1)
    HAL_SPI_Transmit(&spi_port, (uint8_t *)buf, len, HAL_MAX_DELAY);
}

// oled_write_cmd()
//
    void
oled_write_cmd(uint8_t cmd)
{
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 0);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    write_bytes(1, &cmd);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
}

// oled_write_cmd_sequence()
//
    void
oled_write_cmd_sequence(int len, const uint8_t *cmds)
{
    for(int i=0; i<len; i++) {
        oled_write_cmd(cmds[i]);
    }
}

// oled_write_data()
//
    void
oled_write_data(int len, const uint8_t *pixels)
{
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    write_bytes(len, pixels);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
}

// oled_setup()
//
// Ok to call this lots.
//
    void
oled_setup(void)
{
    static uint32_t inited;

    if(inited == 0x238a572F) {
        return;
    }
    inited = 0x238a572F;

    // enable some internal clocks
    __HAL_RCC_GPIOA_CLK_ENABLE();
    __HAL_RCC_SPI1_CLK_ENABLE();

    // simple pins
    GPIO_InitTypeDef setup = {
        .Pin = RESET_PIN | DC_PIN | CS_PIN,
        .Mode = GPIO_MODE_OUTPUT_PP,
        .Pull = GPIO_NOPULL,
        .Speed = GPIO_SPEED_FREQ_MEDIUM,
        .Alternate = 0,
    };
    HAL_GPIO_Init(GPIOA, &setup);

    // starting values
    HAL_GPIO_WritePin(GPIOA, RESET_PIN | CS_PIN | DC_PIN, 1);

    // SPI pins
    setup.Pin = SPI_SCK | SPI_MOSI;
    setup.Mode = GPIO_MODE_AF_PP;
    setup.Alternate = GPIO_AF5_SPI1;
    HAL_GPIO_Init(GPIOA, &setup);

    // lock the RESET pin so that St's DFU code doesn't clear screen
    // it might be trying to use it a MISO signal for SPI loading
    HAL_GPIO_LockPin(GPIOA, RESET_PIN | CS_PIN | DC_PIN);

    // 10ms low-going pulse on reset pin
    delay_ms(1);
    HAL_GPIO_WritePin(GPIOA, RESET_PIN, 0);
    delay_ms(10);
    HAL_GPIO_WritePin(GPIOA, RESET_PIN, 1);

    memset(&spi_port, 0, sizeof(spi_port));

    spi_port.Instance = SPI1;

    // see SPI_InitTypeDef
    spi_port.Init.Mode = SPI_MODE_MASTER;
    spi_port.Init.Direction = SPI_DIRECTION_2LINES;
    spi_port.Init.DataSize = SPI_DATASIZE_8BIT;
    spi_port.Init.CLKPolarity = SPI_POLARITY_LOW;
    spi_port.Init.CLKPhase = SPI_PHASE_1EDGE;
    spi_port.Init.NSS = SPI_NSS_SOFT;
    spi_port.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16;    // conservative
    spi_port.Init.FirstBit = SPI_FIRSTBIT_MSB;
    spi_port.Init.TIMode = SPI_TIMODE_DISABLED;
    spi_port.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLED;

    HAL_SPI_Init(&spi_port);

    // where: SPI1->CR1, CR2, SR
    // mpy settings:
    //      '0x354', '0x1700', '0x002'
    // this code:
    //      '0x37c', '0x1700', '0x603'
    //SPI1->CR1 = 0x354;

    // write a sequence to reset things
    oled_write_cmd_sequence(sizeof(reset_commands), reset_commands);
}

// oled_show_raw()
//
// No decompression.
//
    void
oled_show_raw(uint32_t len, const uint8_t *pixels)
{
    oled_setup();

    oled_write_cmd_sequence(sizeof(before_show), before_show);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    write_bytes(len, pixels);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
}

// oled_show()
//
// Perform simple RLE decompression.
//
    void
oled_show(const uint8_t *pixels)
{
    oled_setup();

    oled_write_cmd_sequence(sizeof(before_show), before_show);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    uint8_t         buf[127];
    const uint8_t *p = pixels;

    // NOTE: must also update code in oled_show_progress, which dups this heavily.
    while(1) {
        uint8_t hdr = *(p++);
        if(!hdr) break;

        uint8_t len = hdr & 0x7f;
        if(hdr & 0x80) {
            // random bytes follow
            memcpy(buf, p, len);
            p += len;
        } else {
            // repeat same byte
            memset(buf, *p, len);
            p++;
        }

        write_bytes(len, buf);
    }

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
}

// oled_show_progress()
//
// Perform simple RLE decompression, and add a bar on final screen line.
//
    void
oled_show_progress(const uint8_t *pixels, int progress)
{
    oled_setup();

    oled_write_cmd_sequence(sizeof(before_show), before_show);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    uint8_t         buf[127];
    const uint8_t *p = pixels;

    const uint16_t p_start = 896;
    uint32_t p_count = 1280 * progress / 1000;

    if(p_count > 128) p_count = 128;
    if(p_count < 0) p_count = 0;

    bool last_line = false;

    uint16_t offset = 0;
    while(1) {
        uint8_t hdr = *(p++);
        if(hdr == 0) break;

        uint8_t len = hdr & 0x7f;
        if(hdr & 0x80) {
            // random bytes follow
            memcpy(buf, p, len);
            p += len;
        } else {
            // repeat same byte
            memset(buf, *p, len);
            p++;
        }

        if(!last_line && (offset+len) >= p_start) {
            last_line = true;

            // adjust so we're aligned w/ last line
            int h = p_start - offset;
            if(h) {
                write_bytes(h, buf);
                memmove(buf, buf+h, len-h);
                len -= h;
                offset += h;
            }
        }

        if(last_line) {
            for(int j=0; (p_count > 0) && (j<len); j++, p_count--) {
                buf[j] |= 0x80;
            }
        }

        write_bytes(len, buf);
        offset += len;
    }

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
}


// EOF
