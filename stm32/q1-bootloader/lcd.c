/*
 * (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 * 
 * Using "oled_" prefix here for code compat w/ mk4. It's actually an LCD.
 * 
 */
#include "oled.h"
#include "delay.h"
#include "rng.h"
#include "console.h"
#include "stm32l4xx_hal.h"
#include <string.h>
#include "misc.h"
#include "gpio.h"
#include "assets/q1_screens.h"

// OLED pins block use of MCO for testing
#undef DISABLE_LCD
//#define DISABLE_LCD

// LCD connections: 
// - mostly on port A
// - mostly push/pull outputs
// - shared with GPU
//
#define RESET_PIN       GPIO_PIN_6
#define DC_PIN          GPIO_PIN_8
#define CS_PIN          GPIO_PIN_4
#define SPI_SCK         GPIO_PIN_5
#define SPI_MOSI        GPIO_PIN_7

// port B
#define TEAR_PIN        GPIO_PIN_11

const int LCD_WIDTH = 320;
const int LCD_HEIGHT = 240;
const int NUM_PIXELS = (LCD_WIDTH*LCD_HEIGHT);

const int PROGRESS_BAR_H = 5;
const int PROGRESS_BAR_Y = (LCD_HEIGHT - PROGRESS_BAR_H);

// doing RGB565, but swab16
const uint16_t COL_BLACK = 0;
const uint16_t COL_WHITE = ~0;
const uint16_t COL_FOREGROUND = 0x60fd;     //SWAB16(0xfd60);     // orange

// track what we are showing so we never re-send same thing (too slow)
static const uint8_t *last_screen;

// memset2()
//
    static inline void
memset2(uint16_t *dest, uint16_t value, uint16_t byte_len)
{
    for(; byte_len; byte_len-=2, dest++) {
        *dest = value;
    }
}

#ifndef DISABLE_LCD
static SPI_HandleTypeDef   spi_port;
#endif

// forward refs
void lcd_fill_solid(uint16_t pattern);
void lcd_write_rows(int y, int num_rows, uint16_t *pixels);

static inline void wait_vsync(void) {
    // PB11 is TEAR input: a positive pulse every 60Hz that
    // corresponds to vertical blanking time
    uint32_t timeout = 1000000;
    for(; timeout; timeout--) {
        if(HAL_GPIO_ReadPin(GPIOB, TEAR_PIN) != 0) {
            return;
        }
    }
    puts("TEAR timeout");
}

// write_bytes()
//
    static inline void
write_bytes(int len, const uint8_t *buf)
{
#ifndef DISABLE_LCD
    // send via SPI(1)
    HAL_SPI_Transmit(&spi_port, (uint8_t *)buf, len, HAL_MAX_DELAY);
#endif
}

// lcd_write_cmd()
//
    static void
lcd_write_cmd(uint8_t cmd)
{
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 0);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    write_bytes(1, &cmd);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
}


// lcd_write_data()
//
    static void
lcd_write_data(int len, const uint8_t *pixels)
{
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    write_bytes(len, pixels);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
}

// lcd_write_cmd4()
//
    static void
lcd_write_cmd4(uint8_t cmd, uint16_t a, uint16_t b)
{
    lcd_write_cmd(cmd);
    uint8_t d[4] = { (a>>8), a&0xff, (b>>8), b&0xff };
    lcd_write_data(4, d);
}

// lcd_write_data1()
//
    static void
lcd_write_data1(uint8_t data)
{
    lcd_write_data(1, &data);
}

// lcd_spi_setup()
//
// Just setup SPI, do not reset display, etc.
//
    void
lcd_spi_setup(void)
{
#ifndef DISABLE_LCD
    // might already be setup
    if(spi_port.Instance == SPI1) return;

    memset(&spi_port, 0, sizeof(spi_port));

    spi_port.Instance = SPI1;

    // see SPI_InitTypeDef
    spi_port.Init.Mode = SPI_MODE_MASTER;
    spi_port.Init.Direction = SPI_DIRECTION_2LINES;
    spi_port.Init.DataSize = SPI_DATASIZE_8BIT;
    spi_port.Init.CLKPolarity = SPI_POLARITY_LOW;
    spi_port.Init.CLKPhase = SPI_PHASE_1EDGE;
    spi_port.Init.NSS = SPI_NSS_SOFT;
    // page 43: cycle > 66ns for WRITE mode, 15ns low/high times min
    // div16 => gives 124ns 
    // div32 => gives 270ns
    // div2 => gives ~16ns and still works? 8/7ns high/low times!
    spi_port.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_2;
    spi_port.Init.FirstBit = SPI_FIRSTBIT_MSB;
    spi_port.Init.TIMode = SPI_TIMODE_DISABLED;
    spi_port.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLED;

    HAL_SPI_Init(&spi_port);
#endif
}

// lcd_full_setup()
//
    void
lcd_full_setup(void)
{
    // configure SPI port and associated pins
    oled_setup();

    // Attempt to avoid flash of garbage at boot/powerup
    // - just enough to clear screen based on default power-up config of LCD
    lcd_write_cmd(0x28);            // DISPOFF
    lcd_write_cmd(0x36);            // MADCTL: memory addr ctrl, page 215
    lcd_write_data1(0x60);          // MV=1 => horz mode, first byte=top-left corner, RGB order
    lcd_fill_solid(COL_BLACK);      // works only on second+ reboots/resets

    // Need 10us+ low-going pulse on reset pin; do 1ms.
    delay_ms(1);
    HAL_GPIO_WritePin(GPIOA, RESET_PIN, 0);
    delay_ms(1);
    HAL_GPIO_WritePin(GPIOA, RESET_PIN, 1);

    // "It is necessary to wait 5msec after releasing RESX before sending commands.
    // Also Sleep Out command cannot be sent for 120msec."
    delay_ms(120);                  // 120ms - reset recovery time

    // Official reset sequence
    // rx'ed by email from vendor
    lcd_write_cmd(0x11);            // SLPOUT: Sleep Out => turn off sleep mode
    delay_ms(5);                    // 5ms - wake up time

    //--display and color format setting
    lcd_write_cmd(0x36);            // MADCTL: memory addr ctrl, page 215
    lcd_write_data1(0x60);          // MV=1 => horz mode, first byte=top-left corner, RGB order

    lcd_write_cmd(0x3a);            // COLMOD: pixel format
    lcd_write_data1(0x05);          // => 16bit/pixel

    //--ST7789SS Frame rate setting
    lcd_write_cmd(0xb2);            // PORCTRL - porch control
    lcd_write_data1(0x0c); 
    lcd_write_data1(0x0c); 
    lcd_write_data1(0x00); 
    lcd_write_data1(0x33); 
    lcd_write_data1(0x33); 

    lcd_write_cmd(0xb7); 
    lcd_write_data1(0x35); 

    //--ST7789SS Power setting
    lcd_write_cmd(0xbb);            // VCOMS
    lcd_write_data1(0x25); //35  20   

    lcd_write_cmd(0xc0);            // LCM
    lcd_write_data1(0x2c); 

    lcd_write_cmd(0xc2);            // VDVVRHEN
    lcd_write_data1(0x01); 

    lcd_write_cmd(0xc3);            // VRHS
    lcd_write_data1(0x13); //0e

    lcd_write_cmd(0xc4);            // VDVSET
    lcd_write_data1(0x20); 

    lcd_write_cmd(0xc6);            // FRCTR2
    lcd_write_data1(0x0f); 

    lcd_write_cmd(0xd0);            // PWCTRL1
    lcd_write_data1(0xa4); 
    lcd_write_data1(0xa1); 


    //--ST7789SS gamma setting
    lcd_write_cmd(0xe0);            // PVGAMCTRL
    lcd_write_data1(0xd0); 
    lcd_write_data1(0x00); 
    lcd_write_data1(0x03); 
    lcd_write_data1(0x09); 
    lcd_write_data1(0x13); 
    lcd_write_data1(0x1c); 
    lcd_write_data1(0x3a); 
    lcd_write_data1(0x55); 
    lcd_write_data1(0x48); 
    lcd_write_data1(0x18); 
    lcd_write_data1(0x12); 
    lcd_write_data1(0x0e); 
    lcd_write_data1(0x19); 
    lcd_write_data1(0x1e);
     
    lcd_write_cmd(0xe1);            // NVGAMCTRL
    lcd_write_data1(0xd0); 
    lcd_write_data1(0x00); 
    lcd_write_data1(0x03); 
    lcd_write_data1(0x09); 
    lcd_write_data1(0x05); 
    lcd_write_data1(0x25); 
    lcd_write_data1(0x3a); 
    lcd_write_data1(0x55); 
    lcd_write_data1(0x50); 
    lcd_write_data1(0x3d); 
    lcd_write_data1(0x1c); 
    lcd_write_data1(0x1d); 
    lcd_write_data1(0x1d); 
    lcd_write_data1(0x1e);

    lcd_write_cmd(0x35);            // TEON - Tear signal on
    lcd_write_data1(0x0);

    // clear screen memory, including top status lines
    lcd_fill_solid(COL_BLACK);

    // finally
    lcd_write_cmd(0x21);            // INVON 
    lcd_write_cmd(0x29);            // DISPON
    delay_ms(50);

    last_screen = NULL;
}

// oled_setup()
//
// Ok to call this lots.
//
    void
oled_setup(void)
{
#ifdef DISABLE_LCD
    puts("lcd disabled");return;     // disable so I can use MCO
#endif

    static uint32_t inited;

    if(inited == 0x238a572F) {
        return;
    }
    inited = 0x238a572F;

    // enable some internal clocks
    __HAL_RCC_SPI1_CLK_ENABLE();

    // take over from GPU
    // - can be issue when coming in via callgate from mpy which might have been showing menu
    HAL_GPIO_WritePin(GPIOE, PIN_G_CTRL, 1);        // set G_CTRL pin -- we have control

    // .. wait for GPU to finish it's work
    // - might take 16+ms because waiting for next vsync, etc
    for(int i=0; i<100; i++) {
        if(HAL_GPIO_ReadPin(GPIOE, PIN_G_BUSY) == 0) break;
        delay_ms(1);
    }

    // Simple pins
    // - must be opendrain to allow GPU to share
    GPIO_InitTypeDef setup = {
        .Pin = RESET_PIN | CS_PIN | DC_PIN,
        .Mode = GPIO_MODE_OUTPUT_OD,
        .Pull = GPIO_PULLUP,
        .Speed = GPIO_SPEED_FREQ_MEDIUM,
        .Alternate = 0,
    };
    HAL_GPIO_Init(GPIOA, &setup);

    // starting values
    HAL_GPIO_WritePin(GPIOA, RESET_PIN | CS_PIN | DC_PIN, 1);

    // SPI pins (same but with AF)
    setup.Pin = SPI_SCK | SPI_MOSI;
    setup.Alternate = GPIO_AF5_SPI1;
    setup.Mode = GPIO_MODE_AF_PP;
    setup.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    HAL_GPIO_Init(GPIOA, &setup);

    // config SPI port
    lcd_spi_setup();
    rng_delay();
}

#if 0
// oled_show_raw()
//
// No decompression. Just used for factory show. 1k bytes
//
    void
oled_show_raw(uint32_t len, const uint8_t *pixels)
{
    // 1024 / 2 = 512 / 320 = 1.6 => just one row!
    lcd_write_rows(LCD_HEIGHT-3, 1, (uint16_t *)pixels);
    lcd_write_rows(LCD_HEIGHT-2, 1, (uint16_t *)pixels);
}
#endif

// lcd_fill_solid()
//
    void
lcd_fill_solid(uint16_t pattern)
{
    // note, MADCTL MV/MX/MY setting causes row vs. col swap here
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, 0, LCD_HEIGHT-1);        // RASET - Row address set range (y)

    lcd_write_cmd(0x2c);            // RAMWR - memory write

    uint16_t    row[LCD_WIDTH];
    memset2(row, pattern, sizeof(row));

    for(int y=0; y<LCD_HEIGHT; y++) {
        lcd_write_data(sizeof(row), (uint8_t *)&row);
    }
}

// lcd_write_rows()
//
    void
lcd_write_rows(int y, int num_rows, uint16_t *pixels)
{
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, y, LCD_HEIGHT-1);        // RASET - Row address set range (y)

    lcd_write_cmd(0x2c);            // RAMWR - memory write

    lcd_write_data(num_rows * 2 * LCD_WIDTH, (uint8_t *)pixels);
}

// oled_show()
//
// Perform simple RLE decompression, and pixel expansion.
//
    void
oled_show(const uint8_t *pixels)
{
    oled_setup();

    // we are NOT fast enough to send entire screen during the
    // vblanking time, so either we show torn stuff, or we flash display off a little
    wait_vsync();
    lcd_write_cmd(0x28);            // DISPOFF

    // always full update: minus part we aren't saving "TOP_CROP" at top edge
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    // RASET - Row address set range (y) 
    lcd_write_cmd4(0x2b, SCREEN_TOP_CROP, LCD_HEIGHT-1);
    lcd_write_cmd(0x2c);            // RAMWR - memory write

    uint8_t         buf[127];
    uint16_t        expand[sizeof(buf)*8];
    const uint8_t *p = pixels;

    uint16_t    blk_row[LCD_WIDTH];
    memset2(blk_row, COL_BLACK, sizeof(blk_row));

    while(1) {
        uint8_t hdr = *(p++);
        if(!hdr) break;         // end marker

        uint8_t len = hdr & 0x7f;
        if(hdr & 0x80) {
            // random bytes follow
            memcpy(buf, p, len);
            p += len;
        } else if(hdr == 0x7f) {
            // special: number of black lines follow
            uint8_t nl = *(p++);

            for(int i=0; i<nl; i++) {
                lcd_write_data(2 * LCD_WIDTH, (uint8_t *)blk_row);
            }

            continue;
        } else {
            // repeat same byte
            memset(buf, *p, len);
            p++;
        }

        // expand 'len' packed monochrome into BGR565 16-bit data: buf => expand
        uint16_t *out = expand;
        for(int i=0; i<len; i++) {
            uint8_t packed = buf[i];
            for(uint8_t mask = 0x80; mask; mask >>= 1, out++) {
                if(packed & mask) {
                    *out = COL_FOREGROUND;
                } else {
                    *out = COL_BLACK;
                }
            }
        }
        lcd_write_data(len*8*2, (uint8_t *)expand);
    }

    lcd_write_cmd(0x29);            // DISPON

    last_screen = pixels;
    rng_delay();
}

// oled_show_progress()
//
// Perform simple RLE decompression, and add a bar on final screen line.
//
    void
oled_show_progress(const uint8_t *pixels, int progress)
{
    oled_setup();

    if(last_screen != pixels) {
        oled_show(pixels);
    }

    uint32_t p_count = LCD_WIDTH * 10 * progress / 1000;
    if(p_count > LCD_WIDTH) p_count = LCD_WIDTH-1;
    if(p_count < 0) p_count = 0;

    // draw just the progress bar
    uint16_t row[LCD_WIDTH];
    memset2(row, COL_FOREGROUND, 2*p_count);
    memset2(&row[p_count], COL_BLACK, 2*(LCD_WIDTH-p_count));

    wait_vsync();

    for(int i=0; i<PROGRESS_BAR_H; i++) {
        lcd_write_rows(PROGRESS_BAR_Y+i, 1, row);
    }

    rng_delay();
}


// oled_factory_busy()
//
    void
oled_factory_busy(void)
{
    // not implemented: would need to talk to GPU for this
}

// EOF
