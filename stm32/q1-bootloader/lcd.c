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

// OLED pins block use of MCO for testing
#undef DISABLE_LCD
//#define DISABLE_LCD

// LCD connections: 
// - all on port A
// - all push/pull outputs
//
#define RESET_PIN       GPIO_PIN_6
#define DC_PIN          GPIO_PIN_8
#define CS_PIN          GPIO_PIN_4
#define SPI_SCK         GPIO_PIN_5
#define SPI_MOSI        GPIO_PIN_7

const int LCD_WIDTH = 320;
const int LCD_HEIGHT = 240;
const int NUM_PIXELS = (LCD_WIDTH*LCD_HEIGHT);

/*
// Bytes to send before sending the 1024 bytes of pixel data.
//
static const uint8_t before_show[] = { 
    0x21, 0x00, 0x7f,       // setup column address range (start, end): 0-127
    0x22, 0x00, 0x07        // setup page start/end address: 0 - 7
};
*/

#ifndef DISABLE_LCD
static SPI_HandleTypeDef   spi_port;
#endif

// forward refs
void lcd_show_pattern(uint32_t pattern);

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
    // div16 => gives 124ns cycle < 150ns req'd but works
    // div32 => gives 270ns, also works
    spi_port.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_32;
    spi_port.Init.FirstBit = SPI_FIRSTBIT_MSB;
    spi_port.Init.TIMode = SPI_TIMODE_DISABLED;
    spi_port.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLED;

    HAL_SPI_Init(&spi_port);
#endif
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

    // config SPI port
    lcd_spi_setup();

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
    lcd_write_data1(0x70);          // MV=MX=MY=1 => horz mode, first byte=top-left corner

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

    // finally
    lcd_write_cmd(0x21);            // INVON 
    lcd_write_cmd(0x29);            // DISPON
    delay_ms(50);

    //test
    lcd_show_pattern(~0);          //rng_sample());

    rng_delay();
}

// oled_show_raw()
//
// No decompression.
//
    void
oled_show_raw(uint32_t len, const uint8_t *pixels)
{
/*
    oled_setup();

    lcd_write_cmd_sequence(sizeof(before_show), before_show);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, DC_PIN, 1);
    HAL_GPIO_WritePin(GPIOA, CS_PIN, 0);

    write_bytes(len, pixels);

    HAL_GPIO_WritePin(GPIOA, CS_PIN, 1);
    rng_delay();
*/
}

// lcd_show_pattern()
//
    void
lcd_show_pattern(uint32_t pattern)
{
    // note, MADCTL MV/MX/MY setting causes row vs. col swap here
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, 0, LCD_HEIGHT-1);        // RASET - Row address set range (y)

    lcd_write_cmd(0x2c);            // RAMWR - memory write

    uint16_t    row[LCD_WIDTH];
    memset(row, pattern, sizeof(row));

    for(int y=0; y<LCD_HEIGHT; y++) {
        lcd_write_data(sizeof(row), (uint8_t *)&row);
    }
}

    void
lcd_write_rows(int y, int num_rows, uint16_t *pixels)
{
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, y, LCD_HEIGHT-1);        // RASET - Row address set range (y)

    lcd_write_cmd(0x2c);            // RAMWR - memory write

    lcd_write_data(num_rows * 2 * LCD_WIDTH, (uint8_t *)&pixels);
}

// oled_show()
//
// Perform simple RLE decompression.
//
    void
oled_show(const uint8_t *pixels)
{
/*
    oled_setup();

    lcd_write_cmd_sequence(sizeof(before_show), before_show);

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
    rng_delay();
*/
}

// oled_show_progress()
//
// Perform simple RLE decompression, and add a bar on final screen line.
//
    void
oled_show_progress(const uint8_t *pixels, int progress)
{
    oled_setup();

/*
    lcd_write_cmd_sequence(sizeof(before_show), before_show);

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
    rng_delay();
*/
}

#if 0
// oled_busy_bar()
//
    void
oled_busy_bar(bool en)
{
    // Render a continuous activity (not progress) bar in lower 8 lines of display
    // - using OLED itself to do the animation, so smooth and CPU free
    // - cannot preserve bottom 8 lines, since we have to destructively write there
    lcd_spi_setup();

    static const uint8_t setup[] = { 
        //0x20, 0x00,             // horz addr-ing mode (normal)
        0x21, 0x00, 0x7f,       // setup column address range (start, end): 0-127
        0x22, 7, 7,             // setup page start/end address: page 7=last 8 lines
    };
    static const uint8_t animate[] = { 
        0x2e,               // stop animations in progress
        0x26,               // scroll leftwards (stock ticker mode)
            0,              // placeholder
            7,              // start 'page' (vertical)
            7,              // scroll speed: 7=fastest, 
            7,              // end 'page'
            0, 0xff,        // placeholders
        0x2f                // start
    };
    static const uint8_t cleanup[] = { 
        0x2e,               // stop animation
        0x20, 0x00,         // horz addr-ing mode
        0x21, 0x00, 0x7f,       // setup column address range (start, end): 0-127
        0x22, 7, 7,             // setup page start/end address: page 7=last 8 lines
    };

    uint8_t data[128];

    if(!en) {
        // clear it, stop animation
        memset(data, 0, sizeof(data));
        lcd_write_cmd_sequence(sizeof(cleanup), cleanup);
        lcd_write_data(sizeof(data), data);

        return;
    }

    // some diagonal lines
    for(int x=0; x<128; x++) {
        // each byte here is a vertical column, 8 pixels tall, MSB at bottom
        switch(x % 4) {
            default:
                data[x] = 0x0;
                break;
            case 0 ... 1:
                data[x] = 0x80;
                break;
        }
    }

    lcd_write_cmd_sequence(sizeof(setup), setup);
    lcd_write_data(sizeof(data), data);
    lcd_write_cmd_sequence(sizeof(animate), animate);
}

// oled_draw_bar()
//
    void
oled_draw_bar(int percent)
{
    // Render a continuous activity (progress) bar in lower 8 lines of display
    // - cannot preserve bottom 8 lines, since we have to destructively write there
    // - requires OLED and GPIO's already setup by other code.
    lcd_spi_setup();

    static const uint8_t setup[] = { 
        0x21, 0x00, 0x7f,       // setup column address range (start, end): 0-127
        0x22, 7, 7,             // setup page start/end address: page 7=last 8 lines
    };

    uint8_t data[128];
    int cut = percent * 128 / 100;

    // each byte here is a vertical column, 8 pixels tall, MSB at bottom
    memset(data, 0x80, cut);
    memset(data+cut, 0x0, 128-cut);

    lcd_write_cmd_sequence(sizeof(setup), setup);
    lcd_write_data(sizeof(data), data);
}
#endif

// oled_factory_busy()
//
    void
oled_factory_busy(void)
{
/* XXX
    // Render a continuous activity (not progress) bar in lower 8 lines of display
    // - using OLED itself to do the animation, so smooth and CPU free
    // - cannot preserve bottom 8 lines, since we have to destructively write there
    //lcd_spi_setup();

    static const uint8_t setup[] = { 
        0x21, 0x00, 0x7f,       // setup column address range (start, end): 0-127
        0x22, 7, 7,             // setup page start/end address: page 7=last 8 lines
    };
    static const uint8_t animate[] = { 
        0x2e,               // stop animations in progress
        0x26,               // scroll leftwards (stock ticker mode)
            0,              // placeholder
            7,              // start 'page' (vertical)
            7,              // scroll speed: 7=fastest, 
            7,              // end 'page'
            0, 0xff,        // placeholders
        0x2f                // start
    };
    uint8_t data[128];

    for(int x=0; x<128; x++) {
        // each byte here is a vertical column, 8 pixels tall, MSB at bottom
        data[x] = (1<<(7 - (x%8)));
    }

    lcd_write_cmd_sequence(sizeof(setup), setup);
    lcd_write_data(sizeof(data), data);
    lcd_write_cmd_sequence(sizeof(animate), animate);
*/
}

// EOF
