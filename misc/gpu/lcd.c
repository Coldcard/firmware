/*
 * (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 * 
 * Control the LCD.
 *
 * - see <external/stm32c0xx_hal_driver/Inc/stm32c0xx_ll_spi.h> for the API of the SPI
 * 
 */
#include "main.h"
#include "lcd.h"
#include <string.h>
#include "stm32c0xx_hal_gpio_ex.h"

const int LCD_WIDTH = 320;
const int LCD_HEIGHT = 240;
const int NUM_PIXELS = (LCD_WIDTH*LCD_HEIGHT);

// doing RGB565, but swab16
const uint16_t COL_BLACK = 0;
const uint16_t COL_WHITE = ~0;
const uint16_t COL_FOREGROUND = 0x60fd;     //SWAB16(0xfd60);     // orange

// progress bar specs
const uint16_t PROG_HEIGHT = 3;
const uint16_t PROG_Y = LCD_HEIGHT - PROG_HEIGHT;

static const int NUM_PHASES = 16;
static int phase = 0;

// forward refs
void lcd_write_rows(int y, int num_rows, uint16_t *pixels);

// memset2()
//
    static inline void
memset2(uint16_t *dest, uint16_t value, uint16_t byte_len)
{
    for(; byte_len; byte_len-=2, dest++) {
        *dest = value;
    }
}

static inline void wait_vsync(void) {
    // PB11 is TEAR input: a positive pulse every 60Hz that
    // corresponds to vertical blanking time
    uint32_t timeout = 1000000;
    for(; timeout; timeout--) {
        if(LL_GPIO_IsInputPinSet(GPIOA, PIN_TEAR)) {
            return;
        }
    }
    //puts("TEAR timeout");
}

// write_byte()
//
    static inline void
write_byte(uint8_t b)
{
    while(LL_SPI_GetTxFIFOLevel(SPI1) == LL_SPI_TX_FIFO_FULL) {
        // wait for space
    }

    LL_SPI_TransmitData8(SPI1, b);

    while(LL_SPI_GetTxFIFOLevel(SPI1) != LL_SPI_TX_FIFO_EMPTY) {
        // wait for FIFO to drain completely
    }
}

// write_bytes()
//
    static inline void
write_bytes(int len, const uint8_t *buf)
{
    for(int n=0; n<len; n++, buf++) {
        while(LL_SPI_GetTxFIFOLevel(SPI1) == LL_SPI_TX_FIFO_FULL) {
            // wait for space
        }

        LL_SPI_TransmitData8(SPI1, *buf);
    }

    while(LL_SPI_GetTxFIFOLevel(SPI1) != LL_SPI_TX_FIFO_EMPTY) {
        // wait for FIFO to drain completely
    }
}

// lcd_write_cmd()
//
    static void
lcd_write_cmd(uint8_t cmd)
{
    LL_GPIO_SetOutputPin(GPIOA, PIN_CS);
    LL_GPIO_ResetOutputPin(GPIOA, PIN_DATA_CMD);
    LL_GPIO_ResetOutputPin(GPIOA, PIN_CS);

    write_byte(cmd);

    LL_GPIO_SetOutputPin(GPIOA, PIN_CS);
    LL_GPIO_SetOutputPin(GPIOA, PIN_DATA_CMD);
}


// lcd_write_data()
//
    void
lcd_write_data(int len, const uint8_t *pixels)
{
    LL_GPIO_SetOutputPin(GPIOA, PIN_CS);
    LL_GPIO_SetOutputPin(GPIOA, PIN_DATA_CMD);
    LL_GPIO_ResetOutputPin(GPIOA, PIN_CS);

    write_bytes(len, pixels);

    LL_GPIO_SetOutputPin(GPIOA, PIN_CS);
}

// lcd_write_cmd4()
//
    static void
lcd_write_cmd4(uint8_t cmd, uint16_t a, uint16_t b)
{
    uint8_t d[4] = { (a>>8), a&0xff, (b>>8), b&0xff };

    lcd_write_cmd(cmd);
    lcd_write_data(4, d);
}

#if 0
// lcd_write_data1()
//
    static void
lcd_write_data1(uint8_t data)
{
    lcd_write_data(1, &data);
}
#endif

// lcd_spi_setup()
//
// Just setup SPI, do not reset display, etc.
//
    void
lcd_setup(void)
{
    LL_SPI_InitTypeDef init = { 0 };

    // see SPI_InitTypeDef
    init.TransferDirection = LL_SPI_HALF_DUPLEX_TX;
    init.Mode = LL_SPI_MODE_MASTER;
    init.DataWidth = LL_SPI_DATAWIDTH_8BIT;
    init.ClockPolarity = LL_SPI_POLARITY_LOW;
    init.ClockPhase = LL_SPI_PHASE_1EDGE;
    init.NSS = LL_SPI_NSS_SOFT;
    init.BaudRate = LL_SPI_BAUDRATEPRESCALER_DIV2;          // measured: 6 Mhz
    init.BitOrder = LL_SPI_MSB_FIRST;
    init.CRCCalculation = LL_SPI_CRCCALCULATION_DISABLE;

    LL_SPI_Init(SPI1, &init);
    LL_SPI_Enable(SPI1);

    phase = 0;
}

// take_control()
//
// Make the shared SPI bus ours. All push-pull, because we need the speed.
//
    static void
take_control(void)
{
    LL_GPIO_InitTypeDef init = {0};

    init.Pin =  SPI_PINS;
    init.Mode = LL_GPIO_MODE_ALTERNATE;
    init.Speed = LL_GPIO_SPEED_FREQ_VERY_HIGH;
    init.Pull = LL_GPIO_PULL_NO;
    init.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
    init.Alternate = GPIO_AF0_SPI1;

    LL_GPIO_Init(GPIOA, &init);

    init.Pin =  SPI_CTRL_PINS;
    init.Mode = LL_GPIO_MODE_OUTPUT;
    init.Speed = LL_GPIO_SPEED_FREQ_VERY_HIGH;
    init.Pull = LL_GPIO_PULL_NO;
    init.OutputType = LL_GPIO_OUTPUT_PUSHPULL;
    init.Alternate = 0;

    LL_GPIO_Init(GPIOA, &init);
}

// release_control()
//
// Go back to being a listener only on SPI.
//
    static void
release_control(void)
{
    // make all inputs again
    LL_GPIO_InitTypeDef init = {0};

    init.Pin =  SPI_PINS | SPI_CTRL_PINS;
    init.Mode = LL_GPIO_MODE_INPUT;
    init.Speed = LL_GPIO_SPEED_FREQ_LOW;
    init.Pull = LL_GPIO_PULL_NO;

    LL_GPIO_Init(GPIOA, &init);
}

// lcd_show_raw()
//
// No decompression. Just used for factory show. 1k bytes
//
    void
lcd_show_raw(uint32_t len, const uint8_t *pixels)
{
    // 1024 / 2 = 512 / 320 = 1.6 => just one row!
    lcd_write_rows(LCD_HEIGHT-3, 1, (uint16_t *)pixels);
    lcd_write_rows(LCD_HEIGHT-2, 1, (uint16_t *)pixels);
}

// lcd_fill_solid()
//
    void
lcd_fill_solid(uint16_t pattern)
{
    // note, MADCTL MV/MX/MY setting causes row vs. col swap here
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, 0, LCD_HEIGHT-1);        // RASET - Row address set range (y)
    lcd_write_cmd(0x2c);                          // RAMWR - memory write

    uint16_t    row[LCD_WIDTH];
    memset2(row, pattern, sizeof(row));

    for(int y=0; y<LCD_HEIGHT; y++) {
        lcd_write_data(sizeof(row), (uint8_t *)&row);
    }
}

// lcd_draw_progress()
//
    void
lcd_draw_progress(void)
{
    uint16_t    row[LCD_WIDTH + NUM_PHASES + 1];

    for(int i=0; i<numberof(row); i++) {
        row[i] = ((i % 8) < 2) ? COL_BLACK : COL_FOREGROUND;
    }

    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);           // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, PROG_Y, LCD_HEIGHT-1);     // RASET - Row address set range (y)
    lcd_write_cmd(0x2c);                            // RAMWR - memory write

    for(int y=0; y<PROG_HEIGHT; y++) {
        lcd_write_data(LCD_WIDTH*2, (uint8_t *)(&row[phase]));
    }
}

// lcd_write_rows()
//
    void
lcd_write_rows(int y, int num_rows, uint16_t *pixels)
{
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, y, LCD_HEIGHT-1);        // RASET - Row address set range (y) [wrong, works]

    lcd_write_cmd(0x2c);            // RAMWR - memory write

    lcd_write_data(num_rows * 2 * LCD_WIDTH, (uint8_t *)pixels);
}

// lcd_show()
//
// Perform simple RLE decompression, and pixel expansion.
//
    void
lcd_show(const uint8_t *pixels)
{
    lcd_setup();

    // we are NOT fast enough to send entire screen during the
    // vblanking time, so either we show torn stuff, or we flash display off a little
    wait_vsync();
    lcd_write_cmd(0x28);            // DISPOFF

    // always full update
    lcd_write_cmd4(0x2a, 0, LCD_WIDTH-1);         // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, 0, LCD_HEIGHT-1);        // RASET - Row address set range (y)

    uint8_t         buf[127];
    uint16_t        expand[sizeof(buf)*8];
    const uint8_t *p = pixels;

    lcd_write_cmd(0x2c);            // RAMWR - memory write

    while(1) {
        uint8_t hdr = *(p++);
        if(!hdr) break;         // end marker

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

        // expand 'len' packed monochrom into BGR565 16-bit data: buf => expand
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
}

// lcd_show_progress()
//
// Perform simple RLE decompression, and add a bar on final screen line.
//
    void
lcd_show_progress(const uint8_t *pixels, int progress)
{
    //if(pixels == screen_verify) return;         // XXX disable screen

#if 0
    lcd_setup();

    if(last_screen != pixels) {
        lcd_show(pixels);
    }

    uint32_t p_count = LCD_WIDTH * 10 * progress / 1000;
    if(p_count > LCD_WIDTH) p_count = LCD_WIDTH-1;
    if(p_count < 0) p_count = 0;

    // draw just the progress bar
    uint16_t row[LCD_WIDTH];
    memset2(row, COL_FOREGROUND, 2*p_count);
    memset2(&row[p_count], COL_BLACK, 2*(LCD_WIDTH-p_count));

    wait_vsync();

    lcd_write_rows(PROGRESS_BAR_Y+0, 1, row);
    lcd_write_rows(PROGRESS_BAR_Y+1, 1, row);
    lcd_write_rows(PROGRESS_BAR_Y+2, 1, row);
#endif
}

#if 0
// lcd_busy_bar()
//
    void
lcd_busy_bar(bool en)
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

// lcd_draw_bar()
//
    void
lcd_draw_bar(int percent)
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

// lcd_factory_busy()
//
    void
lcd_factory_busy(void)
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

// lcd_animate()
//
    void
lcd_animate(void)
{
    take_control();

    lcd_draw_progress();

    phase = (phase + 1) % NUM_PHASES;

    release_control();
}

// EOF
