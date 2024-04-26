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
#include "barcode.h"

lcd_state_t lcd_state;

const int LCD_WIDTH = 320;
const int LCD_HEIGHT = 240;
const int NUM_PIXELS = (LCD_WIDTH*LCD_HEIGHT);

// doing RGB565, but swab16
const uint16_t COL_BLACK = 0;
const uint16_t COL_WHITE = ~0;
const uint16_t COL_RED = 0x00f8;            //SWAP16(0xf800);
const uint16_t COL_FOREGROUND = 0x60fd;     //SWAB16(0xfd60);     // brand orange

// progress bar specs
const uint16_t PROG_HEIGHT = 5;
const uint16_t PROG_Y = LCD_HEIGHT - PROG_HEIGHT;

static const int NUM_PHASES = 16;

#if 0
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
    // PA5 is TEAR input: a positive pulse every 60Hz that
    // corresponds to vertical blanking time
    uint32_t timeout = 1000000;
    for(; timeout; timeout--) {
        if(LL_GPIO_IsInputPinSet(GPIOA, PIN_TEAR)) {
            return;
        }
    }
    //puts("TEAR timeout");
}
#endif

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

// write_uint16()
//
    static inline void
write_uint16(int count, uint16_t val)
{
    uint8_t a = val & 0xff;
    uint8_t b = val >> 8;

    for(int n=0; n<count; n++) {
        while(LL_SPI_GetTxFIFOLevel(SPI1) == LL_SPI_TX_FIFO_FULL) {
            // wait for space
        }
        LL_SPI_TransmitData8(SPI1, a);

        while(LL_SPI_GetTxFIFOLevel(SPI1) == LL_SPI_TX_FIFO_FULL) {
            // wait for space
        }
        LL_SPI_TransmitData8(SPI1, b);
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

// lcd_write_constant()
//
    void
lcd_write_constant(int len, const uint16_t pixel)
{
    LL_GPIO_SetOutputPin(GPIOA, PIN_CS);
    LL_GPIO_SetOutputPin(GPIOA, PIN_DATA_CMD);
    LL_GPIO_ResetOutputPin(GPIOA, PIN_CS);

    write_uint16(len, pixel);

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

    // usually want the busy bar
    lcd_state.activity_bar = true;

#if 0
    // debug values
    lcd_state.cursor_x = 9;
    lcd_state.cursor_y = 2;
    lcd_state.outline_cursor = true;
#endif
#if 0
    lcd_state.dbl_wide = true;
    lcd_state.cursor_x = 16;
    lcd_state.cursor_y = 4;
    lcd_state.solid_cursor = true;
    //lcd_state.outline_cursor = true;
#endif
}

// take_control()
//
// Make the shared SPI bus ours. All push-pull, because we need the speed.
// - force PIN_G_CTRL low while we are in control, so CPU knows we are actively
//   speaking to the LCD
//
    static void
take_control(void)
{
    LL_GPIO_SetOutputPin(GPIOA, PIN_GPU_BUSY);

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

    LL_GPIO_ResetOutputPin(GPIOA, PIN_GPU_BUSY);
}

// send_window()
//
    static void
send_window(int x, int y, int w, int h, const void *data)
{
    // write inclusive range 
    // note, MADCTL MV/MX/MY setting causes row vs. col swap here
    lcd_write_cmd4(0x2a, x, x+w-1);        // CASET - Column address set range (x)
    lcd_write_cmd4(0x2b, y, y+h-1);        // RASET - Row address set range (y)
    lcd_write_cmd(0x2c);                   // RAMWR - memory write

    if(data) {
        // follow with data write of 2*w*h bytes
        lcd_write_data(2*w*h, (uint8_t *)data);
    }
}

// send_solid()
//
    static void
send_solid(int x, int y, int w, int h, uint16_t pixel)
{
    send_window(x, y, w, h, NULL);

    lcd_write_constant(w*h, pixel);
}

// cursor_draw()
//
    void
cursor_draw(int char_x, int char_y, uint8_t ctype, bool phase)
{
    // see shared/lcd.py and shared/font_iosevka.py
    const int LEFT_MARGIN = 7;
    const int TOP_MARGIN = 15;
    const int CHARS_W = 34;
    const int CHARS_H = 10;
    const int CELL_W = 9;
    const int CELL_H = 22;

    // no error reporting.. but dont die either
    if(char_x >= CHARS_W) return;
    if(char_y >= CHARS_H) return;

    bool dbl_wide = ctype & 0x10;
    ctype &= 0xf;

    // top left corner, just on edge of character cell
    int x = LEFT_MARGIN + (char_x * CELL_W);
    int y = TOP_MARGIN + (char_y * CELL_H);
    int cell_w = CELL_W + (dbl_wide?CELL_W:0);

    uint16_t colour = phase ? COL_BLACK : COL_FOREGROUND;

    if(ctype == CURSOR_OUTLINE) {
        // horz
        send_solid(x,y, cell_w, 1, colour);
        send_solid(x,y+CELL_H-1, cell_w, 1, colour);

        // vert
        send_solid(x, y+1, 1, CELL_H-2, colour);
        send_solid(x+cell_w-1, y+1, 1, CELL_H-2, colour);
    }

    if(ctype == CURSOR_SOLID) {
        if(!phase) {
            // solid fill -- draw first time
            send_solid(x,y, cell_w, CELL_H, COL_FOREGROUND);
        } else {
            // box shape, blank interior pixels
            send_solid(x+1,y+1, cell_w-2, CELL_H-2, COL_BLACK);
        }
    }

    if(ctype == CURSOR_MENU) {
        // half-block 
        send_solid(x,y, 4, CELL_H, colour);
    }
}

// lcd_fill_solid()
//
    void
lcd_fill_solid(uint16_t pattern)
{
    // whole screen
    send_window(0, 0, LCD_WIDTH, LCD_HEIGHT, NULL);
    lcd_write_constant(LCD_WIDTH*LCD_HEIGHT, pattern);
}

// lcd_draw_progress()
//
    void
lcd_draw_progress(void)
{
    static int phase = 0;

    uint16_t row[LCD_WIDTH + NUM_PHASES + 1];

    for(int i=0; i<numberof(row); i++) {
        row[i] = ((i % 8) < 2) ? COL_BLACK : COL_FOREGROUND;
    }

    send_window(0, PROG_Y, LCD_WIDTH, PROG_Y-LCD_HEIGHT, NULL);

    for(int y=0; y<PROG_HEIGHT; y++) {
        lcd_write_data(LCD_WIDTH*2, (uint8_t *)(&row[NUM_PHASES - phase - 1]));
    }

    phase = (phase + 1) % NUM_PHASES;
}

// lcd_animate()
//
// Called at LCD frame rate, when we have control over LCD.
//
    void
lcd_animate(void)
{
    take_control();

    if(lcd_state.test_pattern) {
        lcd_test_pattern();
        lcd_state.test_pattern = false;
    }

    if(lcd_state.activity_bar) {
        lcd_draw_progress();
    }

    if(lcd_state.cursor_type != NO_CURSOR) {
        static int cur_phase;

        if(cur_phase == 0) {
            cursor_draw(lcd_state.cursor_x, lcd_state.cursor_y,
                            lcd_state.cursor_type, lcd_state.cur_flash);

            lcd_state.cur_flash = !lcd_state.cur_flash;
        }

        cur_phase = (cur_phase+1) % 32;
    }

    release_control();
}

// lcd_test_pattern()
//
    void
lcd_test_pattern(void)
{
    // NOTE: this is very limited so it cannot be abused to show arbitrary things
    // - take packed pixels in (blk/white)
    // - draw them centered w/ red side border
    // - repeat same pattern bunch of times.
    // - used for a linear barcode in selftest process
    // - important: this cannot render a QR code, nor misleading text.
    // - LATER: let's just make fully static instead.

    STATIC_ASSERT(sizeof(test_barcode) == LCD_WIDTH/8);

    uint16_t    row[LCD_WIDTH];
    for(int i=0, x=0; i<sizeof(test_barcode); i++) {
        for(uint8_t m=0x80; m; m >>= 1) {
            row[x++] = (test_barcode[i] & m) ? COL_BLACK : COL_WHITE;
        }
    }

    const int y = 40, h = 120;
    send_window(0, y, LCD_WIDTH, h, NULL);

    for(int i=0; i<h; i++) {
        lcd_write_data(sizeof(row), (uint8_t *)&row);
    }
}

// EOF
