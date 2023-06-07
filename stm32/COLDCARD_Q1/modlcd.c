//
// (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// modlcd.c - module for driving the Q1 LCD fastly.
// 
#include <stdio.h>
#include <string.h>

#include "py/obj.h"
#include "bufhelper.h"
#include "py/gc.h"
#include "py/runtime.h"
#include "py/mphal.h"
#include "py/mpstate.h"
#include "py/stackctrl.h"
#include "boardctrl.h"
#include "spi.h"

#include "extint.h"

#define PIN_LCD_TEAR        pin_B11
#define PIN_LCD_CS          pin_A4
#define PIN_LCD_SCLK        pin_A5
#define PIN_LCD_RESET       pin_A6
#define PIN_LCD_MOSI        pin_A7
#define PIN_LCD_DATA_CMD    pin_A8

// few key commands for this display
#define CASET   0x2a
#define RASET   0x2b
#define RAMWR   0x2c


#define SWAB16(n)     (( ((n)>>8) | ((n) << 8) )&0xffff)

static inline void write_cmd(const spi_t *spi, uint8_t cmd)
{
    // write a command byte
    mp_hal_pin_write(PIN_LCD_CS, 1);
    mp_hal_pin_write(PIN_LCD_DATA_CMD, 0);
    mp_hal_pin_write(PIN_LCD_CS, 0);

    spi_transfer(spi, 1, (const uint8_t *)&cmd, NULL, SPI_TRANSFER_TIMEOUT(1));

    mp_hal_pin_write(PIN_LCD_CS, 1);
}

static inline void write_cmd2(const spi_t *spi, uint8_t cmd, uint16_t arg1, uint16_t arg2)
{
    // Write a command byte, followed by 2 big-endian 16 bit arguments.
    uint16_t args[2] = { SWAB16(arg1), SWAB16(arg2)};

    mp_hal_pin_write(PIN_LCD_CS, 1);
    mp_hal_pin_write(PIN_LCD_DATA_CMD, 0);
    mp_hal_pin_write(PIN_LCD_CS, 0);

    //spi_transfer(spi, 1, (const uint8_t *)&cmd, NULL, SPI_TRANSFER_TIMEOUT(1));
    HAL_SPI_Transmit(spi->spi, (uint8_t *)&cmd, 1, SPI_TRANSFER_TIMEOUT(1));

    mp_hal_pin_write(PIN_LCD_DATA_CMD, 1);

    // faster to avoid DMA for little transfers, so do that
    //spi_transfer(spi, 4, (const uint8_t *)&args, NULL, SPI_TRANSFER_TIMEOUT(4));
    HAL_SPI_Transmit(spi->spi, (uint8_t *)&args, 4, SPI_TRANSFER_TIMEOUT(4));

    mp_hal_pin_write(PIN_LCD_CS, 1);
}


static void write_data(const spi_t *spi, int len, const uint8_t *data)
{
    // Send a bunch of data, like pixel data.
    mp_hal_pin_write(PIN_LCD_CS, 1);
    mp_hal_pin_write(PIN_LCD_DATA_CMD, 1);
    mp_hal_pin_write(PIN_LCD_CS, 0);

    spi_transfer(spi, len, data, NULL, SPI_TRANSFER_TIMEOUT(len));

    mp_hal_pin_write(PIN_LCD_CS, 1);
}

static void set_window(const spi_t *spi, int x, int y, int w, int h)
{
    // set active window; controls where pixel data will show up on screen
    write_cmd2(spi, CASET, x, x+w-1);
    write_cmd2(spi, RASET, y, y+h-1);
    write_cmd(spi, RAMWR);                  // RAMWR - memory write, implies data to follow
}


STATIC mp_obj_t send_packed(size_t n_args, const mp_obj_t *args)
{
    // take 4-bit packed palette-ized data, unpack and send
    // signature:   spi, x, y, w, h, pal, pixels

    const spi_t *spi = spi_from_mp_obj(args[0]);
 
    mp_int_t x = mp_obj_get_int(args[1]);
    mp_int_t y = mp_obj_get_int(args[2]);
    mp_int_t w = mp_obj_get_int(args[3]);
    mp_int_t h = mp_obj_get_int(args[4]);

    mp_buffer_info_t palette;
    mp_get_buffer_raise(args[5], &palette, MP_BUFFER_READ);
    mp_buffer_info_t pixels;
    mp_get_buffer_raise(args[6], &pixels, MP_BUFFER_READ);
 
    if(palette.len != 16*2) mp_raise_ValueError(NULL);
    const uint8_t *pal = palette.buf;

    // working buffer
    uint8_t fb[(w * h * 2) + 4];        // may write one extra bogus pixel for odd w*h cases
    const uint8_t *p = pixels.buf;
    uint8_t *o = fb;
    for(int i=0; i<pixels.len; i++, p++, o+=4) {
        uint8_t px1 = (*p >> 4) * 2;
        uint8_t px2 = (*p & 0xf) * 2;
        o[0] = pal[px1];
        o[1] = pal[px1+1];
        o[2] = pal[px2];
        o[3] = pal[px2+1];
    }

    set_window(spi, x, y, w, h);
    write_data(spi, w*h*2, (const uint8_t *)fb);

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(send_packed_obj, 7, 7, send_packed);

STATIC mp_obj_t fill_rect(size_t n_args, const mp_obj_t *args)
{
    // write the same pixel value to a region
    // signature:   spi, x, y, w, h, pixel_value
    const spi_t *spi = spi_from_mp_obj(args[0]);
 
    mp_int_t x = mp_obj_get_int(args[1]);
    mp_int_t y = mp_obj_get_int(args[2]);
    mp_int_t w = mp_obj_get_int(args[3]);
    mp_int_t h = mp_obj_get_int(args[4]);
    mp_int_t pixel = mp_obj_get_int(args[5]);

    uint16_t line[w];
    for(int i=0; i<w; i++) {
        line[i] = SWAB16(pixel);
    }

    set_window(spi, x, y, w, h);
    for(int y=0; y<h; y++) {
        write_data(spi, w*2, (const uint8_t *)line);
    }

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(fill_rect_obj, 6, 6, fill_rect);

STATIC const mp_rom_map_elem_t lcd_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),            MP_ROM_QSTR(MP_QSTR_lcd) },
    { MP_ROM_QSTR(MP_QSTR_send_packed),         MP_ROM_PTR(&send_packed_obj) },
    { MP_ROM_QSTR(MP_QSTR_fill_rect),           MP_ROM_PTR(&fill_rect_obj) },
};

STATIC MP_DEFINE_CONST_DICT(lcd_module_globals, lcd_module_globals_table);

const mp_obj_module_t lcd_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&lcd_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_lcd, lcd_module, 1);


// EOF
