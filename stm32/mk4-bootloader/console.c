/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * console.c -- simple debug on uart stuff
 *
 */
#include "basics.h"
#include "stm32l4xx_hal.h"
#include <string.h>

#undef putchar

// mk4 has USART1 on header pins: RGT = Rx Gnd Tx
#define MY_UART        USART1

// (ms) timeout for tx (disable code)
#define TX_TIMEOUT      HAL_MAX_DELAY

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
    HAL_USART_Transmit(&con, (uint8_t *)msg, strlen(msg), TX_TIMEOUT);
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
        HAL_USART_Transmit(&con, &cb, 1, TX_TIMEOUT);
    } else {
        HAL_USART_Transmit(&con, (uint8_t *)CRLF, 2, TX_TIMEOUT);
    }

    return c;
}

    int
puts(const char *msg)
{
    HAL_USART_Transmit(&con, (uint8_t *)msg, strlen(msg), TX_TIMEOUT);
    HAL_USART_Transmit(&con, (uint8_t *)CRLF, 2, TX_TIMEOUT);

    return 1;
}

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

// EOF
