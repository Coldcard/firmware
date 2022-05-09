/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include <stdint.h>

void console_setup(void);

// print stuff in hex. no NL or other jazz
void puthex2(uint8_t b);
void puthex4(uint16_t w);
void puthex8(uint32_t w);
void putdec4(uint16_t w);

// put hex onto the end of a string. output length always 2*len + nul
void strcat_hex(char *msg, const void *d, int len);

// my versions, being careful not to pull in FILE and other stdio.h parts
#undef puts
int puts(const char *msg);
#undef putchar
int putchar(int c);

// like puts() but without newline
void puts2(const char *msg);

// Print out a standard hex dump, with relative offsets
void hex_dump(const void *data, int len);


// EOF
