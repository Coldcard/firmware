/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include <stdbool.h>
#include <stdint.h>

//
// Constant-time functions, useful for crypto checking.
//
// Ironically not constant-time anymore, but the delay is NOT data-dependant so same idea.
//

// Return T if all bytes are 0xff
bool check_all_ones(const void *ptrV, int len);
bool check_all_ones_raw(const void *ptrV, int len);         // excludes delay

// Return T if all bytes are 0x00
bool check_all_zeros(const void *ptrV, int len);

// Equality check.
bool check_equal(const void *aV, const void *bV, int len);

// XOR-mixin more bytes; acc = acc XOR more for each byte
void static inline xor_mixin(uint8_t *acc, const uint8_t *more, int len)
{
	for(; len; len--, more++, acc++) {
		*(acc) ^= *(more);
	}
}


