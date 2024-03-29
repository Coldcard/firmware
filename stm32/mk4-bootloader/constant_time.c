/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include "constant_time.h"
#ifndef TEST_CODE
# include "rng.h"
#else
# define rng_delay()
#endif

// check_all_ones_raw()
//
// Lower-level version, needed before RNG ready.
//
	bool
check_all_ones_raw(const void *ptrV, int len)
{
	uint8_t rv = 0xff;
	const uint8_t *ptr = (const uint8_t *)ptrV;

	for(; len; len--, ptr++) {
		rv &= *ptr;
	}

	return (rv == 0xff);
}

// check_all_ones()
//
// Return T if all bytes are 0xFF
//
	bool
check_all_ones(const void *ptrV, int len)
{
	bool rv = check_all_ones_raw(ptrV, len);

    rng_delay();

	return rv;
}

// check_all_zeros()
//
// Return T if all bytes are 0x00
//
	bool
check_all_zeros(const void *ptrV, int len)
{
	uint8_t rv = 0x0;
	const uint8_t *ptr = (const uint8_t *)ptrV;

	for(; len; len--, ptr++) {
		rv |= *ptr;
	}

    rng_delay();
	return (rv == 0x00);
}

// check_equal()
//
// Equality check.
//
	bool
check_equal(const void *aV, const void *bV, int len)
{
	const uint8_t *left = (const uint8_t *)aV;
	const uint8_t *right = (const uint8_t *)bV;
    uint8_t diff = 0;
    int i;

    for (i = 0; i < len; i++) {
        diff |= (left[i] ^ right[i]);
    }

    rng_delay();
    return (diff == 0);
}

#ifdef TEST_CODE
// compile with:
//
// 	gcc -g -DTEST_CODE constant_time.c -o test && gdb ./test
//
#include <assert.h>
#include <stdio.h>

	int
main(void)
{
	const uint8_t a0[13] = { 0 };
	const uint8_t a1[3] = { 0xff, 0xff, 0xff };
	const uint8_t a2[13] = { 0, 0x1, 0 };


	assert(check_all_zeros(a0, sizeof(a0)));
	assert(check_all_ones(a1, sizeof(a1)));
	assert(!check_equal(a0, a2, sizeof(a2)));
	assert(check_equal(a0, a0, sizeof(a0)));

	const uint8_t x1[4] = {0x5a, 0x61, 0x63, 0x6b };
	const uint8_t x2[4] = {0x1f, 0x0, 0x0, 0x8 };
    const uint8_t x3[4] = { 0x86, 0xf4, 0xa3, 0x13 };
	assert(!check_equal(x1, x2, sizeof(x2)));
	assert(!check_equal(x2, x3, sizeof(x2)));
	assert(!check_equal(x3, x1, sizeof(x2)));

    puts("pass");
}

#endif
