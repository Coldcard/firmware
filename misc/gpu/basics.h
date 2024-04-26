/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include <stdint.h>
#include <stdbool.h>

extern void fatal_error(const char *) __attribute__((noreturn));

// I don't like the ususal assert macro, so here is my replacement,
// and BTW: "assert()" is actually a macro, so it should
// always be capitalized.
//
#undef assert
#undef ASSERT

// this does have an impact, but probably doesn't matter.
#define __unlikely(x)     __builtin_expect((x),0)

#define ASSERT(x) do { if(__unlikely(!(x))) { fatal_error("assert");} } while(0)

// Use anywhere. Will just crash on production, but useful in dev.
#ifndef RELEASE
#define BREAKPOINT          asm("BKPT #0") 
#else
#define BREAKPOINT          #error
#endif

// An assertion that we will be checked at *compile* time. Useful GCC feature.
#define STATIC_ASSERT(cond)		_Static_assert(cond, #cond)

// Similarly: for those times when you want to write ASSERT(False), 
// use this instead to provide a msg and abort. Altho the msg isn't
// in the binary, it's still helpful when looking at source via debugger.
//
// CAUTION: some security checks end up here, so we want to always crash
// in those cases.
//
#define INCONSISTENT(x)     fatal_error("incon")

// Wait for an interrupt which will never happen (ie. die)
#define LOCKUP_FOREVER()    while(1) { __WFI(); }

// Like "sizeof()" but works on arrays, and returns the "numberof" elements.
//
#define numberof(x)			(sizeof(x)/sizeof((x)[0]))

// This is an old favourite with dangerous programers...
//
#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define msizeof(TYPE, MEMBER)	sizeof(((TYPE *)0)->MEMBER)

// Handy macros.
#define MIN(a,b)		(((a)<(b))?(a):(b))
#define MAX(a,b)		(((a)>(b))?(a):(b))
#define CLAMP(x,mn,mx)		(((x)>(mx))?(mx):( ((x)<(mn)) ? (mn) : (x)))
#define SGN(x)          (((x)<0)?-1:(((x)>0)?1:0))
#define ABS(x)      	(((x)<0)?-(x):(x))

