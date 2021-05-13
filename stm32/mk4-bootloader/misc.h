/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

// no screen update
void enter_dfu(void);

// shows "send update" screen first
void dfu_by_request(void);

// memset4()
//
    static inline void
memset4(uint32_t *dest, uint32_t value, uint32_t byte_len)
{
    for(; byte_len; byte_len-=4, dest++) {
        *dest = value;
    }
}

// EOF
