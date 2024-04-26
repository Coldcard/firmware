//
// (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// modckcc.c - module for Coldcard hardware features and glue.
// 
#include <stdio.h>
#include <string.h>

#include "modckcc.h"
#include "rng.h"
#include "usb.h"
#include "flash.h"
#include "bufhelper.h"
#include "py/gc.h"
#include "py/runtime.h"
#include "py/mphal.h"
#include "py/mpstate.h"
#include "py/stackctrl.h"
#include "boardctrl.h"
#include "softtimer.h"
#include "ulight.h"
#include "uart.h"

#include "storage.h"
#include "usb.h"
#include "extint.h"
#include "lib/utils/interrupt_char.h"       // for mp_interrupt_char

// this file needs -O0 for it to work well.
#pragma GCC push_options
#pragma GCC optimize ("O0")

// Presume genuine light is on, at start
STATIC bool presumably_green_light = true;

MP_DECLARE_CONST_FUN_OBJ_0(pyb_rng_get_obj);
MP_DECLARE_CONST_FUN_OBJ_1(pyb_rng_get_bytes_obj);

// See startup.S where this table of entry points/version numbers is defined
typedef struct {
    uint32_t        callgate_entry;
    uint32_t        version_number;
    uint32_t        reserved[4];
} bootloaderInfoTable_t;

#define BOOTLOADER_TABLE        (*((bootloaderInfoTable_t *)0x08000040))

STATIC int callgate_lower(uint32_t method_num, uint32_t arg2, mp_buffer_info_t *io_buf)
{
    uint32_t dest = BOOTLOADER_TABLE.callgate_entry;

    // +4 because that's required by call gate for firewall
    // +1 to set LSB because we know a BLX instruction will be used to
    // get there and we know its thumb code
    // - also 0x100 aligned.
    assert((dest & 0xff) == 0x05);

    ulight_off();
    mp_uint_t before = disable_irq();

    // XXX this doesn't work with compiler optimizations enabled (ie. -O0 only!!)

    // Call the gate; it will trash the normal function-call registers (r0-4)
    // but also r9 and r10. Does not use our stack.
    //
    // references: 
    // - <http://www.ethernut.de/en/documents/arm-inline-asm.html>
    // - <https://gcc.gnu.org/onlinedocs/gcc/Extended-Asm.html>
    //
    int rv = -2;
    register int r_method asm("r0") = method_num;
    register const char *tx asm("r1") = io_buf ? io_buf->buf : NULL;
    register uint32_t tx_len asm("r2") = io_buf ? io_buf->len: 0;
    register uint32_t r_arg2 asm("r3") = arg2;

    asm volatile(   "blx %[dest] \n" 
                    "str r0, %[rv]"
        : [rv] "=m" (rv)
        : [dest] "r" (dest), "r" (tx), "r" (tx_len), "r" (r_arg2), "r" (r_method)
        : "r9", "r10"
    );

    enable_irq(before);

    return rv;
}

STATIC mp_obj_t sec_oneway_gate(mp_obj_t method_obj, mp_obj_t arg2_obj)
{
    // jump to the callgate, but don't expect to come back. Good for DFU entry.

    uint32_t dest = BOOTLOADER_TABLE.callgate_entry;

    uint32_t num = mp_obj_get_int(method_obj);
    uint32_t arg2 = mp_obj_get_int(arg2_obj);

    pyb_usb_dev_deinit();
    storage_flush();
    ulight_off();

    // NOTE: this may not work with compiler optimizations enabled (ie. -O0 only!!)

    mp_uint_t before = disable_irq();

    int rv = -2;            // not really used.
    register int method_num asm("r0") = num;
    register const char *tx asm("r1") = 0;
    register uint32_t tx_len asm("r2") = 0;
    register uint32_t r_arg2 asm("r3") = arg2;

    asm volatile(   "blx %[dest] \n" 
                    "str r0, %[rv]"
        : [rv] "=m" (rv)
        : [dest] "r" (dest), "r" (tx), "r" (tx_len), "r" (r_arg2), "r" (method_num)
        : "r9", "r10"
    );

    enable_irq(before);

    // not reached, except maybe error cases
    return mp_obj_new_int(rv);
}
MP_DEFINE_CONST_FUN_OBJ_2(sec_oneway_gate_obj, sec_oneway_gate);

STATIC mp_obj_t sec_gate(mp_obj_t method_obj, mp_obj_t send_arg, mp_obj_t arg2_obj)
{

    // first and last args are simple integers
    uint32_t method_num = mp_obj_get_int(method_obj);
    uint32_t arg2 = mp_obj_get_int(arg2_obj);

    // 2nd arg: buffer to send to function, or None for NULL
    mp_buffer_info_t send_buf;
    bool is_none = false;

    if(send_arg != mp_const_none) {
        mp_get_buffer_raise(send_arg, &send_buf, MP_BUFFER_RW);
    } else {
        is_none = true;
    }

    int rv = callgate_lower(method_num, arg2, is_none ? NULL : &send_buf);

#if 0
    // bugfix: if bootloader (V1.0.1) calls systick_setup(), this will correct register
    SysTick->CTRL  = SysTick_CTRL_CLKSOURCE_Msk |
                     SysTick_CTRL_TICKINT_Msk   |
                     SysTick_CTRL_ENABLE_Msk;
#endif


    return mp_obj_new_int(rv);
}
MP_DEFINE_CONST_FUN_OBJ_3(sec_gate_obj, sec_gate);


// Since we cache state of green light, need a way for us
// to be reset, altho has no bearing on real operation of 508a.
STATIC mp_obj_t presume_green(void)
{
    presumably_green_light = true;

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_0(presume_green_obj, presume_green);


STATIC mp_obj_t is_simulator(void)
{
    return MP_OBJ_NEW_SMALL_INT(0);
}
MP_DEFINE_CONST_FUN_OBJ_0(is_simulator_obj, is_simulator);

STATIC mp_obj_t is_debug_build(void)
{
    return MP_OBJ_NEW_SMALL_INT(COLDCARD_DEBUG);
}
MP_DEFINE_CONST_FUN_OBJ_0(is_debug_build_obj, is_debug_build);

STATIC mp_obj_t get_cpu_id(void)
{
    // Are we running on a STM32L496RG6? If so, expect 0x461
    return MP_OBJ_NEW_SMALL_INT(DBGMCU->IDCODE & 0xfff);
}
MP_DEFINE_CONST_FUN_OBJ_0(get_cpu_id_obj, get_cpu_id);


STATIC mp_obj_t vcp_enabled(mp_obj_t new_val)
{
    // see vcp_lockdown.c where this is used
    extern bool ckcc_vcp_enabled;

    // Report/Control the VCP lockout. Call with None to readback.
    if(mp_obj_is_integer(new_val)) {
        ckcc_vcp_enabled = !!(mp_obj_get_int_truncated(new_val));

        mp_interrupt_char = ckcc_vcp_enabled ? 3 : -1;
    }

    return MP_OBJ_NEW_SMALL_INT(ckcc_vcp_enabled);
}
MP_DEFINE_CONST_FUN_OBJ_1(vcp_enabled_obj, vcp_enabled);


STATIC mp_obj_t stack_limit(mp_obj_t new_val)
{
    // Report or change the stack limit, in bytes. Probably less than 0x4000.
    if(mp_obj_is_integer(new_val)) {
        mp_int_t limit = mp_obj_get_int_truncated(new_val);

        // Small values will cause immediate crash due to stack-depth checking, so avoid.
        if((limit < 1024) || (limit > 64*1024)) {
            mp_raise_ValueError(NULL);
        }

        mp_stack_set_limit(limit);
    }

    return MP_OBJ_NEW_SMALL_INT(MP_STATE_THREAD(stack_limit));
}
MP_DEFINE_CONST_FUN_OBJ_1(stack_limit_obj, stack_limit);

STATIC mp_obj_t usb_active(void)
{
    // something happened at the class-driver level of USB.
    // - keep the light flashing
    ckcc_usb_active = true;

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_0(usb_active_obj, usb_active);

STATIC mp_obj_t breakpoint(void)
{
    // drop into the debugger, if connected.
    asm("BKPT #0");

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_0(breakpoint_obj, breakpoint);

STATIC mp_obj_t watchpoint(volatile mp_obj_t arg1)
{
    // just be an empty function that we can set as a breakpoint
    // in the debugger...  also gives some visiblilty into a single object

    return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_1(watchpoint_obj, watchpoint);

// See psramdisk.c
extern const mp_obj_type_t psram_type;

STATIC const mp_rom_map_elem_t ckcc_module_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__),            MP_ROM_QSTR(MP_QSTR_ckcc) },
    { MP_ROM_QSTR(MP_QSTR_rng),                 MP_ROM_PTR(&pyb_rng_get_obj) },
    { MP_ROM_QSTR(MP_QSTR_rng_bytes),           MP_ROM_PTR(&pyb_rng_get_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_gate),                MP_ROM_PTR(&sec_gate_obj) },
    { MP_ROM_QSTR(MP_QSTR_oneway),              MP_ROM_PTR(&sec_oneway_gate_obj) },
    { MP_ROM_QSTR(MP_QSTR_is_simulator),        MP_ROM_PTR(&is_simulator_obj) },
    { MP_ROM_QSTR(MP_QSTR_is_debug_build),      MP_ROM_PTR(&is_debug_build_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_cpu_id),          MP_ROM_PTR(&get_cpu_id_obj) },
    { MP_ROM_QSTR(MP_QSTR_vcp_enabled),         MP_ROM_PTR(&vcp_enabled_obj) },
    { MP_ROM_QSTR(MP_QSTR_presume_green),       MP_ROM_PTR(&presume_green_obj) },
    { MP_ROM_QSTR(MP_QSTR_breakpoint),          MP_ROM_PTR(&breakpoint_obj) },
    { MP_ROM_QSTR(MP_QSTR_watchpoint),          MP_ROM_PTR(&watchpoint_obj) },
    { MP_ROM_QSTR(MP_QSTR_stack_limit),         MP_ROM_PTR(&stack_limit_obj) },
    { MP_ROM_QSTR(MP_QSTR_usb_active),          MP_ROM_PTR(&usb_active_obj) },
    { MP_ROM_QSTR(MP_QSTR_PSRAM),               MP_ROM_PTR(&psram_type) },
};

STATIC MP_DEFINE_CONST_DICT(ckcc_module_globals, ckcc_module_globals_table);

const mp_obj_module_t ckcc_module = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t*)&ckcc_module_globals,
};

MP_REGISTER_MODULE(MP_QSTR_ckcc, ckcc_module, 1);

void ckcc_early_init(void)
{
    // Add system-wide init code here.

    // Disable ^C to interrupt code... but see mp_hal_set_interrupt_char()
    // for best disable code.
    mp_interrupt_char = -1;

    // Do the equivilent of "py.usb_mode(None)" in boot.py
    extern mp_uint_t pyb_usb_flags;
    pyb_usb_flags |= PYB_USB_FLAG_USB_MODE_CALLED;
}



void ckcc_boardctrl_before_boot_py(boardctrl_state_t *state)
{
    // do not run /boot.py even if it exists
    state->run_boot_py = false;

    // Clear PSRAM from previous cycles
    extern void psram_init(void);
    psram_init();

    // setup USB activity light
    ulight_setup();
}
void ckcc_boardctrl_after_boot_py(boardctrl_state_t *state)
{
    // nothing to do, no way to report failures anyway
}

// ckcc_heap_start()
//
    void *
ckcc_heap_start(void)
{
    // see layout.ld (linker script)
    extern uint32_t _heap_start;

    return &_heap_start;
}

// ckcc_heap_start()
//
    void *
ckcc_heap_end(void)
{
    extern uint32_t _ram_end;
    uint8_t *rv = (uint8_t *)&_ram_end;

    if((DBGMCU->IDCODE & 0xfff) == 0x461) {
        rv += 160*1024;
    }

    // Mark 1 and 2 
    return rv;
}

// There is no classical C heap in bare-metal ports, only Python
// garbage-collected heap. For completeness, emulate C heap via
// GC heap. Note that MicroPython core never uses malloc() and friends,
// but I need these for the C-language extensions I'm using.
void *malloc(size_t size)
{
    return m_malloc(size);
}

void free(void *ptr)
{
    m_free(ptr);
}

void *realloc(void *ptr, size_t size)
{
    return m_realloc(ptr, size);
}

// EOF
