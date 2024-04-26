/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * main.c
 *
 * Setup code. See dispatch.c for mainline code.
 *
 */
#include "basics.h"
#include "main.h"
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "misc.h"
#include "console.h"
#include "faster_sha256.h"
#include "aes.h"
#include "version.h"
#include "clocks.h"
#include "oled.h"
#include "delay.h"
#include "rng.h"
#include "gpio.h"
#include "ae.h"
#include "se2.h"
#include "pins.h"
#include "verify.h"
#include "storage.h"
#include "psram.h"
#include "sdcard.h"
#include "dispatch.h"
#include "constant_time.h"
#include SCREENS_H
#include "stm32l4xx_hal.h"


// wipe_all_sram()
//
    void
wipe_all_sram(void)
{
    const uint32_t noise = 0xdeadbeef;

    // wipe all of SRAM (except our own memory)
    STATIC_ASSERT((SRAM3_BASE + SRAM3_SIZE) - BL_SRAM_BASE == 8192);

    memset4((void *)SRAM1_BASE, noise, SRAM1_SIZE_MAX);
    memset4((void *)SRAM2_BASE, noise, SRAM2_SIZE);
    memset4((void *)SRAM3_BASE, noise, SRAM3_SIZE - (BL_SRAM_BASE - SRAM3_BASE));
}

// system_startup()
//
// Called only on system boot.
//
    void
system_startup(void)
{
    // configure critical stuff
    system_init0();
    clocks_setup();
    rng_setup();            // needs to be super early
    rng_delay();

#if RELEASE
    // security check: should we be in protected mode? Was there some UV-C bitrot perhaps?
    if(!check_all_ones(rom_secrets->bag_number, sizeof(rom_secrets->bag_number))
            && !flash_is_security_level2()
    ) {
        // yikes. recovery: do lockdown... we should be/(thought we were) locked already
        flash_lockdown_hard(OB_RDP_LEVEL_2);
        // CONCERN: this code has only been called once, and it left the unit with RDP=0xff(1)
        // and not functional. See issue #1268.
    }
#else
# warning "Built for debug."
#endif

    // config pins
    gpio_setup();

    // debug output and banner
    console_setup();

    puts2(BOOT_BANNER);
    puts(version_string);

    uint32_t reset_reason = RCC->CSR;
    if(reset_reason & RCC_CSR_FWRSTF) {
        puts(">FIREWALLED<");
    }
    SET_BIT(RCC->CSR, RCC_CSR_RMVF);

    pin_setup0();
    rng_delay();

#ifndef RELEASE
    sha256_selftest();
    aes_selftest();
    rng_delay();
#endif

#ifdef FOR_Q1_ONLY
    extern void lcd_full_setup(void);

    // clear and setup LCD display - includes long config process
    lcd_full_setup();
#else
    // clear and OLED display
    oled_setup();
#endif

    // Workaround to get into DFU from micropython
    // LATER: none of this is useful with RDP=2, but okay in the office/factory
    if(memcmp(dfu_flag->magic, REBOOT_TO_DFU, sizeof(dfu_flag->magic)) == 0) {
        dfu_flag->magic[0] = 0;

        // still see a flash here, but that's proof it works.
        oled_show(dfu_flag->screen);

        enter_dfu();
        // NOT-REACHED
    }
    rng_delay();

    // Show main boot-up screen
    oled_show_progress(screen_verify, 0);

    // wipe all of SRAM (except our own memory, which was already wiped)
    wipe_all_sram();

    // secure elements setup
    //puts2("SE1 setup: ");
    ae_setup();
    ae_set_gpio(0);         // turn light red
    //puts("done");

    //puts2("SE2 setup: ");
    se2_setup();
    se2_probe();
    //puts("done");

    // protect our flash, and/or check it's protected 
    // - and pick pairing secret if we don't already have one
    // - may also do one-time setup of the secure elements
    // - note: ae_setup must already be called, since it can talk to that
    flash_setup();

    // setup Quad SPI unit and PSRAM chip
    psram_setup();

    // broken pairing secret w/ SE1 means we've been fast-bricked
    if(ae_pair_unlock() != 0) {
        oled_show(screen_brick);
        puts("pair-bricked");

        LOCKUP_FOREVER();
    }

    // Check firmware has valid checksum and signature.
    puts2("Verify: ");
    bool main_ok = verify_firmware();

    if(main_ok) {
        // load a blank screen, so that if the firmware crashes, we are showing
        // something reasonable and not misleading.
        oled_show(screen_blankish);

        return;
    }

    // Try to recover, using an image hanging around in PSRAM
    // .. will reboot if it works; only helps w/ reset pulses, not power downs.
    psram_recover_firmware();

    if(!flash_is_security_level2()) {
        // in factory, DFU is prefered; can't work if flash locked tho
        enter_dfu();
    }

    // use SDCard to recover
    while(1) sdcard_recovery();
}

// fatal_error(const char *msg)
//
    void __attribute__((noreturn))
fatal_error(const char *msgvoid)
{
    oled_setup();
    oled_show(screen_fatal);

#ifndef RELEASE
    puts2("\r\n\nAssert fail: ");
    puts(msgvoid);
    BREAKPOINT;
#endif

    // Maybe should do a reset after a delay, like with
    // the watchdog timer or something.
    LOCKUP_FOREVER();
}

// fatal_mitm()
//
    void __attribute__((noreturn))
fatal_mitm(void)
{
    oled_setup();
    oled_show(screen_mitm);

#ifdef RELEASE
    wipe_all_sram();
#endif

    LOCKUP_FOREVER();
}

// enter_dfu()
//
    void __attribute__((noreturn))
enter_dfu(void)
{
    puts("enter_dfu()");

    // clear the green light, if set
    ae_setup();
    ae_set_gpio(0);

    // Reset huge parts of the chip
    __HAL_RCC_APB1_FORCE_RESET();
    __HAL_RCC_APB1_RELEASE_RESET();

    __HAL_RCC_APB2_FORCE_RESET();
    __HAL_RCC_APB2_RELEASE_RESET();

    __HAL_RCC_AHB1_FORCE_RESET();
    __HAL_RCC_AHB1_RELEASE_RESET();

#if 0
    // But not this; it borks things.
    __HAL_RCC_AHB2_FORCE_RESET();
    __HAL_RCC_AHB2_RELEASE_RESET();
#endif

    __HAL_RCC_AHB3_FORCE_RESET();
    __HAL_RCC_AHB3_RELEASE_RESET();

    __HAL_FIREWALL_PREARM_ENABLE();

    // Wipe all of memory SRAM, just in case 
    // there is some way to trick us into DFU
    // after sensitive content in place.
    wipe_all_sram();

    if(flash_is_security_level2()) {
        // cannot do DFU in RDP=2, so just die. Helps to preserve screen
        LOCKUP_FOREVER();
    }

    // Reset clocks.
    HAL_RCC_DeInit();

    // move system ROM into 0x0
    __HAL_SYSCFG_REMAPMEMORY_SYSTEMFLASH();

    // need this here?!
    asm("nop; nop; nop; nop;");

    // simulate a reset vector
    __ASM volatile ("movs r0, #0\n"
                    "ldr r3, [r0, #0]\n"
                    "msr msp, r3\n"
                    "ldr r3, [r0, #4]\n"
                    "blx r3"
        : : : "r0", "r3");      // also SP

    // NOT-REACHED.
    __builtin_unreachable();
}

// EOF
