/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * main.c
 *
 * Setup code and mainline.
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
#include "assets/screens.h"
#include "stm32l4xx_hal.h"

// reboot_seed_setup()
//
// We need to know when we are rebooted, so write some noise
// into SRAM and lock its value. Not secrets. One page = 1k bytes here.
//
// PROBLEM: 4S5 memory map puts SRAM2 in the middle of useful things, and
// so protecting one page of it would be unworkable. Firewall doesn't
// work due to an errata, so can't protect SRAM1 with that.
//
    static inline void
reboot_seed_setup(void)
{
    extern uint8_t      reboot_seed_base[1024];      // see link-script.ld

    // lots of manual memory alloc here...
    uint8_t            *reboot_seed = &reboot_seed_base[0];  // 32 bytes

    // populate seed w/ some noise
    ASSERT(((uint32_t)reboot_seed) == 0x20001c00);
    rng_buffer(reboot_seed, 32);

    ASSERT((uint32_t)&shared_bootflags == RAM_BOOT_FLAGS_MK4);

    // clear
    shared_bootflags = 0;

    // this value can also be checked at runtime, but historical
    if(!flash_is_security_level2()) {
        shared_bootflags |= RBF_FACTORY_MODE;
    }
}

// wipe_all_sram()
//
    void
wipe_all_sram(void)
{
    const uint32_t noise = 0xdeadbeef;

    // wipe all of SRAM (except our own memory)
    const uint32_t s1start = SRAM1_BASE + BL_SRAM_SIZE + 0x400;
    memset4((void *)s1start, noise, SRAM1_BASE  + SRAM1_SIZE_MAX - s1start);
    memset4((void *)SRAM2_BASE, noise, SRAM2_SIZE);
    memset4((void *)SRAM3_BASE, noise, SRAM3_SIZE);
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
    }
#else
# warning "Built for debug."
#endif

    // config pins
    gpio_setup();

    // debug output and banner
    console_setup();

    puts2("\r\n\nMk4 Bootloader: ");
    puts(version_string);

    // setup some limited shared data space between mpy and ourselves
    reboot_seed_setup();
    rng_delay();

#ifndef RELEASE
    sha256_selftest();
    aes_selftest();
#endif
    rng_delay();

    // Workaround to get into DFU from micropython
    // LATER: none of this is useful with RDP=2, but okay in the office.
    if(memcmp(dfu_flag->magic, REBOOT_TO_DFU, sizeof(dfu_flag->magic)) == 0) {
        dfu_flag->magic[0] = 0;

        // still see a flash here, but that's proof it works.
        oled_setup();
        oled_show(dfu_flag->screen);

        enter_dfu();
        // NOT-REACHED
    }
    rng_delay();

    // clear and setup OLED display
    oled_setup();
    oled_show_progress(screen_verify, 0);

    // wipe all of SRAM (except our own memory, which was already wiped)
    wipe_all_sram();

    puts2("SE1 setup: ");

    // secure elements setup
    ae_setup();
    ae_set_gpio(0);         // turn light red

    puts("done");

    puts2("SE2 setup: ");
    se2_setup();
    se2_probe();
    puts("done");


#if 0
    {   uint8_t config[128] = {0};
        int x = ae_config_read(config);
        if(x == 0) {
            puts("config[128]:");
            hex_dump(config, 128);
        } else {
            puts("config read fail");
        }
    }
#endif

    // protect our flash, and/or check it's protected 
    // - and pick pairing secret if we don't already have one
    // - may also do one-time setup of 508a
    // - note: ae_setup must already be called, since it can talk to that
    flash_setup();
    //puts("Flash: setup done");

    //puts("PSRAM setup");
    psram_setup();

//ae_dump_pubkey();
se2_testcode();
//BREAKPOINT;

    // Check firmware is legit; else enter DFU
    // - may die due to downgrade attack or badly signed image
    puts2("Verify: ");
    bool main_ok = verify_firmware();

    if(main_ok) {
        // load a blank screen, so that if the firmware crashes, we are showing
        // something reasonable and not misleading.
        oled_show(screen_blankish);

        return;
    }


    // try to recover, from an image hanging around in PSRAM
    // .. will reboot if it works; only helps w/ reset pulses, not power downs.
    psram_recover_firmware();

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

    // simulate a reset vector
    __ASM volatile ("movs r0, #0\n"
                    "ldr r3, [r0, #0]\n"
                    "msr msp, r3\n"
                    "ldr r3, [r0, #4]\n"
                    "blx r3"
        : : : "r0", "r3", "sp");

    // NOT-REACHED.
    __builtin_unreachable();
}

// EOF
