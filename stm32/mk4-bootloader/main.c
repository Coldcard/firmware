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
#include "version.h"
#include "clocks.h"
#include "oled.h"
#include "delay.h"
#include "rng.h"
#include "gpio.h"
#include "ae.h"
#include "pins.h"
#include "verify.h"
#include "storage.h"
#include "sflash.h"
#include "psram.h"
#include "dispatch.h"
#include "constant_time.h"
#include "assets/screens.h"
#include "stm32l4xx_hal.h"

// reboot_seed_setup()
//
// We need to know when we are rebooted, so write some noise
// into SRAM and lock its value. Not secrets. One page = 1k bytes here.
//
    void
reboot_seed_setup(void)
{
#warning "re-enable sram protection"
#if 0
    extern uint8_t      reboot_seed_base[1024];      // see link-script.ld

    // lots of manual memory alloc here...
    uint8_t                     *reboot_seed = &reboot_seed_base[0];  // 32 bytes
    coldcardFirmwareHeader_t    *hdr_copy = (void *)&reboot_seed_base[32];
    uint32_t                    *boot_flags = (uint32_t *)RAM_BOOT_FLAGS;

    // can only do this once, and might be done already
    if(SYSCFG->SWPR != (1<<31)) {
        ASSERT(((uint32_t)reboot_seed) == 0x10007c00);
        ASSERT(((uint32_t)hdr_copy) == RAM_HEADER_BASE);

        // populate seed w/ noise
        memset(reboot_seed, 0x55, 1024);
        rng_buffer(reboot_seed, 32);

        // preserve a copy of the verified FW header
        memcpy(hdr_copy, FW_HDR, sizeof(coldcardFirmwareHeader_t));

        // document how we booted.
        uint32_t fl = 0;
        if(!flash_is_security_level2()) {
            fl |= RBF_FACTORY_MODE;
        }
        if(sf_completed_upgrade == SF_COMPLETED_UPGRADE) {
            fl |= RBF_FRESH_VERSION;
        }
        *boot_flags = fl;

        // lock it (top most page = 1k bytes)
        SYSCFG->SWPR = (1<<31);
    }
#endif
}

// wipe_all_sram()
//
    void
wipe_all_sram(void)
{
    const uint32_t noise = 0xdeadbeef;

    // wipe all of SRAM (except our own memory, which was already wiped)
    memset4((void *)(SRAM1_BASE+BL_SRAM_SIZE), noise, SRAM1_SIZE_MAX - BL_SRAM_SIZE);
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
    // configure clocks first
    clocks_setup();

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

    sha256_selftest();

    // workaround to get into DFU from micropython
    // LATER: none of this is useful with RDP=2, but okay in the office.
    if(memcmp(dfu_flag->magic, REBOOT_TO_DFU, sizeof(dfu_flag->magic)) == 0) {
        dfu_flag->magic[0] = 0;

        // still see a flash here, but that's proof it works.
        oled_setup();
        oled_show(dfu_flag->screen);

        enter_dfu();
        // NOT-REACHED
    }

    // clear and setup OLED display
    oled_setup();
    oled_show_progress(screen_verify, 0);

    // won't always need it, but enable RNG anyway
    rng_setup();

    puts2("RNG setup done: ");
    puthex4(rng_sample());
    putchar('\n');

    // wipe all of SRAM (except our own memory, which was already wiped)
    wipe_all_sram();

    puts("AE setup start");
    // secure element setup
    ae_setup();
    ae_set_gpio(0);         // not checking return on purpose

    puts("AE setup done");

    // protect our flash, and/or check it's protected 
    // - and pick pairing secret if we don't already have one
    // - may also do one-time setup of 508a
    // - note: ae_setup must already be called, since it can talk to that
    flash_setup();

    puts("flash setup done");

    // maybe upgrade to a firmware image found in sflash
    sf_firmware_upgrade();

    //puts("PSRAM setup");
    psram_setup();
    puts("verify");
    // SLOW part: check firmware is legit; else enter DFU
    // - may die due to downgrade attack or unsigned/badly signed image
    verify_firmware();

    // track reboots, capture firmware hdr used
    // - must be near end of boot process, ie: here.
    reboot_seed_setup();

    // load a blank screen, so that if the firmware crashes, we are showing
    // something reasonable and not misleading.
    oled_show(screen_blankish);
}

// fatal_error(const char *msg)
//
    void
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
    void
fatal_mitm(void)
{
    oled_setup();
    oled_show(screen_mitm);

#ifdef RELEASE
    wipe_all_sram();
#endif

    LOCKUP_FOREVER();
}

// dfu_by_request()
//
    void
dfu_by_request(void)
{
    if(flash_is_security_level2()) {
        // cannot get into DFU when secure
        // so do nothing
        return;
    }

    oled_show(screen_dfu);
    enter_dfu();
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
