/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 *
 * dispatch.c
 *
 * This code runs in an area of flash protected from viewing. It has limited entry
 * point (via a special callgate) and checks state carefully before running other stuff.
 *
 */
#include <errno.h>
#include <stdint.h>
#include <string.h>
#include "basics.h"
#include "misc.h"
#include "sha256.h"
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
#include "dispatch.h"
#include "constant_time.h"
#include "assets/screens.h"
#include "stm32l4xx_hal.h"

// This magic value indicates we should go direct into DFU on this reboot.
// Arbitrary SRAM1 location, random magic values. Also what screen to show.
static const char *REBOOT_TO_DFU = "Boot2DFU";
typedef struct {
    char            magic[8];
    const uint8_t  *screen;
} dfu_flag_t;
#define dfu_flag        ((dfu_flag_t *)0x20008000)

// reboot_seed_setup()
//
// We need to know when we are rebooted, so write some noise
// into SRAM and lock its value. Not secrets. One page = 1k bytes here.
//
    void
reboot_seed_setup(void)
{
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
}

// memset4()
//
    static inline void
memset4(uint32_t *dest, uint32_t value, uint32_t byte_len)
{
    for(; byte_len; byte_len-=4, dest++) {
        *dest = value;
    }
}

// wipe_all_sram()
//
    static void
wipe_all_sram(void)
{
    const uint32_t noise = 0xdeadbeef;

    // wipe all of SRAM (except our own memory, which was already wiped)
    memset4((void *)SRAM1_BASE, noise, SRAM1_SIZE_MAX);
    memset4((void *)SRAM2_BASE, noise, SRAM2_SIZE - BL_SRAM_SIZE);
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
#endif

    // workaround to get into DFU from micropython
    // LATER: none of this is useful with RDP=2
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

    // wipe all of SRAM (except our own memory, which was already wiped)
    wipe_all_sram();

    // config pins
    gpio_setup();
    ae_setup();
    ae_set_gpio(0);         // not checking return on purpose

    // protect our flash, and/or check it's protected 
    // - and pick pairing secret if we don't already have one
    // - may also do one-time setup of 508a
    // - note: ae_setup must already be called, since it can talk to that
    flash_setup();

    // escape into DFU
    if(dfu_button_pressed()) dfu_by_request();

    // maybe upgrade to a firmware image found in sflash
    sf_firmware_upgrade();

    // SLOW part: check firmware is legit; else enter DFU
    // - may die due to downgrade attack or unsigned/badly signed image
    verify_firmware();

    // .. for slow people, check again; last chance
    if(dfu_button_pressed()) dfu_by_request();

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
    const uint32_t noise = 0xDeadBeef;

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
    memset4((void *)SRAM1_BASE, noise, SRAM1_SIZE_MAX);
    memset4((void *)SRAM2_BASE, noise, SRAM2_SIZE - 1024);      // avoid seed area

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

// good_addr()
//
    static int
good_addr(const uint8_t *b, int minlen, int len, bool readonly)
{
    uint32_t x = (uint32_t)b;

    if(minlen) {
        if(!b) return EFAULT;               // gave no buffer
        if(len < minlen) return ERANGE;     // too small
    }
        

    if((x >= SRAM1_BASE) && ((x-SRAM1_BASE) < SRAM1_SIZE_MAX)) {
        // inside SRAM1, okay
        return 0;
    }

    if(!readonly) {
        return EPERM;
    }

    if((x >= FIRMWARE_START) && (x - FIRMWARE_START) < FW_MAX_LENGTH) {
        // inside flash of main firmware (happens for QSTR's)
        return 0;
    }

    return EACCES;
}

/*
    The callgate into the firewall...

    From the reference manual:
        The “call gate” is composed of 3 words located on the first three
        32-bit addresses of the base address of the code segment and of the
        Volatile data segment if it is declared as not shared (VDS = 0) and
        executable (VDE = 1).

        – 1st word: Dummy 32-bit words always closed in order to protect
          the “call gate” opening from an access due to a prefetch buffer.

        – 2nd and 3rd words: 2 specific 32-bit words called “call gate” and always opened.

    We are assuming the caller gives us a working C runtime: stack, arguments in
    registers and so on.
*/

// firewall_dispatch()
//
// A C-runtime compatible env. is running, so do some work.
//
    __attribute__ ((used))
    int
firewall_dispatch(int method_num, uint8_t *buf_io, int len_in,
                        uint32_t arg2, uint32_t incoming_sp, uint32_t incoming_lr)
{

    // from linker, offset of firewall entry
    extern uint32_t firewall_starts;

    int rv = 0;

#if 0
    // TODO: re-enable this; causing crash now.
    // in case the caller didn't already, but would just lead to a crash anyway
    __disable_irq();
#endif

    // "1=any code executed outside the protected segment will close the Firewall"
    // "0=.. will reset the processor"
    __HAL_FIREWALL_PREARM_DISABLE();

    // Important:
    // - range check pointers so we aren't tricked into revealing our secrets
    // - check buf_io points to main SRAM, and not into us!
    // - range check len_in tightly
    // - calling convention only gives me enough for 4 args to this function, so 
    //   using read/write in place.
    // - use arg2 use when a simple number is needed; never a pointer!
    // - mpy may provide a pointer to flash if we give it a qstr or small value, and if
    //   we're reading only, that's fine.

    if(len_in > 1024) {     // arbitrary max, increase as needed
        rv = ERANGE;
        goto fail;
    }

    // Use these macros
#define REQUIRE_IN_ONLY(x)   if((rv = good_addr(buf_io, (x), len_in, true))) { goto fail; }
#define REQUIRE_OUT(x)       if((rv = good_addr(buf_io, (x), len_in, false))) { goto fail; }

    switch(method_num) {
        case 0: {
            REQUIRE_OUT(64);

            // Return my version string
            memset(buf_io, 0, len_in);
            strlcpy((char *)buf_io, version_string, len_in);

            rv = strlen(version_string);

            break;
        }

        case 1: {
            // Perform SHA256 over ourselves, with 32-bits of salt, to imply we 
            // haven't stored valid responses.
            REQUIRE_OUT(32);

            SHA256_CTX  ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (void *)&arg2, 4);
            sha256_update(&ctx, (void *)BL_FLASH_BASE, BL_FLASH_SIZE);
            sha256_final(&ctx, buf_io);

            break;
        }

        case 2: {
            const uint8_t   *scr;
            bool secure = flash_is_security_level2();

            // Go into DFU mode. It's a one-way trip.
            // Also used to show some "fatal" screens w/ memory wipe.

            switch(arg2) {
                default:
                case 0:
                    // enter DFU for firmware upgrades
                    if(secure) {
                        // we cannot support DFU in secure mode anymore
                        rv = EPERM;
                        goto fail;
                    }
                    scr = screen_dfu;
                    break;
                case 1:
                    // in case some way for Micropython to detect it.
                    scr = screen_downgrade;
                    break;
                case 2:
                    scr = screen_blankish;
                    break;
                case 3:
                    scr = screen_brick;
                    secure = true;      // no point going into DFU, if even possible
                    break;
            }

            oled_setup();
            oled_show(scr);

            wipe_all_sram();

            if(secure) {
                // just die with that message shown; can't start DFU
                LOCKUP_FOREVER();
            } else {
                // Cannot just call enter_dfu() because it doesn't work well
                // once Micropython has configured so much stuff in the chip.

                // Leave a reminder to ourselves
                memcpy(dfu_flag->magic, REBOOT_TO_DFU, sizeof(dfu_flag->magic));
                dfu_flag->screen = scr;

                // reset system
                NVIC_SystemReset();

                // NOT-REACHED
            }
            break;
        }

        case 3:
            // logout: wipe all of memory and lock up. Must powercycle to recover.
            switch(arg2) { 
                case 0:
                case 2:
                    oled_show(screen_logout);
                    break;
                case 1:
                    // leave screen untouched
                    break;
            }

            wipe_all_sram();

            if(arg2 == 2) {
                // need some time to show OLED contents
                delay_ms(100);

                // reboot so we can "login" again
                NVIC_SystemReset();

                // NOT-REACHED (but ok if it does)
            }

            // wait for an interrupt which will never happen (ie. sleep)
            LOCKUP_FOREVER()
            break;

        case 4:
            // attempt to control the GPIO (won't work for 1)
            ae_setup();
            ae_keep_alive();
            switch(arg2) {
                default:
                case 0:     // read state
                    rv = ae_get_gpio();
                    break;
                case 1:     // clear it (can work anytime)
                    rv = ae_set_gpio(0);
                    break;
                case 2:     // set it (will always fail)
                    rv = ae_set_gpio(1);
                    break;

                case 3: {     // do a verify and see if it maybe goes green
                    uint8_t fw_digest[32], world_digest[32];

                    // takes time, shows progress bar
                    checksum_flash(fw_digest, world_digest);

                    rv = ae_set_gpio_secure(world_digest);

                    oled_show(screen_blankish);
                    break;
                }
            }
            break;

        case 5:     
            // Are we a brick?
            // if the pairing secret doesn't work anymore, that
            // means we've been bricked.
            // TODO: also report hardware issue, and non-configured states
            ae_setup();
            rv = (ae_pair_unlock() != 0);
            break;

        case 6:
            // Do we have a ATECC608a and all that implies?
            // NOTE: this number was unused in V1 bootroms, so return ENOENT
            #if FOR_608
                rv = 0;
            #else
                rv = ENOENT;
            #endif
            break;

        case 12:
            // read the DFU button (used for selftest at least)
            REQUIRE_OUT(1);
            gpio_setup();
            buf_io[0] = dfu_button_pressed();
            break;

        case 15: {
            // Read a dataslot directly. Will fail on 
            // encrypted slots.
            if(len_in != 4 && len_in != 32 && len_in != 72) {
                rv = ERANGE;
            } else {
                REQUIRE_OUT(4);

                ae_setup();
                if(ae_read_data_slot(arg2 & 0xf, buf_io, len_in)) {
                    rv = EIO;
                }
            }
            
            break;
        }

        case 16: {
            // Provide the 2 words for anti-phishing.
            REQUIRE_OUT(MAX_PIN_LEN);

            // arg2: length of pin.
            if((arg2 < 1) || (arg2 > MAX_PIN_LEN)) {
                rv = ERANGE;
            } else {
                if(pin_prefix_words((char *)buf_io, arg2, (uint32_t *)buf_io)) {
                    rv = EIO;
                }
            }
            break;
        }

        case 17:
            // test rng
            REQUIRE_OUT(32);
            memset(buf_io, 0x55, 32);       // to help show errors
            rng_buffer(buf_io, 32);
            break;

        case 18: {
            // Try login w/ PIN.
            REQUIRE_OUT(PIN_ATTEMPT_SIZE_V2);
            pinAttempt_t *args = (pinAttempt_t *)buf_io;

            switch(arg2) {
                case 0:
                    rv = pin_setup_attempt(args);
                    break;
                case 1:
                    rv = pin_delay(args);
                    break;
                case 2:
                    rv = pin_login_attempt(args);
                    break;
                case 3:
                    rv = pin_change(args);
                    break;
                case 4:
                    rv = pin_fetch_secret(args);
                    break;

                case 5:
                    rv = pin_firmware_greenlight(args);
                    break;

                case 6:         // new for v2
                    rv = pin_long_secret(args);
                    break;

                default:
                    rv = ENOENT;
                    break;
            }

            break;
        }


        case 19: {   // bag number stuff
            switch(arg2) {
                case 0:
                    // read out number
                    REQUIRE_OUT(32);
                    memcpy(buf_io, rom_secrets->bag_number, 32);
                    break;

                case 1:
                    // set the bag number, and (should) do lock down
                    REQUIRE_IN_ONLY(32);

                    flash_save_bag_number(buf_io);
                    break;

                case 100:
                    flash_lockdown_hard(OB_RDP_LEVEL_0);        // wipes contents of flash (1->0)
                    break;
                case 101:
                    flash_lockdown_hard(OB_RDP_LEVEL_1);        // Can only do 0->1 (experiments)
                    break;
                case 102:
                    // production units will be:
                    flash_lockdown_hard(OB_RDP_LEVEL_2);        // No change possible after this.
                    break;

                default:
                    rv = ENOENT;
                    break;
            }
            break;
        }
            
        case 20:
            // Read out entire config dataspace
            REQUIRE_OUT(128);

            ae_setup();
            rv = ae_config_read(buf_io);
            if(rv) {
                rv = EIO;
            } 
            break;

        case 21:
            // read OTP / downgrade protection
            switch(arg2) {
                case 0:
                    REQUIRE_OUT(8);
                    get_min_version(buf_io);
                    break;

                case 1:
                    REQUIRE_IN_ONLY(8);
                    rv = check_is_downgrade(buf_io, NULL);
                    break;

                case 2:
                    REQUIRE_IN_ONLY(8);

                    if(buf_io[0] < 0x10 || buf_io[0] >= 0x40) {
                        // bad data
                        rv = ERANGE;
                    } if(check_is_downgrade(buf_io, NULL)) {
                        // already at a higher version?
                        rv = EAGAIN;
                    } else {
                        uint8_t min[8];
                        get_min_version(min);

                        if(memcmp(min, buf_io, 8) == 0) {
                            // dupe
                            rv = EAGAIN;
                        } else {
                            // save it, but might be "full" already
                            if(record_highwater_version(buf_io)) {
                                rv = ENOMEM;
                            }
                        }
                    }
                    break;

                case 3:
                    // read raw counter0 value (max is 0x1fffff)
                    REQUIRE_OUT(4);
                    ae_setup();
                    rv = ae_get_counter((uint32_t *)buf_io, 0) ? EIO: 0;
                    break;

                default:
                    rv = ENOENT;
                    break;
            }
            break;

        case -1:
            // System startup code. Cannot be reached by any code (that hopes to run
            // again) except our reset stub.
            if(incoming_lr <= BL_FLASH_BASE || incoming_lr >= (uint32_t)&firewall_starts) {
                fatal_error("LR");
            } else {
                system_startup();
            }            
            break;


        default:
            rv = ENOENT;
            break;
    }
#undef REQUIRE_IN_ONLY
#undef REQUIRE_OUT

fail:

    // Precaution: we don't want to leave ATECC508A authorized for any specific keys,
    // perhaps due to an error path we didn't see. Always reset the chip.
    ae_reset_chip();

    // Unlikely it matters, but clear flash memory cache.
    __HAL_FLASH_DATA_CACHE_DISABLE();
    __HAL_FLASH_DATA_CACHE_RESET();
    __HAL_FLASH_DATA_CACHE_ENABLE();

    // .. and instruction memory (flash cache too?)
    __HAL_FLASH_INSTRUCTION_CACHE_DISABLE();
    __HAL_FLASH_INSTRUCTION_CACHE_RESET();
    __HAL_FLASH_INSTRUCTION_CACHE_ENABLE();
    

    // authorize return from firewall into user's code
    __HAL_FIREWALL_PREARM_ENABLE();

    return rv;
}

// HAL support garbage
const uint8_t  AHBPrescTable[16] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 6, 7, 8, 9};
const uint8_t  APBPrescTable[8] =  {0, 0, 0, 0, 1, 2, 3, 4};
const uint32_t MSIRangeTable[12] = {100000, 200000, 400000, 800000, 1000000, 2000000, \
                                  4000000, 8000000, 16000000, 24000000, 32000000, 48000000};
uint32_t SystemCoreClock;

// TODO: cleanup HAL stuff to not use this
uint32_t HAL_GetTick(void) { return 53; }

// EOF
