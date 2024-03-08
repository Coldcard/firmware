/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
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
#include "main.h"
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
#include "psram.h"
#include "se2.h"
#include "dispatch.h"
#include "constant_time.h"
#include SCREENS_H
#include "stm32l4xx_hal.h"


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
        
    if((x >= SRAM1_BASE) && ((x+len) <= BL_SRAM_BASE)) {
        // ok: it's inside the SRAM areas, up to where we start
        return 0;
    }

    if(!readonly) {
        return EPERM;
    }

    if((x >= FIRMWARE_START) && (x - FIRMWARE_START) < FW_MAX_LENGTH_MK4) {
        // inside flash of main firmware (happens for QSTR's)
        return 0;
    }

    return EACCES;
}

/*
    The callgate into the firewall...

    From the reference manual:
        The "call gate" is composed of 3 words located on the first three
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

    // in case the caller didn't already, but would just lead to a crash anyway
    __disable_irq();

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
                    puts("Die: DFU");
                    scr = screen_upgrading;     // was screen_dfu, but limited audience
                    break;
                case 1:
                    // in case some way for Micropython to detect it. Unused?
                    scr = screen_downgrade;
                    puts("Die: Downgrade");
                    break;
                case 2:
                    scr = screen_blankish;
                    puts("Die: Blankish");
                    break;
                case 3:
                    scr = screen_brick;
                    puts("Die: Brick");
                    secure = true;      // no point going into DFU, if even possible
                    break;
            }

            oled_setup();
            oled_show(scr);

            wipe_all_sram();
            psram_wipe();

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
#ifdef FOR_Q1_ONLY
                case 3:
                    oled_show(screen_poweroff);
                    break;
#endif
                case 1:
                    // leave screen untouched
                    break;
            }

            wipe_all_sram();
            psram_wipe();

#ifdef FOR_Q1_ONLY
            if(arg2 == 3) {
                // need some time for user to see message
                delay_ms(100);

                turn_power_off();
            }
#endif
            if(arg2 == 2) {
                // need some time for user to see message
                delay_ms(100);

                // reboot so we can "login" again
                NVIC_SystemReset();

                // NOT-REACHED (but ok if it does)
            }

            // wait for an interrupt which will never happen (ie. sleep)
            LOCKUP_FOREVER();
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
                    checksum_flash(fw_digest, world_digest, 0);

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
            // Do we have a ATECC608 and all that implies? Always
            rv = 0;
            break;

        case 12:
            // read the DFU button (used for selftest at least)
            REQUIRE_OUT(1);
            buf_io[0] = 0;          // NOT SUPPORTED on Mk4
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
                    rv = pin_long_secret(args, NULL);
                    break;

                case 7:         // new for Mk4
                    rv = pin_firmware_upgrade(args);
                    break;

                case 8:         // new for Mk4: faster for reading only tho
                    REQUIRE_OUT(PIN_ATTEMPT_SIZE_V2 + AE_LONG_SECRET_LEN);
                    rv = pin_long_secret(args, &buf_io[PIN_ATTEMPT_SIZE_V2]);
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

                case 2:
                    // read RDP=2 flag.. only in the factory will this be false
                    REQUIRE_OUT(1);
                    buf_io[0] = (flash_is_security_level2() ? 2 : 0xff);
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

        case 22: {          // Mk4+ only
            // Trick pin managment: needs pin change args, plus slot data after that!
            REQUIRE_OUT(PIN_ATTEMPT_SIZE_V2 + sizeof(trick_slot_t));
            const pinAttempt_t *args = (pinAttempt_t *)buf_io;
            trick_slot_t *slot = (trick_slot_t *)(&buf_io[PIN_ATTEMPT_SIZE_V2]);

            // Verify we know the main PIN, but don't do anything
            bool trick_mode;
            rv = pin_check_logged_in(args, &trick_mode);
            if(rv) goto fail;

            if(trick_mode) {
                // Already logged in via a trick PIN, so clear the seed to protect 
                // it (we have a smart one here) and continue.
                mcu_key_clear(NULL);
            }

            switch(arg2) {
                case 0:     // clear all
                    if(!trick_mode) {
                        se2_clear_tricks();
                    }
                    break;
                case 1:     // get by pin
                    if(trick_mode) {
                        // never finds anything
                        rv = ENOENT;
                    } else {
                        // lookup and return value
                        if(slot->pin_len > 16) {
                            rv = ERANGE;
                            goto fail;
                        }
                        if(se2_test_trick_pin(slot->pin, slot->pin_len, slot, true)) {
                            // found
                            rv = 0;
                        } else {
                            rv = ENOENT;
                        }
                    }
                    break;
                case 2:     // clear/update slot
                    if(!trick_mode) {
                        rv = se2_save_trick(slot);
                    }
                    break;

                default:
                    rv = ENOENT;
                    break;
            }

            break;
        }

        case 23:
            // fast wipe -- does system reset, no UX
            if(arg2 == 0xBeef) {
                // silent version, but does reset system
                fast_wipe();
            } else if(arg2 == 0xDead) {
                // noisy, shows screen, halts
                mcu_key_clear(NULL);
                oled_show(screen_wiped);

                LOCKUP_FOREVER();
            }
            rv = EPERM;
            break;

        case 24:
            // fast brick -- locks up w/ message
            if(arg2 == 0xDead) fast_brick();
            rv = EPERM;
            break;

        case 25: {
            // mk4: usage of mcu key slots
            REQUIRE_OUT(8);

            int *avail = (int *)(buf_io+0);
            int *consumed = (int *)(buf_io+4);
            int *total = (int *)(buf_io+8);

            mcu_key_usage(avail, consumed, total);
            break;
        }

        case 26: {
            // Read some random bytes from various sources, like SE's.
            REQUIRE_OUT(33);

            switch(arg2) {
                case 1:         // for SE1
                    // secure, any MitM will be detected
                    ae_setup();
                    ae_secure_random(&buf_io[1]);
                    buf_io[0] = 32;
                    break;

                case 2:         // for SE2
                    // secure, requires knowledge of pairing secret
                    se2_read_rng(&buf_io[1]);
                    buf_io[0] = 8;
                    break;

                default:
                    rv = ERANGE;
                    break;
            }

            break;
        }

#ifndef FOR_Q1_ONLY
        case 27:
            // Get versions/parts installed in SE1/SE2
            // - simple fact: we will be recompiling this code if/when 
            //   part revision happen!
            // - OBSOLETE: unused on Q and only versions >= 5.2.3 on Mk4
            REQUIRE_OUT(80);
            strcpy((char *)buf_io, "ATECC608B\nDS28C36B");
            break;
#endif

#if 0
        // p256r1 test code
        case 130: {      // verify signature
            REQUIRE_IN_ONLY(64+32+64);
            const uint8_t *pubkey = buf_io+0;
            const uint8_t *digest = buf_io+64;
            const uint8_t *signature = buf_io+64+32;

            bool ok = p256_verify(pubkey, digest, signature);
            if(!ok) {
                rv = EAGAIN;
            }

            break;
        }
        case 131: {      // gen keypair
            REQUIRE_OUT(32+64);
            uint8_t *privkey = buf_io+0;
            uint8_t *pubkey = buf_io+32;

            p256_gen_keypair(privkey, pubkey);

            break;
        }
        case 132: {      // sign digest
            REQUIRE_OUT(32+32+64);
            const uint8_t *privkey = buf_io+0;
            const uint8_t *digest = buf_io+32;
            uint8_t *sig = buf_io+32+32;

            p256_sign(privkey, digest, sig);

            break;
        }
        case 133: {      // ecdh multiply
            REQUIRE_OUT(64+32+32);
            const uint8_t *pubkey = buf_io+0;
            const uint8_t *privkey = buf_io+64;
            uint8_t *result = buf_io+64+32;
            
            ps256_ecdh(pubkey, privkey, result);

            break;
        }
#endif


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

    // Precaution: we don't want to leave SE1 authorized for any specific keys,
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

// EOF
