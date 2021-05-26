/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * verify.c -- Check signatures on firmware images in flash.
 *
 */
#include "basics.h"
#include "verify.h"
#include "faster_sha256.h"
#include "assets/screens.h"
#include "oled.h"
#include "console.h"
#include "misc.h"
#include "ae.h"
#include "rng.h"
#include "gpio.h"
#include "delay.h"
#include "storage.h"
#include <string.h>
#include "micro-ecc/uECC.h"
#include "firmware-keys.h"

// 2 megabyte on mk4
#define MAIN_FLASH_SIZE          (2<<20)

// actual qty of bytes we check
// - minus 64 because the firmware signature is skipped
// - 0x400 of OTP area
// - plus (0x28) twice for option bytes
// - plus complete "system meory" area (boot rom with DFU)
// - 12 bytes of device serial number
#define TOTAL_CHECKSUM_LEN      (MAIN_FLASH_SIZE - 64 + 0x400 + (0x28 *2) + 0x7000 + 12)


// checksum_more()
//
    static void
checksum_more(SHA256_CTX *ctx, uint32_t *total, const uint8_t *addr, int len)
{
    // mk4 has hardware hash engine, and no DFU button
    int percent = ((*total) * 100) / TOTAL_CHECKSUM_LEN;

#if 0
    puts2("Verify %0x");
    puthex2(percent);
    putchar('\n');
#endif

    oled_show_progress(screen_verify, percent);

    sha256_update(ctx, addr, len);
    *total += len;
}


// checksum_flash()
//
    void
checksum_flash(uint8_t fw_digest[32], uint8_t world_digest[32])
{
    const uint8_t *start = (const uint8_t *)FIRMWARE_START;

    rng_delay();

    SHA256_CTX  ctx;
    uint32_t    total_len = 0;
    uint8_t first[32];

    sha256_init(&ctx);

    // start of firmware (just after we end) to header
    checksum_more(&ctx, &total_len, start, FW_HEADER_OFFSET + FW_HEADER_SIZE - 64);

    // from after header to end
    checksum_more(&ctx, &total_len, start + FW_HEADER_OFFSET + FW_HEADER_SIZE, 
                            FW_HDR->firmware_length - (FW_HEADER_OFFSET + FW_HEADER_SIZE));

    sha256_final(&ctx, first);

    // double SHA256
    sha256_single(first, sizeof(first), fw_digest);

    // start over, and get the rest of flash. All of it.
    sha256_init(&ctx);

    // .. and chain in what we have so far
    sha256_update(&ctx, fw_digest, 32);

    // bootloader, including pairing secret area.
    const uint8_t *base = (const uint8_t *)BL_FLASH_BASE;
    checksum_more(&ctx, &total_len, base, start-base);

    // probably-blank area after firmware, and filesystem area
    const uint8_t *fs = start + FW_HDR->firmware_length;
    const uint8_t *last = base + MAIN_FLASH_SIZE;
    checksum_more(&ctx, &total_len, fs, last-fs);

    rng_delay();

    // OTP area
    checksum_more(&ctx, &total_len, (void *)0x1fff7000, 0x400);

    // "just in case" ... the option bytes (2 banks)
    checksum_more(&ctx, &total_len, (void *)0x1fff7800, 0x28);
    checksum_more(&ctx, &total_len, (void *)0x1ffff800, 0x28);

    // System ROM (they say it can't change, but clearly
    // implemented as flash cells)
    checksum_more(&ctx, &total_len, (void *)0x1fff0000, 0x7000);

    // device serial number, just for kicks
    checksum_more(&ctx, &total_len, (void *)0x1fff7590, 12);

    ASSERT(total_len == TOTAL_CHECKSUM_LEN);
    
    sha256_final(&ctx, world_digest);

    // double SHA256 (a bitcoin fetish)
    sha256_single(world_digest, 32, world_digest);

    rng_delay();
}

// get_min_version()
//
// Scan the OTP area and determine what the current min-version (timestamp)
// we can allow. All zeros if any if okay.
//
    void
get_min_version(uint8_t min_version[8])
{
    const uint8_t *otp = (const uint8_t *)OPT_FLASH_BASE;

    rng_delay();
    memset(min_version, 0, 8);

    for(int i=0; i<NUM_OPT_SLOTS; i++, otp+=8) {
        // is it programmed?
        if(otp[0] == 0xff) continue;

        // is it a timestamp value?
        if(otp[0] >= 0x40) continue;
        if(otp[0] < 0x10) continue;

        if(memcmp(otp, min_version, 8) > 0) {
            memcpy(min_version, otp, 8);
        }
    }
}

// check_is_downgrade()
//
    bool
check_is_downgrade(const uint8_t timestamp[8], const char *version)
{
    if(version) {
        int major = (version[1] == '.') ? (version[0]-'0') : 10;
        if(major < 3) {
            // we require major version 3.0.0 or later (for mark3 hardware)
            return true;
        }
    }

    // look at FW_HDR->timestamp and compare to a growing list in main flash OTP
    uint8_t min[8];
    get_min_version(min);

    return (memcmp(timestamp, min, 8) < 0);
}

// check_factory_key()
//
    void
check_factory_key(uint32_t pubkey_num)
{
    if(IS_FACTORY_KEY(pubkey_num)) return;

    // warn the victim/altcoin user/developer
#if RELEASE
    const int wait = 100;
#else
    const int wait = 1;
#endif
    
    for(int i=0; i < wait; i++) {
        oled_show_progress(screen_devmode, (i*100)/wait);

        delay_ms(250);
    }
}

// verify_header()
//
    bool
verify_header(const coldcardFirmwareHeader_t *hdr)
{
    rng_delay();

    if(hdr->magic_value != FW_HEADER_MAGIC) goto fail;
    if(hdr->version_string[0] == 0x0) goto fail;
    if(hdr->timestamp[0] >= 0x40) goto fail;        // 22 yr product lifetime
    if(hdr->firmware_length < FW_MIN_LENGTH) goto fail;
    if(hdr->firmware_length > FW_MAX_LENGTH) goto fail;
    if(hdr->pubkey_num >= NUM_KNOWN_PUBKEYS) goto fail;

    return true;
fail:
    return false;
}

// verify_signature()
//
// Given double-sha256 over the firmware bytes, check the signature.
//
    bool
verify_signature(const coldcardFirmwareHeader_t *hdr, const uint8_t fw_check[32])
{
    // this takes a few ms at least, not fast.
    int ok = uECC_verify(approved_pubkeys[hdr->pubkey_num], fw_check, 32,
                                    hdr->signature, uECC_secp256k1());

    //puts(ok ? "Sig ok" : "Sig fail");

    return ok;
}

// verify_firmware()
//
    void
verify_firmware(void)
{
    STATIC_ASSERT(sizeof(coldcardFirmwareHeader_t) == FW_HEADER_SIZE);

    rng_delay();

    // watch for unprogrammed header. and some 
    if(FW_HDR->version_string[0] == 0xff) goto blank;
    if(!verify_header(FW_HDR)) goto fail;

    rng_delay();

    // measure checksum
    uint8_t fw_check[32], world_check[32];
    checksum_flash(fw_check, world_check);

    rng_delay();

    // Verify the signature
    // - use pubkey_num to pick a specific key
    if(!verify_signature(FW_HDR, fw_check)) goto fail;

    rng_delay();
 
    // Push the hash to the SE which might make the Genuine light green,
    // but only if we arrived at same hash before. It decides.
    int not_green = ae_set_gpio_secure(world_check);

    rng_delay();

#if 0
    // XXX change this, no more dev key
    // maybe show big warning if not an "approved" key
    if(not_green) {
        check_factory_key(FW_HDR->pubkey_num);
    }
#endif

    puts("good firmware");
    oled_show_progress(screen_verify, 100);

    return;

fail:
    puts("corrupt firmware");
    oled_show(screen_corrupt);
    enter_dfu();
    return;

blank:
    puts("no firmware");
    oled_show(screen_dfu);
    enter_dfu();
    return;
}

// EOF
