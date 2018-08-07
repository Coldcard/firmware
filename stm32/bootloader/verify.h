/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#pragma once
#include "basics.h"
#include "sigheader.h"

// Where the firmware starts in flash (right after us).
#define FIRMWARE_START  (BL_FLASH_BASE + BL_FLASH_SIZE + BL_NVROM_SIZE)

// The in-flash header.
#define FW_HDR      ((coldcardFirmwareHeader_t *)(FIRMWARE_START + FW_HEADER_OFFSET))

// check we have something valid, and signed, in memory
extern void verify_firmware(void);

// read and checksum over **all** of flash memory
void checksum_flash(uint8_t fw_digest[32], uint8_t world_digest[32]);

// do some range/sanity checking on a signed header
bool verify_header(const coldcardFirmwareHeader_t *hdr);

// give digest over firmware, check the signature from header
// - use only with a verified header (call verify_header first)
// - return T if ok.
bool verify_signature(const coldcardFirmwareHeader_t *hdr, const uint8_t fw_check[32]);

// check if proposed version is new enough (based on OTP values)
bool check_is_downgrade(const uint8_t timestamp[8]);

// read what the watermark is, might be all zeros
void get_min_version(uint8_t min_version[8]);

// EOF
