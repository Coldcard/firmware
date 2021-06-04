/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include "basics.h"
#include "sigheader.h"

// Where the firmware starts in flash (right after us).
#define FIRMWARE_START  (BL_FLASH_BASE + BL_FLASH_SIZE + BL_NVROM_SIZE)

// The in-flash header.
#define FW_HDR      ((coldcardFirmwareHeader_t *)(FIRMWARE_START + FW_HEADER_OFFSET))

// check we have something valid, and signed, in memory. T if okay
bool verify_firmware(void);

// read and checksum over **all** of flash memory
// - fw_length is length of firmware from it's header
// - if fw_length is nonzero, then use incoming fw_digest
void checksum_flash(uint8_t fw_digest[32], uint8_t world_digest[32], uint32_t fw_length);

// do some range/sanity checking on a signed header
bool verify_header(const coldcardFirmwareHeader_t *hdr);

// give digest over firmware, check the signature from header
// - use only with a verified header (call verify_header first)
// - return T if ok.
bool verify_signature(const coldcardFirmwareHeader_t *hdr, const uint8_t fw_check[32]);

// check if proposed version is new enough (based on OTP values)
bool check_is_downgrade(const uint8_t timestamp[8], const char *version);

// verify a firmware image that's in RAM, and provide digest needed for 608
bool verify_firmware_in_ram(const uint8_t *start, uint32_t len, uint8_t world_check[32]);

// read what the watermark is, might be all zeros
void get_min_version(uint8_t min_version[8]);

// EOF
