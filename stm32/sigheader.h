// (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
#pragma once
#include <stdint.h>

// Our simple firmware header.
//
// Although called a header, this data is placed into the middle of the binary.
// It is located at start of firmware + 16k - sizeof(heaer). This is a gap unused in normal
// micropython layout. Exactly the last 64 bytes (signature) should be left out of
// the checksum. We do checksum areas beyond the end of the last byte of firmware (up to length)
// and expect those regions to be unprogrammed flash (ones).
//
// - timestamp must increase with each upgrade (downgrade protection)
// - version_string is for humans only
// - pubkey_num indicates which pubkey was used for signature
// - firmware_length, must be:
//      - bigger than minimum length, less than max
//      - 512-byte aligned
//  - bootloader assumes the flash filesystem (FAT FS) follows the firmware.
//  - this C header file is somewhat parsed and used by python signature-adding code
//  - timestamp is YYMMDDHHMMSS0000 in BCD
//

typedef struct {
    uint32_t    magic_value;            // fixed magic value
    uint8_t     timestamp[8];           // for downgrade protection, this must increase
    uint8_t     version_string[8];      // zero-terminated string: "1.0.0ab7" for humans
    uint32_t    pubkey_num;             // which pubkey was used to sign binary
    uint32_t    firmware_length;        // must be 512-aligned, and marks start of flash filesystem
    uint32_t    install_flags;          // flags about this release
    uint32_t    hw_compat;              // which hardware can run this release
    uint8_t     best_ts[8];             // for downgrade protection, recommended min timestamp
    uint32_t    future[5];              // reserved words
    uint8_t     signature[64];          // signature over secp256k1
} coldcardFirmwareHeader_t;

#define FW_HEADER_SIZE       128
#define FW_HEADER_OFFSET     (0x4000-FW_HEADER_SIZE)

#define FW_HEADER_MAGIC             0xCC001234

// Firmware Image Size

// arbitrary min size
#define FW_MIN_LENGTH        (256*1024)

// (mk1-3) absolute max size: 1MB flash - 32k for bootloader = 1,015,808
// - but practical limit for our-protocol USB upgrades: 786432 (or else settings damaged)
#define FW_MAX_LENGTH        (0x100000 - 0x8000)

// .. for Mk4: 2Mbytes, less bootrom of 128k.
#define FW_MAX_LENGTH_MK4        (0x200000 - 0x20000)

// Arguments to be used w/ python's struct module.
#define FWH_PY_FORMAT      "<I8s8sIIII8s20s64s"
#define FWH_PY_VALUES      "magic_value timestamp version_string pubkey_num firmware_length install_flags hw_compat best_ts future signature"
#define FWH_NUM_FUTURE      7

// offset of pubkey number
#define FWH_PK_NUM_OFFSET   20

// Bits in install_flags
#define FWHIF_HIGH_WATER        0x01
#define FWHIF_BEST_TS           0x02

// Bits in hw_compat
#define MK_1_OK                 0x01
#define MK_2_OK                 0x02
#define MK_3_OK                 0x04
#define MK_4_OK                 0x08
#define MK_Q1_OK                0x10
// RFU:
#define MK_6_OK                 0x20

// (Mk1-3) There is a copy of the header at this location in RAM, copied by bootloader
// **after** it has been verified. If you write to this memory area, you will be reset!
// .. in mk4, no header copy anymore
#define RAM_HEADER_BASE          0x10007c20

// Original copy of header, as recorded in flash/firmware file.
#define FLASH_HEADER_BASE        0x0800bf80
#define FLASH_HEADER_BASE_MK4    0x08023f80

// (Mk1-3) One 32-bit word of flags from bootloader about how we got here (in protected RAM)
#define RAM_BOOT_FLAGS           (RAM_HEADER_BASE + FW_HEADER_SIZE)

// Bitmask for RAM_BOOT_FLAGS
// - we just did a firmware upgrade on this bootup
#define RBF_FRESH_VERSION      0x01
// - factory mode: flash not yet locked-down
#define RBF_FACTORY_MODE       0x02
