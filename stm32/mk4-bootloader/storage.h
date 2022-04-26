/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once

#include "basics.h"
#include "rng.h"
#include "secrets.h"
#include "stm32l4xx_hal.h"

// ../../external/micropython/lib/stm32lib/STM32L4xx_HAL_Driver/Inc/stm32l4xx_hal_flash.h
// has 3 values, but 8k is right one for our setup. DBANK=0
#undef FLASH_PAGE_SIZE
#define FLASH_PAGE_SIZE                    ((uint32_t)0x2000)

// but when erasing "pages" they are half as big, since only in one physical bank
#define FLASH_ERASE_SIZE                    ((uint32_t)0x1000)

// Details of the OTP area. 64-bit slots.
#define OPT_FLASH_BASE     0x1FFF7000
#define NUM_OPT_SLOTS      128

// Call at boot time. Picks pairing secret and/or verifies it.
void flash_setup(void);

// Set option-bytes region to appropriate values
void flash_lockdown_hard(uint8_t rdp_level_code);

// Save a serial number from secure element
void flash_save_ae_serial(const uint8_t serial[9]);

// Save bunch of stuff related to SE2
void flash_save_se2_data(const se2_secrets_t *se2);

// Write bag number (probably a string)
void flash_save_bag_number(const uint8_t new_number[32]);

// Are we operating in level2?
static inline bool flash_is_security_level2(void) {
    rng_delay();
    return ((FLASH->OPTR & FLASH_OPTR_RDP_Msk) == 0xCC);
}

// generial purpose flash functions
void flash_setup0(void);
void flash_lock(void);
void flash_unlock(void);
int flash_burn(uint32_t address, uint64_t val);
int flash_page_erase(uint32_t address);

// write to OTP
int record_highwater_version(const uint8_t timestamp[8]);

// related to SE2/SE1/seed key management
const mcu_key_t *mcu_key_get(bool *valid);
void mcu_key_clear(const mcu_key_t *cur);
const mcu_key_t *mcu_key_pick(void);
void mcu_key_usage(int *avail_out, int *consumed_out, int *total_out);

void fast_brick(void);
void fast_wipe(void);

// EOF
