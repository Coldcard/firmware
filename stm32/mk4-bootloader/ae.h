/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
//
// Atmel ATECC508A and 608A related code. Trying to keep this able to handle both devices.
//

//#define FOR_508     1
#define FOR_608     1

// Opcodes from table 9-4, page 51
//
typedef enum {
	OP_CheckMac = 0x28, OP_Counter = 0x24, OP_DeriveKey = 0x1C, OP_ECDH = 0x43,
	OP_GenDig = 0x15, OP_GenKey = 0x40, OP_Info = 0x30,
	OP_Lock = 0x17, OP_MAC = 0x08, OP_Nonce = 0x16,
	OP_PrivWrite = 0x46, OP_Random = 0x1B, OP_Read = 0x02, OP_Sign = 0x41,
	OP_SHA = 0x47, OP_UpdateExtra = 0x20, OP_Verify = 0x45, OP_Write = 0x12,
#if FOR_508
    OP_HMAC = 0x11,
    OP_Pause = 0x01,
#elif FOR_608
    OP_AES = 0x51,
    OP_KDF = 0x56,
    OP_SecureBoot = 0x80,
    OP_SelftTest = 0x77,
#endif
} aeopcode_t;

// Status/Error Codes that occur in 4-byte groups. See page 50, table 9-3.
#define AE_COMMAND_OK			0x00
#define AE_CHECKMAC_FAIL		0x01
#define AE_PARSE_ERROR			0x03
#define AE_ECC_FAULT			0x05
#define AE_SELFTEST_ERROR		0x07
#define AE_EXEC_ERROR			0x0f
#define AE_AFTER_WAKE			0x11
#define AE_WATCHDOG_EXPIRE		0xEE
#define AE_COMM_ERROR			0xFF

// Basic pin/uart setup
void ae_setup(void);

// Call this lots! It's quick and clears volatile state on device.
void ae_reset_chip(void);

// Test if chip responds correctly, and do some setup; returns error string if fail.
const char *ae_probe(void);

// Use the chip as SHA256 "accelerator"
int ae_sha256(const uint8_t *msg, int msg_len, uint8_t digest[32]);

// Read a one-byte response (ie. status code, see below)
int ae_read1(void);

// Read and check CRC over N bytes, wrapped in 3-bytes of framing overhead.
// Fails with non-zero if unable to read after 3 tries. Not clever about variable length.
int ae_read_n(uint8_t len, uint8_t *buf);

// Write and lock a "slot". length must be 32, regardless of actual slot size
int ae_write_data_slot(int slot_num, const uint8_t *data, int len, bool lock_it);

// Read first 32 bytes out of a slot. len must be 4 or 32.
int ae_read_data_slot(int slot_num, uint8_t *data, int len);

// Read and write to slots that are encrypted (must know that before using)
// - can specific different lenghts
int ae_encrypted_read(int data_slot, int read_kn, const uint8_t read_key[32], uint8_t *data, int len);
int ae_encrypted_write(int data_slot, int write_kn, const uint8_t write_key[32], const uint8_t *data, int len);

// read/write exactly 32 bytes
int ae_encrypted_read32(int data_slot, int blk, int read_kn,
                    const uint8_t read_key[32], uint8_t data[32]);
int ae_encrypted_write32(int data_slot, int blk, int write_kn,
                    const uint8_t write_key[32], const uint8_t data[32]);

// Use the pairing secret to validate ourselves to AE chip.
int ae_pair_unlock(void);

// Do a CheckMac operation. Caution: don't rely on return value, it can be faked.
int ae_checkmac(uint8_t keynum, const uint8_t secret[32]);

// Verify the chip and I know the same value for a keynum. Cannot be faked by MitM.
int ae_checkmac_hard(uint8_t keynum, const uint8_t secret[32]);

// Send a one-byte command, maybe with args.
void ae_send(aeopcode_t opcode, uint8_t p1, uint16_t p2);
// .. same but with body data as well.
void ae_send_n(aeopcode_t opcode, uint8_t p1, uint16_t p2, const uint8_t *data, uint8_t data_len);

// Return the waiting time (max) for specific opcode.
int ae_delay_time(aeopcode_t opcode);

// Refresh the chip's watchdog timer.
void ae_keep_alive(void);

// Pick a fresh random number.
int ae_random(uint8_t randout[32]);

// Roll (derive) a key using random number we forget. One way!
int ae_destroy_key(int keynum);

// Ask the chip to make a digest of a counter's value or data slot's contents.
int ae_gendig_counter(int counter_num, const uint32_t expected_value, uint8_t digest[32]);
int ae_gendig_slot(int slot_num, const uint8_t slot_contents[32], uint8_t digest[32]);

// Verify the chip has arrived at the same digest we have.
bool ae_is_correct_tempkey(const uint8_t expected_tempkey[32]);

// Do Info(p1=2) command, and return result; p1=3 if get_gpio
uint16_t ae_get_info(void);

// Bits in Info(p1=2) response
#define I_TempKey_KeyId(n)		((n >> 8) & 0x0f)
#define I_TempKey_SourceFlag(n)	((n >> 12) & 0x1)
#define I_TempKey_GenDigData(n)	((n >> 13) & 0x1)
#define I_TempKey_GenKeyData(n)	((n >> 14) & 0x1)
#define I_TempKey_NoMacFlag(n)	((n >> 15) & 0x1)

#define I_EEPROM_RNG(n)			((n >> 0) & 0x1)
#define I_SRAM_RNG(n)			((n >> 1) & 0x1)
#define I_AuthValid(n)			((n >> 2) & 0x1)
#define I_AuthKey(n)			((n >> 3) & 0x0f)
#define I_TempKey_Valid(n)		((n >> 7) & 0x1)

// Do a dance that unlocks various keys. Return T if it fails.
int ae_unlock_ip(uint8_t keynum, const uint8_t secret[32]);

// Load Tempkey with a Nonce value that we both know, but
// is random and we both know is random too!
int ae_pick_nonce(const uint8_t num_in[20], uint8_t tempkey[32]);

// Read a one-way counter (there are 2 of these)
int ae_get_counter(uint32_t *result, uint8_t counter_number);

// Add onto a counter. Slow; has to go by one.
int ae_add_counter(uint32_t *result, uint8_t counter_number, int incr);

// Perform HMAC on the chip, using a particular key.
//int ae_hmac(uint8_t keynum, const uint8_t *msg, uint16_t msg_len, uint8_t digest[32]);
int ae_hmac32(uint8_t keynum, const uint8_t *msg, uint8_t digest[32]);

// Read config area (not confidential)
int ae_config_read(uint8_t config[128]);

// Load TempKey with indicated value, exactly.
int ae_load_nonce(const uint8_t nonce[32]);

// Return the serial number.
// Nine bytes of serial number. First 2 bytes always 0x0123 and last one 0xEE
int ae_get_serial(uint8_t serial[6]);

// Control the LED. Might require authenticaiton first.
int ae_set_gpio(int state);

// Set the GPIO using secure hash generated somehow already.
int ae_set_gpio_secure(uint8_t digest[32]);

// Return current state of GPIO pin
uint8_t ae_get_gpio(void);

// One-time config and lockdown of the chip. Never call unless you just
// picked the original pairing secret.
int ae_setup_config(void);

// Read a byte from config area, or -1 if fail.
int ae_read_config_byte(int offset);

// Read a 4-byte area from config area, or -1 if fail.
int ae_read_config_word(int offset, uint8_t *dest);

// Call this if possible mitm is detected.
extern void fatal_mitm(void) __attribute__((noreturn));

#if FOR_608
// Update the match-counter with a new number.
int ae_write_match_count(uint32_t count, const uint8_t *write_key);

// Perform many key iterations and read out the result. Designed to be slow.
int ae_stretch_iter(const uint8_t start[32], uint8_t end[32], int iterations);

// Mix in (via HMAC) the contents of a specific key on the device.
int ae_mixin_key(uint8_t keynum, const uint8_t start[32], uint8_t end[32]);

#endif

// EOF
