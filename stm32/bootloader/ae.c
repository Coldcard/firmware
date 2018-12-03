/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#include "basics.h"
#include "ae.h"
#include "rng.h"
#include "delay.h"
#include "sha256.h"
#include "constant_time.h"
#include "gpio.h"
#include "storage.h"
#include "stm32l4xx_hal.h"
#include "ae_config.h"
#include <errno.h>
#include <string.h>

// Selectable debug level; keep them as comments regardless
#if 0
# define ERR(msg)            BREAKPOINT;
# define ERRV(val, msg)       BREAKPOINT;
#else
# define ERR(msg)
# define ERRV(val, msg)
#endif

// Must be exactly 32 chars:
static const char *copyright_msg = "Copyright 2018- by Coinkite Inc.";     

// "one wire" is on PA0 aka. UART4
#define MY_UART         UART4

// keep this in place.
#define RET_IF_BAD(rv)		do { if(rv) return rv; } while(0)

#define AE_CHIP_IS_SETUP        0x35d25d63
static uint32_t ae_chip_is_setup;

// Forward refs...
static void crc16_chain(uint8_t length, const uint8_t *data, uint8_t crc[2]);
static void ae_delay(aeopcode_t opcode);
static void ae_wake(void);

static struct {
    int crc_error;
    int len_error;
    int crc_len_error;
    int short_error;
    int l1_retry;
    int ln_retry;
    int extra_bits;
    aeopcode_t last_op;
    uint8_t last_resp1, last_p1;
    uint16_t last_p2;
} stats;

// Bit patterns to be sent
#define BIT0    0x7d
#define BIT1    0x7f

// These control the direction of the single wire bus
typedef enum {
    IOFLAG_CMD      = 0x77,
    IOFLAG_TX       = 0x88,
    IOFLAG_IDLE     = 0xBB,
    IOFLAG_SLEEP    = 0xCC,
} ioflag_t;

// _send_byte()
//
    static inline void
_send_byte(uint8_t ch)
{
    // reset timeout timer (Systick)
    uint32_t    ticks = 0;
    SysTick->VAL = 0;

    while(!(MY_UART->ISR & UART_FLAG_TXE)) {
        // busy-wait until able to send (no fifo?)
        if(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) {
            // failsafe timeout
            ticks += 1;
            if(ticks > 10) break;
        }
    }
    MY_UART->TDR = ch;
}

// _send_bits()
//
    static void
_send_bits(uint8_t tx)
{
    // serialize and send one byte
    uint8_t     mask = 0x1;

    for(int i=0; i<8; i++, mask <<= 1) {
        uint8_t h = (tx & mask) ? BIT1 : BIT0;

        _send_byte(h);
    }
}

// _send_serialized()
//
    static void
_send_serialized(const uint8_t *buf, int len)
{
    for(int i=0; i<len; i++) {
        _send_bits(buf[i]);
    }
}

// _read_byte()
//
// Return -1 in case of timeout, else one byte.
//
    static inline int
_read_byte(void)
{
    uint32_t    ticks = 0;

    // reset timeout timer (Systick)
    SysTick->VAL = 0;

    while(!(MY_UART->ISR & UART_FLAG_RXNE) && !(MY_UART->ISR & UART_FLAG_RTOF)) {
        // busy-waiting

        if(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) {
            ticks += 1;
            if(ticks >= 5) {
                // a full Xms has been wasted; give up.

                // NOTE: this is a failsafe long timeout, not reached in
                // practise because the bit-time timeout from UART (RTOF)
                return -1;
            }
        }
    }

    if(MY_UART->ISR & UART_FLAG_RXNE) {
        return MY_UART->RDR & 0x7f;
    }
    if(MY_UART->ISR & UART_FLAG_RTOF) {
        // "fast" timeout reached, clear flag
        MY_UART->ICR = USART_ICR_RTOCF;
        return -1;
    }
    INCONSISTENT("rxf");
    return -1;
}

// deserialize()
//
// Return a deserialized byte, or -1 for timeout.
//
    static void
deserialize(const uint8_t *from, int from_len, uint8_t *into, int max_into)
{
    while(from_len > 0) {
        uint8_t rv = 0, mask = 0x1;

        for(int i=0; i<8; i++, mask <<= 1) {
            if(from[i] == BIT1) {
                rv |= mask;
            }
        }

        *(into++) = rv;
        from += 8;
        from_len -= 8;

        max_into --;
        if(max_into <= 0) break;
    }
}

// _flush_rx()
//
    static inline void
_flush_rx(void)
{
    // reset timeout timer (Systick)
    SysTick->VAL = 0;

    while(!(MY_UART->ISR & UART_FLAG_TC)) {
        // wait for last bit(byte) to be serialized and sent

        if(SysTick->CTRL & SysTick_CTRL_COUNTFLAG_Msk) {
            // full 1ms has passed -- timeout.
            break;
        }
    }

    // We actualy need this delay here!
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();
    __NOP();

    // clear junk in rx buffer
    MY_UART->RQR = USART_RQR_RXFRQ;

    // clear overrun error
    // clear rx timeout flag
    // clear framing error
    MY_UART->ICR = USART_ICR_ORECF | USART_ICR_RTOCF | USART_ICR_FECF;
}

// ae_read_response()
//
// Read upto N bytes of response. Suspress echo of 0x88 and
// return actual number of (deserialized) bytes received.
// We ignore extra bytes not expected, and always read until a timeout.
// Cmds to chip can be up to 155 bytes, but not clear what max len for responses.
//
    static int
ae_read_response(uint8_t *buf, int max_len)
{
    int max_expect = (max_len+1) * 8;
    uint8_t raw[max_expect];

    // tell chip to write stuff to bus
    _send_bits(IOFLAG_TX);

    // kill first byte which we expect to be IOFLAG_TX echo (0x88)
    _flush_rx();

    // It takes between 64 and 131us (tTURNAROUND) for the chip to recover
    // and start sending bits to us. We're blocked on reading
    // them anyway, so no need to delay. Also a danger of overruns here.

    int actual = 0;
    for(uint8_t *p = raw; ; actual++) {
        int ch = _read_byte();
        if(ch < 0) {
            break;
        }

        if(actual < max_expect) {
            *(p++) = ch;
        }
    }

    // Sometimes our framing is not perfect.
    // We might get a spurious bit at the leading edge (perhaps an echo
    // of part of the 0x88??) or junk at the end.
    actual &= ~7;
    deserialize(raw, actual, buf, max_len);

    return actual / 8;
}

// ae_send_sleep()
//
	static void
ae_send_sleep(void)
{
	// "The ATECC508A goes into the low power sleep mode and ignores all
	// subsequent I/O transitions until the next wake flag. The entire volatile
	// state of the device is reset"
    ae_wake();

    _send_bits(IOFLAG_SLEEP);
}

// ae_send_idle()
//
	static void
ae_send_idle(void)
{
	// "The ATECC508A goes into the idle mode and ignores all subsequent
	// I/O transitions until the next wake flag. The contents of TempKey
	// and RNG Seed registers are retained."

    ae_wake();

    _send_bits(IOFLAG_IDLE);
}

// ae_wake()
//
    static void
ae_wake(void)
{
    // send zero (all low), delay 2.5ms
    _send_byte(0x00);

    delay_us(2500);

    _flush_rx();
}

// ae_reset_chip()
//
    void
ae_reset_chip(void)
{
    if(ae_chip_is_setup == AE_CHIP_IS_SETUP) {
        // "The ATECC508A goes into the low power sleep mode and ignores all
        // subsequent I/O transitions until the next wake flag. The entire volatile
        // state of the device is reset"
        _send_bits(IOFLAG_SLEEP);
    } else {
        // we may not have a working UART, and we probably didn't
        // talk to the chip, so skip it.
    }
}


// ae_setup()
//
// Configure pins. Do not attempt to talk to chip.
//
    void
ae_setup(void)
{
#if 0
    self.ow = UART(4, baudrate=230400, bits=7, parity=None, stop=1,
                            timeout=1, read_buf_len=(80*8))

    # correct pin settings, because we have external pullup
    self.pa0 = Pin('A0', mode=Pin.ALT, pull=Pin.PULL_NONE, af=Pin.AF8_UART4)

	// setup UART4: 7N1, 230400 bps.
        .BaudRate = 230400,
        .WordLength = UART_WORDLENGTH_7B,
        .StopBits = UART_STOPBITS_1,
        .Parity = UART_PARITY_NONE,
        .Mode = UART_MODE_TX_RX,
#endif

    memset(&stats, 0, sizeof(stats));

    // enable clock to that part of chip
    __HAL_RCC_UART4_CLK_ENABLE();

    // copy config values from a running system, setup by mpy code
    // - except disable all interrupts
    // - mpy code will have to clean this up, see ...reinit() member func
    //
    // For max clock error insensitivity:
    // OVER8==0, ONEBIT=1

    // disable UART so some other bits can be set (only while disabled)
    MY_UART->CR1 = 0;
    MY_UART->CR1 = 0x1000002d & ~(0
                                    | USART_CR1_PEIE 
                                    | USART_CR1_TXEIE 
                                    | USART_CR1_TCIE 
                                    | USART_CR1_RXNEIE
                                    | USART_CR1_IDLEIE
                                    | USART_CR1_OVER8
                                    | USART_CR1_UE);

    MY_UART->RTOR = 24;                  // timeout in bit periods: 3 chars or so
    MY_UART->CR2 = USART_CR2_RTOEN;      // rx timeout enable
    MY_UART->CR3 = USART_CR3_HDSEL | USART_CR3_ONEBIT;
    MY_UART->BRR = 0x0000015b;          // 230400 bps 

    // clear rx timeout flag
    MY_UART->ICR = USART_ICR_RTOCF;

    // finally enable UART
    MY_UART->CR1 |= USART_CR1_UE;
    
    // configure pin A0 to be AF8_UART4, PULL_NONE
    gpio_setup();
    
    // mark it as ready
    ae_chip_is_setup = AE_CHIP_IS_SETUP;
}

// ae_probe()
//
	const char *
ae_probe(void)
{

    // Make it sleep / wake it up.
	ae_send_sleep();

    // Wake it again (to reset state)
    ae_wake();

	// do a real read w/ CRC
	// with no command happening, expect 0x11: "After Wake, prior to first command"
    ae_read1();

	uint8_t chk = ae_read1();
	if(chk != AE_AFTER_WAKE) return "wk fl";

#if 0
    if(is_personalized()) {
        // attempt pairing?
        if(ae_pair_unlock()) return "pair";
    } else {
        // test the chip works?
    }
#endif

    // read the serial number one time
    uint8_t serial[6];
	if(ae_get_serial(serial)) return "no ser";

	// put into a low-power mode, might be a bit before we come back
	ae_send_sleep();

	return NULL;
}


// ae_keep_alive()
//
	void
ae_keep_alive(void)
{
	// To reset the watchdog, (1) put it into idle mode, then (2) wake it.
	ae_send_idle();

    // not clear if delay needed here?
	ae_wake();
}

// Originally from Libraries/ecc108_library/ecc108_helper.c

/** This function calculates CRC.
 *
 * crc_register is initialized with *crc, so it can be chained to
 * calculate CRC from large array of data.
 *
 * For the first calculation or calculation without chaining, crc[0]
 * and crc[1] values must be initialized to 0 by the caller.
 *  
 * \param[in] length number of bytes in buffer
 * \param[in] data pointer to data for which CRC should be calculated
 * \param[out] crc pointer to 16-bit CRC
 */ 
	static void
crc16_chain(uint8_t length, const uint8_t *data, uint8_t crc[2])
{
    uint8_t counter;
    uint16_t crc_register = 0;
    uint16_t polynom = 0x8005;
    uint8_t shift_register;
    uint8_t data_bit, crc_bit;
    
    crc_register = (((uint16_t) crc[0]) & 0x00FF) | (((uint16_t) crc[1]) << 8);
    
    for (counter = 0; counter < length; counter++) {
      for (shift_register = 0x01; shift_register > 0x00; shift_register <<= 1) {
         data_bit = (data[counter] & shift_register) ? 1 : 0;
         crc_bit = crc_register >> 15;

         // Shift CRC to the left by 1.
         crc_register <<= 1; 

         if ((data_bit ^ crc_bit) != 0)
            crc_register ^= polynom;
      }  
    }
        
    crc[0] = (uint8_t) (crc_register & 0x00FF);
    crc[1] = (uint8_t) (crc_register >> 8);
}   

// ae_check_crc()
//
	static bool
ae_check_crc(const uint8_t *data, uint8_t length)
{
	uint8_t obs[2] = { 0, 0 };

	if(data[0] != length) {
		// length is wrong
        stats.crc_len_error++;
		return false;
	}

	crc16_chain(length-2, data, obs);

	return (obs[0] == data[length-2] && obs[1] == data[length-1]);
}

// ae_read1()
//
// Read a one-byte status/error code response from chip. It's wrapped as 4 bytes: 
//	(len=4) (value) (crc16) (crc16)
//
	int
ae_read1(void)
{
	uint8_t msg[4];

	for(int retry=3; retry >= 0; retry--) {
        ae_wake();

        // tell it we want to read a response, read it, and deserialize
        int rv = ae_read_response(msg, 4);

        if(rv != 4) {
            ERR("rx len");
            stats.len_error++;
            goto try_again;
        }

		// Check length and CRC bytes. we will retry a few times
		// if they are wrong.
		if(!ae_check_crc(msg, 4)) {
			ERR("bad crc");
            stats.crc_error++;
			goto try_again;
		}

        stats.last_resp1 = msg[1];

		// done, and it worked; return the one byte.
		return msg[1];

	try_again:
        stats.l1_retry++;
		ae_wake();
	}

	// fail.
	return -1;
}

// ae_read_n()
//
// Read and check CRC over N bytes, wrapped in 3-bytes of framing overhead.
//
	int
ae_read_n(uint8_t len, uint8_t *body)
{
    uint8_t tmp[1+len+2];

	for(int retry=3; retry >= 0; retry--) {

        int actual = ae_read_response(tmp, len+3);
        if(actual < 4) {
            ERR("too short");
            stats.short_error++;
            goto try_again;
        }

        uint8_t resp_len = tmp[0];
		if(resp_len != (len + 3)) {
            stats.len_error++;
            if(resp_len == 4) {
				// Probably an unexpected error. But no way to return a short read, so
				// just print out debug info.
                ERRV(msg[1], "ae errcode");
                stats.last_resp1 = tmp[1];

                return -1;
            }
			ERRV(msg[0], "wr len");		 // wrong length
			goto try_again;
		}

		if(!ae_check_crc(tmp, actual)) {
			ERR("bad crc");
            stats.crc_error++;
			goto try_again;
		}

		// normal case: copy out body of message w/o framing
        memcpy(body, tmp+1, actual-3);
		return 0;

	try_again:
        stats.ln_retry++;
		ae_wake();
	}

	return -1;
}

// ae_send()
//
	int
ae_send(aeopcode_t opcode, uint8_t p1, uint16_t p2) 
{
	return ae_send_n(opcode, p1, p2, NULL, 0);
}

// ae_send_n()
//
	int
ae_send_n(aeopcode_t opcode, uint8_t p1, uint16_t p2, const uint8_t *data, uint8_t data_len) 
{
	// all commands will have this fixed header, which includes just one layer of framing
	struct {
		uint8_t	ioflag;
		uint8_t	framed_len;
		uint8_t	op;
		uint8_t	p1;
		uint8_t	p2_lsb;
		uint8_t	p2_msb;
	} known = { 
        .ioflag = IOFLAG_CMD,
		.framed_len = (data_len + 7),		// 7 = (1 len) + (4 bytes of msg) + (2 crc)
		.op = opcode,
		.p1 = p1,
		.p2_lsb = p2 & 0xff,
		.p2_msb = (p2 >> 8) & 0xff,
	};

	STATIC_ASSERT(sizeof(known) == 6);

    stats.last_op = opcode;
    stats.last_p1 = p1;
    stats.last_p2 = p2;

    ae_wake();

    _send_serialized((const uint8_t *)&known, sizeof(known));

	// CRC will start from frame_len onwards
	uint8_t crc[2] = {0, 0};
	crc16_chain(sizeof(known)-1, &known.framed_len, crc);

	// insert a variable-length body area (sometimes)
	if(data_len) {
        _send_serialized(data, data_len);
		
		crc16_chain(data_len, data, crc);
	}

	// send final CRC bytes
    _send_serialized(crc, 2);

	// done!	

	return 0;
}

// ae_delay()
//
// Delay for worse-case time. Don't use in real code, since blocks
// whole system, and some commands are really long!
//
	void
ae_delay(aeopcode_t opcode)
{
	delay_ms(ae_delay_time(opcode));
}

// ae_random()
//
// Get a fresh random number.
//
	int
ae_random(uint8_t randout[32])
{
	int rv;

	rv = ae_send(OP_Random, 0, 0);
	RET_IF_BAD(rv);

	ae_delay(OP_Random);

	rv = ae_read_n(32, randout);
	RET_IF_BAD(rv);

	return 0;
}

// ae_get_info()
//
// Do Info(p1=2) command, and return result.
//
	uint16_t
ae_get_info(void)
{
	// not doing error checking here
	ae_send(OP_Info, 0x2, 0);

	ae_delay(OP_Info);

	// note: always returns 4 bytes, but most are garbage and unused.
	uint8_t tmp[4];
	ae_read_n(4, tmp);

	return (tmp[0] << 8) | tmp[1];
}

// ae_delay_time()
//
// Returns time in MS for max exec time of each command.
//
	int
ae_delay_time(aeopcode_t opcode)
{
	// worse case delay times.
	switch(opcode) {
		case OP_CheckMac:		// 0x28
			return 13;
		case OP_Counter:		// 0x24
			return 20;
		case OP_DeriveKey:		// 0x1C
			return 50;
		case OP_ECDH:			// 0x43
			return 58;
		case OP_GenDig:			// 0x15
			return 11;
		case OP_GenKey:			// 0x40
			return 115;
		case OP_HMAC:			// 0x11
			return 23;
		case OP_Info:			// 0x30
			return 2;					// officially 1, but marginal
		case OP_Lock:			// 0x17
			return 32;
		case OP_MAC:			// 0x08
			return 14;
		case OP_Nonce:			// 0x16
			return 30;					// officially 7, but need 30 for real
		case OP_Pause:			// 0x01
			return 3;
		case OP_PrivWrite:		// 0x46
			return 48;
		case OP_Random:			// 0x1B
			return 23;
		case OP_Read:			// 0x02
			return 1;
		case OP_Sign:			// 0x41
			return 50;
		case OP_SHA:			// 0x47
			return 9;
		case OP_UpdateExtra:	// 0x20
			return 10;
		case OP_Verify:			// 0x45
			return 58;
		case OP_Write:			// 0x12
			return 26;
	}

	return 100;
}

// ae_load_nonce()
//
// Load Tempkey with a specific value. Resulting Tempkey cannot be
// used with many commands/keys, but is needed for signing.
//
	int
ae_load_nonce(const uint8_t nonce[32])
{
    // p1=3
	int rv = ae_send_n(OP_Nonce, 3, 0, nonce, 32);
    RET_IF_BAD(rv);

	ae_delay(OP_Nonce);

    return ae_read1();
}

// ae_pick_nonce()
//
// Load Tempkey with a nonce value that we both know, but
// is random and we both know is random! Tricky!
//
	int
ae_pick_nonce(const uint8_t num_in[20], uint8_t tempkey[32])
{
	// we provide some 20 bytes of randomness to chip
	int	rv;

	// The chip must provide 32-bytes of random-ness,
	// so no choice in args to OP.Nonce here (due to ReqRandom).
	rv = ae_send_n(OP_Nonce, 0, 0, num_in, 20);
	RET_IF_BAD(rv);

	ae_delay(OP_Nonce);

	// Nonce command returns the RNG result, but not contents of TempKey
	uint8_t randout[32];
	rv = ae_read_n(32, randout);
	RET_IF_BAD(rv);

	// Hash stuff appropriately to get same number as chip did.
	//  TempKey on the chip will be set to the output of SHA256 over 
	//  a message composed of my challenge, the RNG and 3 bytes of constants:
	//
	//		return sha256(rndout + num_in + b'\x16\0\0').digest()
	//
	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, randout, 32);
    sha256_update(&ctx, num_in, 20);
	const uint8_t fixed[3] = { 0x16, 0, 0 };
    sha256_update(&ctx, fixed, 3);

    sha256_final(&ctx, tempkey);

	return 0;
}

// ae_pair_unlock()
//
// Do a dance that unlocks access to the private key for signing.
// Purpose is to show we are a pair of chips that belong together.
//
	int
ae_pair_unlock()
{
    return ae_checkmac(KEYNUM_pairing, rom_secrets->pairing_secret);
}

// ae_checkmac()
//
    int
ae_checkmac(uint8_t keynum, const uint8_t secret[32])
{
	int rv;

	// Since this is part of the hash, we want random bytes
	// for our "other data". Also a number for "numin" of nonce
	uint8_t od[32], numin[20];

	rng_buffer(od, sizeof(od));
	rng_buffer(numin, sizeof(numin));

    // need this one, want to reset watchdog to this point.
	ae_keep_alive();

	// - load tempkey with a known nonce value
	uint8_t zeros[8] = {0};
	uint8_t tempkey[32];
	rv = ae_pick_nonce(numin, tempkey);
	RET_IF_BAD(rv);

	// - hash nonce and lots of other bits together
	SHA256_CTX ctx;
    sha256_init(&ctx);

    // shared secret is 32 bytes from flash
    sha256_update(&ctx, secret, 32);

    sha256_update(&ctx, tempkey, 32);
    sha256_update(&ctx, &od[0], 4);

    sha256_update(&ctx, zeros, 8);

    sha256_update(&ctx, &od[4], 3);

	uint8_t ee = 0xEE;
    sha256_update(&ctx, &ee, 1);
    sha256_update(&ctx, &od[7], 4);

	uint8_t snp[2] = { 0x01, 0x23 };
    sha256_update(&ctx, snp, 2);
    sha256_update(&ctx, &od[11], 2);

	// format the request body
	struct {
		uint8_t		ch3[32];		// not actually used, but has to be there
		uint8_t		resp[32];
		uint8_t		od[13];
	} req;

    // content doesn't matter, but nice and visible:
    memcpy(req.ch3, copyright_msg, 32);

#if 0
	// this verifies no problem.
	int l = (ctx.blocks * 64) + ctx.npartial;
	ASSERT(l == 32+32+4+8+3+1+4+2+2);			// == 88
#endif

    sha256_final(&ctx, req.resp);
	memcpy(req.od, od, 13);

	STATIC_ASSERT(sizeof(req) == 32 + 32 + 13);

	// Give our answer to the chip.
	rv = ae_send_n(OP_CheckMac, 0x01, keynum, (uint8_t *)&req, sizeof(req));

	ae_delay(OP_CheckMac);

	rv = ae_read1();
	if(rv != 0) {
		// did it work?! No.
		if(rv == AE_CHECKMAC_FAIL) {
			ERR("CM fail");				// typical case: our hashs don't match
		} else {
			ERRV(rv, "CheckMac");
		}
		return -1;
	}

#if 0
	// double check?
	uint16_t ii = ae_get_info();
	// expect 0x005d for key 11

	if(!I_AuthValid(ii) || (I_AuthKey(ii) != keynum)) {
		ERR("Info r/b");
		return -1;
	}
#endif

	// just in case ... always restart watchdog timer.
	ae_keep_alive();

	return 0;
}

// ae_sign()
//
// Sign a message (already digested)
//
	int
ae_sign(uint8_t keynum, uint8_t msg_hash[32], uint8_t signature[64])
{
	int rv = ae_load_nonce(msg_hash);
	RET_IF_BAD(rv);

	rv = ae_send_n(OP_Sign, 0x80, keynum, NULL, 0);
	RET_IF_BAD(rv);

	ae_delay(OP_Sign);

	rv = ae_read_n(64, signature);
	RET_IF_BAD(rv);

	return 0;
}

// ae_get_counter()
//
// Inc and return the one-way counter.
//
	int
ae_get_counter(uint32_t *result, int counter_number, bool incr)
{
	int rv = ae_send(OP_Counter, incr ? 0x1 : 0x0, counter_number);
	RET_IF_BAD(rv);

	ae_delay(OP_Counter);

	// already in correct endian
	rv = ae_read_n(4, (uint8_t *)result);
	RET_IF_BAD(rv);

	return 0;
}

// ae_make_mac()
//
// Generate a MAC for the indicated key. Will be dependent on serial number.
//
	int
ae_make_mac(uint8_t keynum, uint8_t challenge[32], uint8_t mac_out[32])
{
	int rv = ae_send_n(OP_MAC, (1<<6), keynum, challenge, 32);

	ae_delay(OP_MAC);

	rv = ae_read_n(32, mac_out);
	RET_IF_BAD(rv);

	return 0;
}

#if 0
// ae_hmac()
//
// Perform HMAC on the chip, using a particular key.
//
	int
ae_hmac(uint8_t keynum, const uint8_t *msg, uint16_t msg_len, uint8_t digest[32])
{
	// setup SHA in HMAC mode.
	int rv = ae_send(OP_SHA, 0x04, keynum);
	RET_IF_BAD(rv);

	ae_delay(OP_SHA);

	rv = ae_read1();
	if(rv != AE_COMMAND_OK) return -1;

	// send full blocks, if any.

	while(msg_len >= 64) {
		rv = ae_send_n(OP_SHA, 0x01, 64, msg, 64);
		RET_IF_BAD(rv);
		ae_delay(OP_SHA);

		rv = ae_read1();
		if(rv != AE_COMMAND_OK) return -1;

		msg += 64;
		msg_len -= 64;
	}

	// finalize, with final 0 to 63 bytes
	rv = ae_send_n(OP_SHA, 0x02, msg_len, msg, msg_len);
	RET_IF_BAD(rv);

	ae_delay(OP_SHA);

	rv = ae_read_n(32, digest);
	RET_IF_BAD(rv);

	return 0;
}
#endif

// ae_hmac32()
//
// Different opcode, OP_HMAC does exactly 32 bytes w/ less steps.
//
    int
ae_hmac32(uint8_t keynum, const uint8_t msg[32], uint8_t digest[32])
{
    // Load tempkey w/ message to be HMAC'ed
	int rv = ae_load_nonce(msg);
	RET_IF_BAD(rv);

	// Ask for HMAC using specific key
	rv = ae_send(OP_HMAC, (1<<2) | (1<<6), keynum);
	RET_IF_BAD(rv);

	ae_delay(OP_HMAC);

	rv = ae_read_n(32, digest);
	RET_IF_BAD(rv);

	return 0;
}

// ae_get_serial()
//
// Return the serial number: it's 9 bytes, altho 3 are fixed.
//
	int
ae_get_serial(uint8_t serial[6])
{
	int rv = ae_send(OP_Read, 0x80, 0x0);
	RET_IF_BAD(rv);

	ae_delay(OP_Read);

	uint8_t temp[32];
	rv = ae_read_n(32, temp);
	RET_IF_BAD(rv);

    // reformat to 9 bytes.
    uint8_t ts[9];
	memcpy(ts, &temp[0], 4);
	memcpy(&ts[4], &temp[8], 5);

    // check the hard-coded values
    if((ts[0] != 0x01) || (ts[1] != 0x23) || (ts[8] != 0xEE)) return 1;

    // save only the unique bits.
    memcpy(serial, ts+2, 6);

	return 0;
}


// ae_slot_locks()
//
// Read a 16-bit bitmask of which data slots are presently locked.
//
    int
ae_slot_locks(void)
{
    // Bytes 88, 89 in the Config zone is a bitmap of
    // which slots are locked. Have to read 4 bytes here tho
	int rv = ae_send(OP_Read, 0x00, 88/4);
    if(rv) return -1;

	ae_delay(OP_Read);

	uint8_t tmp[4];
	rv = ae_read_n(4, tmp);
    if(rv) return -2;

    // returns positive 16-bit number on success
	return (tmp[1] << 8) | tmp[0];
}

// ae_write_data_slot()
//
// -- can also lock it.
//
    int
ae_write_data_slot(int slot_num, const uint8_t *data, int len, bool lock_it)
{
    ASSERT(len == 32 || len == 72);      // limitation for this project.

    for(int blk=0; blk<3; blk++) {
        // have to write each "block" of 32-bytes, separately
        // zone => data
        int rv = ae_send_n(OP_Write, 0x80|2, (blk<<8) | (slot_num<<3), data+(blk*32), 32);
        RET_IF_BAD(rv);

        ae_delay(OP_Write);

        rv = ae_read1();
        RET_IF_BAD(rv);

        if(len == 32) break;
    }

    if(lock_it) {
        ASSERT(slot_num != 8);          // no support for mega slot 8
        ASSERT(len == 32);

        // Assume 36/72-byte long slot, which will be partially written, and rest
        // should be ones.
        const int slot_len = (slot_num <= 7) ? 36 : 72;
        uint8_t copy[slot_len];
        memset(copy, 0xff, slot_len);

        memcpy(copy, data, len);

        // calc expected CRC
        uint8_t crc[2] = {0, 0};
        crc16_chain(slot_len, copy, crc);

        // do the lock
        int rv = ae_send(OP_Lock, 2 | (slot_num << 2), (crc[1]<<8) | crc[0]);
        RET_IF_BAD(rv);

        ae_delay(OP_Lock);

        rv = ae_read1();
        RET_IF_BAD(rv);
    }

    return 0;
}

// ae_gendig_slot()
//
    static int
ae_gendig_slot(int slot_num, const uint8_t slot_key[32], uint8_t digest[32])
{
/*
is_delay_needed
        # Construct a digest on the device (and here) that depends on the secret
        # contents of a specific slot.
        assert len(hkey) == 32
        assert not noMac, "don't know how to handle noMac=1 on orig key"

        challenge = self.load_nonce()

        # using Zone=2="Data" => "KeyID specifies a slot in the Data zone"

        msg = hkey + b'\x15\x02' + ustruct.pack("<H", slot_num)
        msg += b'\xee\x01\x23' + (b'\0'*25) + challenge
        assert len(msg) == 32+1+1+2+1+2+25+32

        rv = self.ae_cmd1(opcode=OP.GenDig, p1=0x2, p2=slot_num)
        if rv:
            raise ChipErrorResponse(hex(rv))

        self.reset_watchdog()

        return sha256(msg).digest()
*/
    uint8_t num_in[20], tempkey[32];

	rng_buffer(num_in, sizeof(num_in));
	int rv = ae_pick_nonce(num_in, tempkey);
    RET_IF_BAD(rv);

    //using Zone=2="Data" => "KeyID specifies a slot in the Data zone"
    rv = ae_send(OP_GenDig, 0x2, slot_num);
    RET_IF_BAD(rv);

    ae_delay(OP_GenDig);

    rv = ae_read1();
    RET_IF_BAD(rv);

    ae_keep_alive();

    // we now have to match the digesting (hashing) that has happened on
    // the chip. No feedback at this point if it's right tho.
    //
    //   msg = hkey + b'\x15\x02' + ustruct.pack("<H", slot_num)
    //   msg += b'\xee\x01\x23' + (b'\0'*25) + challenge
    //   assert len(msg) == 32+1+1+2+1+2+25+32
    //
	SHA256_CTX ctx;
    sha256_init(&ctx);

	uint8_t args[7] = { OP_GenDig, 2, slot_num, 0, 0xEE, 0x01, 0x23 };
    uint8_t zeros[25] = { 0 };

    sha256_update(&ctx, slot_key, 32);
    sha256_update(&ctx, args, sizeof(args));
    sha256_update(&ctx, zeros, sizeof(zeros));
    sha256_update(&ctx, tempkey, 32);

    sha256_final(&ctx, digest);

    return 0;
}

// ae_encrypted_read32()
//
    static int
ae_encrypted_read32(int data_slot, int blk,
                    int read_kn, const uint8_t read_key[32], uint8_t data[32])
{
    uint8_t     digest[32];

    ae_keep_alive();
    ae_pair_unlock();

    int rv = ae_gendig_slot(read_kn, read_key, digest);
    RET_IF_BAD(rv);

    // read nth 32-byte "block"
    rv = ae_send(OP_Read, 0x82, (blk << 8) | (data_slot<<3));
    RET_IF_BAD(rv);

    ae_delay(OP_Read);

    rv = ae_read_n(32, data);
    RET_IF_BAD(rv);

    xor_mixin(data, digest, 32);

    return 0;
}

// ae_encrypted_read()
//
    int
ae_encrypted_read(int data_slot, int read_kn, const uint8_t read_key[32], uint8_t *data, int len)
{
    // not clear if chip supports 4-byte encrypted reads 
    ASSERT((len == 32) || (len == 72));

    int rv = ae_encrypted_read32(data_slot, 0, read_kn, read_key, data);
    RET_IF_BAD(rv);

    if(len == 32) return 0;

    rv = ae_encrypted_read32(data_slot, 1, read_kn, read_key, data+32);
    RET_IF_BAD(rv);

    uint8_t tmp[32];
    rv = ae_encrypted_read32(data_slot, 2, read_kn, read_key, tmp);
    RET_IF_BAD(rv);

    memcpy(data+64, tmp, 72-64);

    return 0;
}

// ae_encrypted_write()
//
    static int
ae_encrypted_write32(int data_slot, int blk, int write_kn,
                        const uint8_t write_key[32], const uint8_t data[32])
{
    uint8_t digest[32];

    ae_keep_alive();
    ae_pair_unlock();

    // generate a hash over shared secret and rng
    int rv = ae_gendig_slot(write_kn, write_key, digest);
    RET_IF_BAD(rv);

    // encrypt the data to be written, and append an authenticating MAC
    uint8_t body[32 + 32];

    for(int i=0; i<32; i++) {
        body[i] = data[i] ^ digest[i];
    }

    // make auth-mac to go with
	//	SHA-256(TempKey, Opcode, Param1, Param2, SN<8>, SN<0:1>, <25 bytes of zeros>, PlainTextData)
	//	msg = (dig 
	//	    + ustruct.pack('<bbH', OP.Write, args['p1'], args['p2']) 
	//	    + b'\xee\x01\x23'
	//	    + (b'\0'*25)
	//	    + new_value)
	//	assert len(msg) == 32+1+1+2+1+2+25+32
	//		
	SHA256_CTX ctx;
    sha256_init(&ctx);

    uint8_t p1 = 0x80|2;        // 32 bytes into a data slot
    uint8_t p2_lsb = (data_slot << 3); 
    uint8_t p2_msb = blk;

	uint8_t args[7] = { OP_Write, p1, p2_lsb, p2_msb, 0xEE, 0x01, 0x23 };
    uint8_t zeros[25] = { 0 };

    sha256_update(&ctx, digest, 32);
    sha256_update(&ctx, args, sizeof(args));
    sha256_update(&ctx, zeros, sizeof(zeros));
    sha256_update(&ctx, data, 32);

    sha256_final(&ctx, &body[32]);

    rv = ae_send_n(OP_Write, p1, (p2_msb << 8) | p2_lsb, body, sizeof(body));
    RET_IF_BAD(rv);

    ae_delay(OP_Write);

    rv = ae_read1();
    RET_IF_BAD(rv);

    return 0;
}

// ae_encrypted_write()
//
    int
ae_encrypted_write(int data_slot, int write_kn, const uint8_t write_key[32],
                        const uint8_t *data, int len)
{
    for(int blk=0; blk<3 && len>0; blk++, len-=32) {
        int here = MIN(32, len);

        // be nice and don't read past end of input buffer
        uint8_t     tmp[32] = { 0 };
        memcpy(tmp, data+(32*blk), here);

        int rv = ae_encrypted_write32(data_slot, blk, write_kn, write_key, tmp);
        RET_IF_BAD(rv);
    }

    return 0;
}

// ae_read_data_slot()
//
    int
ae_read_data_slot(int slot_num, uint8_t *data, int len)
{
    ASSERT((len == 4) || (len == 32) || (len == 72));

    // zone => data
    // only reading first block of 32 bytes. ignore the rest
    int rv = ae_send(OP_Read, (len == 4 ? 0x00 : 0x80) | 2, (slot_num<<3));
    RET_IF_BAD(rv);

    ae_delay(OP_Read);

    rv = ae_read_n((len == 4) ? 4 : 32, data);
    RET_IF_BAD(rv);

    if(len == 72) {
        // read second block
        int rv = ae_send(OP_Read, 0x82, (1<<8) | (slot_num<<3));
        RET_IF_BAD(rv);

        ae_delay(OP_Read);

        rv = ae_read_n(32, data+32);
        RET_IF_BAD(rv);

        // read third block, but only using part of it
        uint8_t     tmp[32];
        rv = ae_send(OP_Read, 0x82, (2<<8) | (slot_num<<3));
        RET_IF_BAD(rv);

        ae_delay(OP_Read);

        rv = ae_read_n(32, tmp);
        RET_IF_BAD(rv);

        memcpy(data+64, tmp, 72-64);
    }

    return 0;
}

// ae_config_write()
//
    static int
ae_config_write(const uint8_t config[128])
{
    // send all 128 bytes, less some that can't be written.
    for(int n=16; n<128; n+= 4) {
        if((n >= 84) && (n < 90)) {
            continue;
        }

        // Must work on words, since can't write to most of the complete blocks.
        //  args = write_params(block=n//32, offset=n//4, is_config=True)
        //  p2 = (block << 3) | offset
        int rv = ae_send_n(OP_Write, 0, n/4, &config[n], 4);
        RET_IF_BAD(rv);

        ae_delay(OP_Write);
    
		rv = ae_read1();
        if(rv) return rv;
    }

    return 0;
}

// ae_lock_config_zone()
//
    static int
ae_lock_config_zone(const uint8_t config[128])
{
    // calc expected CRC
    uint8_t crc[2] = {0, 0};

    crc16_chain(128, config, crc);

    // do the lock: mode=0
    int rv = ae_send(OP_Lock, 0x0, (crc[1]<<8) | crc[0]);
    RET_IF_BAD(rv);

    ae_delay(OP_Lock);

    return ae_read1();
}

// ae_lock_data_zone()
//
    static int
ae_lock_data_zone(void)
{
    // NOTE: I haven't been able to calc CRC right, so not using it.

    // do the lock: mode=1 (datazone) + 0x80 (no CRC check)
    int rv = ae_send(OP_Lock, 0x81, 0x0000);
    RET_IF_BAD(rv);

    ae_delay(OP_Lock);

    return ae_read1();
}


// ae_sha256()
//
	int
ae_sha256(const uint8_t *msg, int msg_len, uint8_t digest[32])
{
	// setup
	int rv = ae_send(OP_SHA, 0x00, 0);
	RET_IF_BAD(rv);

	ae_delay(OP_SHA);

	rv = ae_read1();
	if(rv != AE_COMMAND_OK) return -1;

	while(msg_len >= 64) {
		rv = ae_send_n(OP_SHA, 0x01, 64, msg, 64);
		RET_IF_BAD(rv);
		ae_delay(OP_SHA);

		rv = ae_read1();
		if(rv != AE_COMMAND_OK) return -1;

		msg += 64;
		msg_len -= 64;
	}

	// finalize, with final 0 to 63 bytes
	rv = ae_send_n(OP_SHA, 0x02, msg_len, msg, msg_len);
	RET_IF_BAD(rv);

	ae_delay(OP_SHA);

	rv = ae_read_n(32, digest);
	RET_IF_BAD(rv);

	return 0;
}

// ae_set_gpio()
//
    int
ae_set_gpio(int state)
{
    // 1=turn on green, 0=red light (if not yet configured to be secure)
    int rv = ae_send(OP_Info, 3, 2 | (!!state));
	RET_IF_BAD(rv);

	ae_delay(OP_Info);

    // "Always return the current state in the first byte followed by three bytes of 0x00"
    // - simple 1/0, in LSB.
    uint8_t resp[4];

    rv = ae_read_n(4, resp);
	RET_IF_BAD(rv);

    return (resp[0] != state) ? -1 : 0;
}

// ae_set_gpio_secure()
//
// Set the GPIO using secure hash generated somehow already.
//
    int
ae_set_gpio_secure(uint8_t digest[32])
{
    ae_pair_unlock();
    ae_checkmac(KEYNUM_firmware, digest);

    return ae_set_gpio(1);
}

// ae_get_gpio()
//
// Do Info(p1=3) command, and return result.
//
	uint8_t
ae_get_gpio(void)
{
	// not doing error checking here
	ae_send(OP_Info, 0x3, 0);

	ae_delay(OP_Info);

	// note: always returns 4 bytes, but most are garbage and unused.
	uint8_t tmp[4];
	ae_read_n(4, tmp);

	return tmp[0];
}

// ae_read_config()
//
// Read a byte from config area.
//
    int
ae_read_config_byte(int offset)
{
	uint8_t tmp[4];

    ae_read_config_word(offset, tmp);

	return tmp[offset % 4];
}

// ae_read_config_word()
//
// Read a 4-byte area from config area, or -1 if fail.
//
    int
ae_read_config_word(int offset, uint8_t *dest)
{
    offset &= 0x7f;

    // read 32 bits (aligned)
	int rv = ae_send(OP_Read, 0x00, offset/4);
    if(rv) return -1;

	ae_delay(OP_Read);

	rv = ae_read_n(4, dest);
    if(rv) return -1;

    return 0;
}


// ae_destroy_key()
//
    int
ae_destroy_key(int keynum)
{
	uint8_t numin[20];

	// Load tempkey with a known (random) nonce value
	rng_buffer(numin, sizeof(numin));
	int rv = ae_send_n(OP_Nonce, 0, 0, numin, 20);
	RET_IF_BAD(rv);

	ae_delay(OP_Nonce);

	// Nonce command returns the RNG result, not contents of TempKey,
    // but since we are destroying, no need to calculate what it is.
	uint8_t randout[32];
	rv = ae_read_n(32, randout);
	RET_IF_BAD(rv);

    // do a "DeriveKey" operation, based on that!
	rv = ae_send(OP_DeriveKey, 0x00, keynum);
    if(rv) return -1;

	ae_delay(OP_DeriveKey);

    return ae_read1();
}

// ae_setup_config()
//
// One-time config and lockdown of the chip
//
// CONCERN: Must not be possible to call this function after replacing
// the chip deployed originally. But key secrets would have been lost
// by then anyway... looks harmless, and regardless once the datazone
// is locked, none of this code will work... but:
//
// IMPORTANT: If they blocked the real chip, and provided a blank one for
// us to write the (existing) pairing secret into, they would see the pairing
// secret in cleartext. They could then restore original chip and access freely.
//
    int
ae_setup_config(void)
{
    // Is data zone is locked?
    // Allow rest of function to happen if it's not.

    //  0x55 = unlocked; 0x00 = locked
    bool data_locked = (ae_read_config_byte(86) != 0x55);
    if(data_locked) return 0;       // basically success

    // Program the "config" area, and then lock it.

    // To lock, we need a CRC over whole thing, but we
    // only set a few values... plus the serial number is
    // in there, so start with some readout.
    uint8_t config[4 * 32];

    for(int blk=0; blk<4; blk++) {
        // read 32 bytes (aligned) from config "zone"
        int rv = ae_send(OP_Read, 0x80, blk<<3);
        if(rv) return EIO;

        ae_delay(OP_Read);

        rv = ae_read_n(32, &config[32*blk]);
        if(rv) return EIO;
    }

    // verify some fixed values
    ASSERT(config[0] == 0x01);
    ASSERT(config[1] == 0x23);
    ASSERT(config[12] == 0xee);

    uint8_t serial[9];
	memcpy(serial, &config[0], 4);
	memcpy(&serial[4], &config[8], 5);

    if(check_all_ones(rom_secrets->ae_serial_number, 9)) {
        // flash is empty; remember this serial number
        flash_save_ae_serial(serial);
    }

    if(!check_equal(rom_secrets->ae_serial_number, serial, 9)) {
        // write failed?
        // we're already linked to a different chip? Write failed?
        return EPERM;
    }

    // Setup steps:
    // - write config zone data
    // - lock that
    // - write pairing secret (test it works)
    // - pick RNG value for words secret (and forget it)
    // - set all PIN values to known value (zeros)
    // - set all money secrets to knonw value (zeros)
    // - lock the data zone

    if(config[87] == 0x55) {
        // config is still unlocked

        // setup "config zone" area of the chip
        static const uint8_t    config_1[] = AE_CHIP_CONFIG_1;
        static const uint8_t    config_2[] = AE_CHIP_CONFIG_2;

        STATIC_ASSERT(sizeof(config_1) == 84-16);
        STATIC_ASSERT(sizeof(config_2) == 128-90);

        memcpy(&config[16], config_1, sizeof(config_1));
        memcpy(&config[90], config_2, sizeof(config_2));

        // write it.
        if(ae_config_write(config)) {
            INCONSISTENT("conf wr");
        }

        ae_keep_alive();

        // lock config zone
        if(ae_lock_config_zone(config)) {
            INCONSISTENT("conf lock");
        }
    } else {
        // check config is what we need? but when would that happen?
        // omit this check, since only useful for debug cases
    }

    // Load data zone with some known values.
    // The datazone still unlocked, so no encryption needed (nor possible).

    
    // will use zeros for all PIN codes, and secret starting values
    uint8_t     zeros[72];
    memset(zeros, 0, sizeof(zeros));

    for(int kn=0; kn<16; kn++) {
        ae_keep_alive();

        switch(kn) {
            default:
            case 15: break;

            case KEYNUM_pairing:
                if(ae_write_data_slot(kn, rom_secrets->pairing_secret, 32, false)) {
                    INCONSISTENT("wr pair");
                }
                break;


            case KEYNUM_words: {
                    // - hmac key for phishing words (and then we forget it)
                    uint8_t     tmp[32];
                    rng_buffer(tmp, sizeof(tmp));

                    if(ae_write_data_slot(kn, tmp, 32, true)) {
                        INCONSISTENT("wr word");
                    }
                }
                break;

            case KEYNUM_pin_1:
            case KEYNUM_pin_2:
            case KEYNUM_pin_3:
            case KEYNUM_pin_4:
            case KEYNUM_lastgood_1:
            case KEYNUM_lastgood_2:
            case KEYNUM_brickme:
            case KEYNUM_firmware:
                if(ae_write_data_slot(kn, zeros, 32, false)) {
                    INCONSISTENT("wr blk 32");
                }
                break;

            case KEYNUM_secret_1:
            case KEYNUM_secret_2:
            case KEYNUM_secret_3:
            case KEYNUM_secret_4:
                if(ae_write_data_slot(kn, zeros, 72, false)) {
                    INCONSISTENT("wr blk 72");
                }
                break;

            case 0:
                if(ae_write_data_slot(kn, (const uint8_t *)copyright_msg, 32, true)) {
                    INCONSISTENT("wr (c)");
                }
                break;
        }
    }

    // lock the data zone and effectively enter normal operation.
    ae_keep_alive();
    if(ae_lock_data_zone()) {
        INCONSISTENT("data lock");
    }

    return 0;
}
// EOF
