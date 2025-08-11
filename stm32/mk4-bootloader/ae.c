/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#include "basics.h"
#include "ae.h"
#include "se2.h"
#include "clocks.h"
#include "rng.h"
#include "delay.h"
#include "faster_sha256.h"
#include "constant_time.h"
#include "gpio.h"
#include "storage.h"
#include "stm32l4xx_hal.h"
#include "ae_config.h"
#include "se2.h"
#include "oled.h"
#include "console.h"
#include <errno.h>
#include <string.h>

// Must be exactly 32 chars:
static const char *copyright_msg = "Copyright 2018- by Coinkite Inc.";     

// Selectable debug level; keep them as comments regardless
#if 0
// break on any error: not helpful since some are normal
# define ERR(msg)            BREAKPOINT;
# define ERRV(val, msg)       BREAKPOINT;
#elif 0
// affects timing
# define ERR(msg)       puts(msg)
# define ERRV(val, msg) do { puts2(msg); puts2(": "); puthex2(val); putchar('\n'); } while(0)
#else
# define ERR(msg)
# define ERRV(val, msg)
#endif

// "one wire" is on PA0 aka. UART4
#define MY_UART         UART4

// keep this in place.
#define RET_IF_BAD(rv)		do { if(rv) return rv; } while(0)

#define AE_CHIP_IS_SETUP        0x35d25d63
static uint32_t ae_chip_is_setup;

// Forward refs...
static void crc16_chain(uint8_t length, const uint8_t *data, uint8_t crc[2]);
static void ae_wake(void);

// Enable some powerful debug features.
#if 0
#define DEV_STATS

static struct {
    int crc_error;
    int len_error;
    int crc_len_error;
    int short_error;
    int not_ready, not_ready_n;
    int l1_retry;
    int ln_retry;
    int extra_bits;
    aeopcode_t last_op;
    uint8_t last_resp1, last_p1;
    uint16_t last_p2;
    uint8_t     last_n_data[32];
    uint8_t     last_n_len;
    uint16_t    was_locked;
} stats;
#define STATS(x)         stats. x;
#else
#define STATS(x)
#endif

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

    // We actually need this delay here!
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

// ae_wake()
//
// Do not call this casually: it may cause next read to return 0x11 (After Wake,
// Prior to First Command) as an error to any on-going/attempted operation.
//
//
    static void
ae_wake(void)
{
    // send zero (all low), delay 2.5ms
    _send_byte(0x00);

    delay_ms(3);     // measured: ~2.9ms

    _flush_rx();
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
#ifdef DEV_STATS
    memset(&stats, 0, sizeof(stats));
#endif

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
#ifdef USART_CR1_TXEIE
                                    | USART_CR1_TXEIE 
#endif
                                    | USART_CR1_TCIE 
#ifdef USART_CR1_RXNEIE
                                    | USART_CR1_RXNEIE
#endif
                                    | USART_CR1_IDLEIE
                                    | USART_CR1_OVER8
                                    | USART_CR1_UE);

    MY_UART->RTOR = 24;                  // timeout in bit periods: 3 chars or so
    MY_UART->CR2 = USART_CR2_RTOEN;      // rx timeout enable
    MY_UART->CR3 = USART_CR3_HDSEL | USART_CR3_ONEBIT;
#if HCLK_FREQUENCY == 80000000
    MY_UART->BRR = 0x0000015b;          // 230400 bps @ 80 Mhz SYSCLK
#elif HCLK_FREQUENCY == 120000000
    MY_UART->BRR = 521;                 // 230400 bps @ 120 Mhz SYSCLK
#else
#   error "needs math"
#endif

    // clear rx timeout flag
    MY_UART->ICR = USART_ICR_RTOCF;

    // finally enable UART
    MY_UART->CR1 |= USART_CR1_UE;
    
    // configure pin A0 to be AFx_UARTy, PULL_NONE
    // should already be done: gpio_setup();
    
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

    // no need to wake: next transaction will do that 
	//ae_wake();
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
        STATS(crc_len_error++);
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

	for(int retry=7; retry >= 0; retry--) {
        // tell it we want to read a response, read it, and deserialize
        int rv = ae_read_response(msg, 4);

        if(rv == 0) {
            // nothing heard, it's probably still processing
            ERR("not rdy");
            STATS(not_ready++);

            delay_ms(5);
            goto try_again;
        }

        if(rv != 4) {
            ERR("rx len");
            STATS(len_error++);
            goto try_again;
        }

		// Check length and CRC bytes. we will retry a few times
		// if they are wrong.
		if(!ae_check_crc(msg, 4)) {
			ERR("bad crc");
            STATS(crc_error++);
			goto try_again;
		}

        STATS(last_resp1 = msg[1]);

		// done, and it worked; return the one byte.
		return msg[1];

	try_again:
        STATS(l1_retry++);
	}

	// fail.
	return -1;
}

// ae_read_n()
//
// Read and check CRC over N bytes, wrapped in 3-bytes of framing overhead.
// Return -1 for timeout, zero for normal, and one-byte error code otherwise.
//
	int
ae_read_n(uint8_t len, uint8_t *body)
{
    uint8_t tmp[1+len+2];

	for(int retry=7; retry >= 0; retry--) {

        int actual = ae_read_response(tmp, len+3);
        if(actual < 4) {

            if(actual == 0) {
                // nothing heard, it's probably still processing
                delay_ms(5);
                ERR("not ready2");
                STATS(not_ready_n++);
            } else {
                // a weird short-read? probably fatal, but retry
                ERR("too short");
                STATS(short_error++);
            }
            goto try_again;
        }

        uint8_t resp_len = tmp[0];
		if(resp_len != (len + 3)) {
            STATS(len_error++);
            if(resp_len == 4) {
				// Probably an unexpected error. But no way to return a short read, so
				// just print out debug info.
                ERRV(tmp[1], "ae errcode");
                STATS(last_resp1 = tmp[1]);

                return tmp[1];
            }
			ERRV(tmp[0], "wr len");		 // wrong length
			goto try_again;
		}

		if(!ae_check_crc(tmp, actual)) {
			ERR("bad crc");
            STATS(crc_error++);
			goto try_again;
		}

		// normal case: copy out body of message w/o framing
        memcpy(body, tmp+1, actual-3);

#ifdef DEV_STATS
        memcpy(stats.last_n_data, body, MIN(32, actual-3));
        stats.last_n_len =  actual-3;
#endif

		return 0;

	try_again:
        STATS(ln_retry++);
        ae_wake();
	}

	return -1;
}

// ae_send()
//
	void
ae_send(aeopcode_t opcode, uint8_t p1, uint16_t p2) 
{
	ae_send_n(opcode, p1, p2, NULL, 0);
}

// ae_send_n()
//
	void
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

    STATS(last_op = opcode);
    STATS(last_p1 = p1);
    STATS(last_p2 = p2);

    // important to wake chip at this point.
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
}

#if 0
// ae_random()
//
// Get a fresh random number.
//
// RISKY - Easy for Mitm to control value.
//
	int
ae_random(uint8_t randout[32])
{
	int rv;

	ae_send(OP_Random, 0, 0);

	rv = ae_read_n(32, randout);
	RET_IF_BAD(rv);

	return 0;
}
#endif


// ae_secure_random()
//
// Generate a random number, using nonces generated by chip and by us.
// Verify the result was not modified by MitM.
//
    void
ae_secure_random(uint8_t randout[32])
{
    // Generate a digest of pairing secret slot, which will include
    // a nonce from chip.
    int rv = ae_gendig_slot(KEYNUM_pairing, rom_secrets->pairing_secret, randout);

    // Verify digest was made using inputs we think.
    if(rv || !ae_is_correct_tempkey(randout)) {
        fatal_mitm();
    }

    // since that value is "tempkey" inside the secure element, it feels
    // wrong to share that directly, so hash it up.
    sha256_single(randout, 32, randout);
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

	// note: always returns 4 bytes, but most are garbage and unused.
	uint8_t tmp[4];
	ae_read_n(4, tmp);

	return (tmp[0] << 8) | tmp[1];
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
	ae_send_n(OP_Nonce, 3, 0, nonce, 32);          // 608a ok

    return ae_read1();
}

// ae_load_msgdigest()
//
// Load 32bytes of message digest  with a specific value.
// Needed for signing.
//
	int
ae_load_msgdigest(const uint8_t md[32])
{
	ae_send_n(OP_Nonce, (1<<6) | 3, 0, md, 32);

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
	// We provide some 20 bytes of randomness to chip
	// The chip must provide 32-bytes of random-ness,
	// so no choice in args to OP.Nonce here (due to ReqRandom).
	ae_send_n(OP_Nonce, 0, 0, num_in, 20);

	// Nonce command returns the RNG result, but not contents of TempKey
	uint8_t randout[32];
	int rv = ae_read_n(32, randout);
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

// ae_is_correct_tempkey()
//
// Check that TempKey is holding what we think it does. Uses the MAC
// command over contents of Tempkey and our shared secret.
//
    bool
ae_is_correct_tempkey(const uint8_t expected_tempkey[32])
{
    const uint8_t mode =   (1<<6)     // include full serial number
                         | (0<<2)     // TempKey.SourceFlag == 0 == 'rand'
                         | (0<<1)     // first 32 bytes are the shared secret
                         | (1<<0);    // second 32 bytes are tempkey

	ae_send(OP_MAC, mode, KEYNUM_pairing);

    // read chip's answer
	uint8_t resp[32];
	int rv = ae_read_n(32, resp);
    if(rv) return false;

    ae_keep_alive();

    // Duplicate the hash process, and then compare.
	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    sha256_update(&ctx, expected_tempkey, 32);

	const uint8_t fixed[16] = { OP_MAC, mode, KEYNUM_pairing, 0x0,
                                    0,0,0,0, 0,0,0,0,       // eight zeros
                                    0,0,0,                  // three zeros
                                    0xEE };
    sha256_update(&ctx, fixed, sizeof(fixed));

    sha256_update(&ctx, ((const uint8_t *)rom_secrets->ae_serial_number)+4, 4);
    sha256_update(&ctx, ((const uint8_t *)rom_secrets->ae_serial_number)+0, 4);

#if 0
	// this verifies no problem.
	ASSERT(ctx.datalen + (ctx.bitlen/8) == 32+32+1+1+2+8+3+1+4+2+2);        // == 88
#endif

    uint8_t         actual[32];
    sha256_final(&ctx, actual);

    return check_equal(actual, resp, 32);
}

// ae_checkmac_hard()
//
// Check the chip produces a hash over various things the same way we would
// meaning that we both know the shared secret and the state of stuff in
// the chip is what we expect.
//
    int
ae_checkmac_hard(uint8_t keynum, const uint8_t secret[32])
{
    uint8_t     digest[32];

    int rv = ae_gendig_slot(keynum, secret, digest);
    RET_IF_BAD(rv);

    // NOTE: we use this sometimes when we know the value is wrong, like
    // checking for blank pin codes... so not a huge error/security issue
    // if wrong here.
    if(!ae_is_correct_tempkey(digest)) return -2;

    // worked.
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
// CAUTION: The result from this function could be modified by an
// active attacker on the bus because the one-byte response from the chip
// is easily replaced. This command is useful for us to authorize actions
// inside the 508a/608a, like use of a specific key, but not for us to
// authenticate the 508a/608a or its contents/state.
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
	ae_send_n(OP_CheckMac, 0x01, keynum, (uint8_t *)&req, sizeof(req));

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

// ae_sign_authed()
//
// Sign a message (already digested)
//
	int
ae_sign_authed(uint8_t keynum, const uint8_t msg_hash[32],
                uint8_t signature[64], int auth_kn, const uint8_t auth_digest[32])
{
    // indicate we know the PIN
    ae_pair_unlock();
    int rv = ae_checkmac(KEYNUM_main_pin, auth_digest);
    RET_IF_BAD(rv);

    // send what we need signed
	rv = ae_load_msgdigest(msg_hash);
	RET_IF_BAD(rv);

    do {
        ae_send(OP_Sign, (7<<5), keynum);

        delay_ms(60);     // min time for processing

        rv = ae_read_n(64, signature);
    } while(rv == AE_ECC_FAULT);

	return rv;
}

#if 0
// ae_ecdh()
//
// Calc a shared secret.
//
	int
ae_ecdh(uint8_t keynum, const uint8_t pubkey[64], uint8_t shared_x[32], int auth_kn, const uint8_t auth_digest[32])
{
    // indicate we know the PIN
    ae_pair_unlock();
    int rv = ae_checkmac(KEYNUM_main_pin, auth_digest);
    RET_IF_BAD(rv);

    uint8_t result[64];
    do {
        ae_send_n(OP_ECDH, (3<<2) | (1<<1) | (0<<0), keynum, pubkey, 64);

        delay_ms(60);     // min time for processing

        rv = ae_read_n(64, result);
    } while(rv == AE_ECC_FAULT);

    RET_IF_BAD(rv);

    // result is encrypted by AE.
	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    sha256_update(&ctx, &result[32], 16);

	uint8_t tempkey[32];
    sha256_final(&ctx, tempkey);

    memcpy(shared_x, result, 32);
    xor_mixin(shared_x, tempkey, 32);

	return rv;
}
#endif

// ae_gen_ecc_key()
//
    int
ae_gen_ecc_key(uint8_t keynum, uint8_t pubkey_out[64])
{
    int rv;
    uint8_t junk[3] = { 0 };

    do {
        ae_send_n(OP_GenKey, (1<<2), keynum, junk, 3);

        delay_ms(100);     // to avoid timeouts

        rv = ae_read_n(64, pubkey_out);
    } while(rv == AE_ECC_FAULT);

    return rv;
}

#if 0
// TEST CODE -- works, value will match rom_secrets->se2.auth_pubkey
// ae_dump_pubkey()
//
    int
ae_dump_pubkey(void)
{
    uint8_t keynum = KEYNUM_joiner_key;
    int rv;
    uint8_t junk[3] = { 0 };
    uint8_t pubkey_out[64];

    uint8_t     auth_digest[32]={0};
    ae_pair_unlock();

	{ uint16_t state = ae_get_info();
      puts2("st1="); puthex4(state); putchar('\n');
    }

    // indicate we know the correct PIN
    rv = ae_checkmac(KEYNUM_main_pin, auth_digest);
    RET_IF_BAD(rv);

	{ uint16_t state = ae_get_info();
      puts2("st2="); puthex4(state); putchar('\n');
    }

    ae_send_n(OP_GenKey, 0x0, keynum, junk, 3);

    delay_ms(50);     // to avoid timeouts?

    rv = ae_read_n(64, pubkey_out);

    puts2("rv="); puthex2(rv);
    puts2("\r\npk="); hex_dump(pubkey_out, 64);

    return rv;
}
#endif

// ae_get_counter()
//
// Just read a one-way counter.
//
	int
ae_get_counter(uint32_t *result, uint8_t counter_number)
{
    ae_send(OP_Counter, 0x0, counter_number);

    int rv = ae_read_n(4, (uint8_t *)result);
    RET_IF_BAD(rv);

    // IMPORTANT: Always verify the counter's value because otherwise
    // nothing prevents an active MitM changing the value that we think
    // we just read.

    uint8_t     digest[32];
    rv = ae_gendig_counter(counter_number, *result, digest);
	RET_IF_BAD(rv);

    if(!ae_is_correct_tempkey(digest)) {
        // no legit way for this to happen, so just die.
        fatal_mitm();
    }

    return 0;
}

// ae_add_counter()
//
// Add-to and return a one-way counter's value. Have to go up in
// single-unit steps, but can we loop.
//
	int
ae_add_counter(uint32_t *result, uint8_t counter_number, int incr)
{
    for(int i=0; i<incr; i++) {
        ae_send(OP_Counter, 0x1, counter_number);
        int rv = ae_read_n(4, (uint8_t *)result);
        RET_IF_BAD(rv);
    }

    // IMPORTANT: Always verify the counter's value because otherwise
    // nothing prevents an active MitM changing the value that we think
    // we just read. They could also stop us increamenting the counter.

    uint8_t     digest[32];
    int rv = ae_gendig_counter(counter_number, *result, digest);
	RET_IF_BAD(rv);

    if(!ae_is_correct_tempkey(digest)) {
        // no legit way for this to happen, so just die.
        fatal_mitm();
    }

    return 0;
}

#if 0
// unused code, and not supported directly on 608a
// ae_hmac()
//
// Perform HMAC on the chip, using a particular key.
//
	int
ae_hmac(uint8_t keynum, const uint8_t *msg, uint16_t msg_len, uint8_t digest[32])
{
	// setup SHA in HMAC mode.
	ae_send(OP_SHA, 0x04, keynum);

	int rv = ae_read1();
	if(rv != AE_COMMAND_OK) return -1;

	// send full blocks, if any.

	while(msg_len >= 64) {
		ae_send_n(OP_SHA, 0x01, 64, msg, 64);

		rv = ae_read1();
		if(rv != AE_COMMAND_OK) return -1;

		msg += 64;
		msg_len -= 64;
	}

	// finalize, with final 0 to 63 bytes
	ae_send_n(OP_SHA, 0x02, msg_len, msg, msg_len);
	RET_IF_BAD(rv);

	rv = ae_read_n(32, digest);
	RET_IF_BAD(rv);

	return 0;
}
#endif

// ae_hmac32()
//
// 508a: Different opcode, OP_HMAC does exactly 32 bytes w/ less steps.
// 608a: Use old SHA256 command, but with new flags.
//
    int
ae_hmac32(uint8_t keynum, const uint8_t msg[32], uint8_t digest[32])
{
    // Start SHA w/ HMAC setup
	ae_send(OP_SHA, 4, keynum);        // 4 = HMAC_Init

    // expect zero, meaning "ready"
    int rv = ae_read1();
    RET_IF_BAD(rv);

    // send the contents to be hashed
	ae_send_n(OP_SHA, (3<<6) | 2, 32, msg, 32); // 2 = Finalize, 3=Place output
    
    // read result
    return ae_read_n(32, digest);
}

// ae_get_serial()
//
// Return the serial number: it's 9 bytes, altho 3 are fixed.
//
	int
ae_get_serial(uint8_t serial[6])
{
	ae_send(OP_Read, 0x80, 0x0);

	uint8_t temp[32];
	int rv = ae_read_n(32, temp);
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

#if 0
// ae_slot_locks()
//
// Read a 16-bit bitmask of which data slots are presently locked.
//
    int
ae_slot_locks(void)
{
    // Bytes 88, 89 in the Config zone is a bitmap of
    // which slots are locked. Have to read 4 bytes here tho
	ae_send(OP_Read, 0x00, 88/4);

	uint8_t tmp[4];
	int rv = ae_read_n(4, tmp);
    if(rv) return -2;

    // returns positive 16-bit number on success
	return (tmp[1] << 8) | tmp[0];
}
#endif

// ae_write_data_slot()
//
// -- can also lock it.
//
    int
ae_write_data_slot(int slot_num, const uint8_t *data, int len, bool lock_it)
{
    ASSERT(len >= 32);
    ASSERT(len <= 416);

    for(int blk=0, xlen=len; xlen>0; blk++, xlen-=32) {
        // have to write each "block" of 32-bytes, separately
        // zone => data
        ae_send_n(OP_Write, 0x80|2, (blk<<8) | (slot_num<<3), data+(blk*32), 32);

        int rv = ae_read1();
        RET_IF_BAD(rv);
    }

    if(lock_it) {
        ASSERT(slot_num != 8);          // no support for mega slot 8
        ASSERT(len == 32);              // probably not a limitation here

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
        ae_send(OP_Lock, 2 | (slot_num << 2), (crc[1]<<8) | crc[0]);

        int rv = ae_read1();
        RET_IF_BAD(rv);
    }

    return 0;
}

// ae_gendig_slot()
//
    int
ae_gendig_slot(int slot_num, const uint8_t slot_contents[32], uint8_t digest[32])
{
    // Construct a digest on the device (and here) that depends on the secret
    // contents of a specific slot.
    uint8_t num_in[20], tempkey[32];

	rng_buffer(num_in, sizeof(num_in));
	int rv = ae_pick_nonce(num_in, tempkey);
    RET_IF_BAD(rv);

    //using Zone=2="Data" => "KeyID specifies a slot in the Data zone"
    ae_send(OP_GenDig, 0x2, slot_num);

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

    sha256_update(&ctx, slot_contents, 32);
    sha256_update(&ctx, args, sizeof(args));
    sha256_update(&ctx, zeros, sizeof(zeros));
    sha256_update(&ctx, tempkey, 32);

    sha256_final(&ctx, digest);

    return 0;
}

// ae_gendig_counter()
//
// Construct a digest over one of the two counters. Track what we think
// the digest should be, and ask the chip to do the same. Verify we match
// using MAC command (done elsewhere).
//
    int
ae_gendig_counter(int counter_num, const uint32_t expected_value, uint8_t digest[32])
{
    uint8_t num_in[20], tempkey[32];

	rng_buffer(num_in, sizeof(num_in));
	int rv = ae_pick_nonce(num_in, tempkey);
    RET_IF_BAD(rv);

    //using Zone=4="Counter" => "KeyID specifies the monotonic counter ID"
    ae_send(OP_GenDig, 0x4, counter_num);

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

    uint8_t zeros[32] = { 0 };
	uint8_t args[8] = { OP_GenDig, 0x4, counter_num, 0,  0xEE, 0x01, 0x23, 0x0 };

    sha256_update(&ctx, zeros, 32);
    sha256_update(&ctx, args, sizeof(args));
    sha256_update(&ctx, (const uint8_t *)&expected_value, 4);
    sha256_update(&ctx, zeros, 20);
    sha256_update(&ctx, tempkey, 32);

    sha256_final(&ctx, digest);

    return 0;
}

// ae_encrypted_read32()
//
    int
ae_encrypted_read32(int data_slot, int blk,
                    int read_kn, const uint8_t read_key[32], uint8_t data[32])
{
    uint8_t     digest[32];

    ae_pair_unlock();

    int rv = ae_gendig_slot(read_kn, read_key, digest);
    RET_IF_BAD(rv);

    // read nth 32-byte "block"
    ae_send(OP_Read, 0x82, (blk << 8) | (data_slot<<3));

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
    int
ae_encrypted_write32(int data_slot, int blk, int write_kn,
                        const uint8_t write_key[32], const uint8_t data[32])
{
    uint8_t digest[32];

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

    ae_send_n(OP_Write, p1, (p2_msb << 8) | p2_lsb, body, sizeof(body));

    return ae_read1();
}

// ae_encrypted_write()
//
    int
ae_encrypted_write(int data_slot, int write_kn, const uint8_t write_key[32],
                        const uint8_t *data, int len)
{
    ASSERT(data_slot >= 0);
    ASSERT(data_slot <= 15);

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
    ae_send(OP_Read, (len == 4 ? 0x00 : 0x80) | 2, (slot_num<<3));

    int rv = ae_read_n((len == 4) ? 4 : 32, data);
    RET_IF_BAD(rv);

    if(len == 72) {
        // read second block
        ae_send(OP_Read, 0x82, (1<<8) | (slot_num<<3));

        int rv = ae_read_n(32, data+32);
        RET_IF_BAD(rv);

        // read third block, but only using part of it
        uint8_t     tmp[32];
        ae_send(OP_Read, 0x82, (2<<8) | (slot_num<<3));

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
        if(n == 84) continue;       // that word not writable

        // Must work on words, since can't write to most of the complete blocks.
        //  args = write_params(block=n//32, offset=n//4, is_config=True)
        //  p2 = (block << 3) | offset
        ae_send_n(OP_Write, 0, n/4, &config[n], 4);
    
		int rv = ae_read1();
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
    ae_send(OP_Lock, 0x0, (crc[1]<<8) | crc[0]);

    return ae_read1();
}

// ae_lock_data_zone()
//
    static int
ae_lock_data_zone(void)
{
    // NOTE: I haven't been able to calc CRC right, so not using it.

    // do the lock: mode=1 (datazone) + 0x80 (no CRC check)
    ae_send(OP_Lock, 0x81, 0x0000);

    return ae_read1();
}

#if 0
// ae_sha256()
//
	int
ae_sha256(const uint8_t *msg, int msg_len, uint8_t digest[32])
{
	// setup
    ae_send(OP_SHA, 0x00, 0);

	int rv = ae_read1();
	if(rv != AE_COMMAND_OK) return -1;

	while(msg_len >= 64) {
		ae_send_n(OP_SHA, 0x01, 64, msg, 64);

		rv = ae_read1();
		if(rv != AE_COMMAND_OK) return -1;

		msg += 64;
		msg_len -= 64;
	}

	// finalize, with final 0 to 63 bytes
    ae_send_n(OP_SHA, 0x02, msg_len, msg, msg_len);

    return ae_read_n(32, digest);
}
#endif

// ae_set_gpio()
//
    int
ae_set_gpio(int state)
{
    // 1=turn on green, 0=red light (if not yet configured to be secure)
    ae_send(OP_Info, 3, 2 | (!!state));

    // "Always return the current state in the first byte followed by three bytes of 0x00"
    // - simple 1/0, in LSB.
    uint8_t resp[4];

    int rv = ae_read_n(4, resp);
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

    int rv = ae_set_gpio(1);

    if(rv == 0) {
        // We set the output, and we got a successful readback, but we can't
        // trust that readback, and so do a verify that the chip has 
        // the digest we think it does. If MitM wanted to turn off the output,
        // they can do that anytime regardless. We just don't want them to be
        // able to fake it being set, and therefore bypass the
        // "unsigned firmware" delay and warning.
        ae_pair_unlock();

        if(ae_checkmac_hard(KEYNUM_firmware, digest) != 0) {
            fatal_mitm();
        }
    }

    return rv;
}

// ae_get_gpio()
//
// Do Info(p1=3) command, and return result.
//
// IMPORTANT: do not trust this result, could be MitM'ed.
//
	uint8_t
ae_get_gpio(void)
{
	// not doing error checking here
	ae_send(OP_Info, 0x3, 0);

	// note: always returns 4 bytes, but most are garbage and unused.
	uint8_t tmp[4];
	ae_read_n(4, tmp);

	return tmp[0];
}

// ae_read_config_byte()
//
// Read a byte from config area.
//
    int
ae_read_config_byte(int offset)
{
	uint8_t tmp[4];

    ae_read_config_word(offset, tmp);
    // BUG: didnt check for failure, in which case we will return un-inited values

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
    ae_send(OP_Read, 0x00, offset/4);

	int rv = ae_read_n(4, dest);
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
    ae_send_n(OP_Nonce, 0, 0, numin, 20);

	// Nonce command returns the RNG result, not contents of TempKey,
    // but since we are destroying, no need to calculate what it is.
	uint8_t randout[32];
	int rv = ae_read_n(32, randout);
	RET_IF_BAD(rv);

    // do a "DeriveKey" operation, based on that!
	ae_send(OP_DeriveKey, 0x00, keynum);

    return ae_read1();
}

// ae_config_read()
//
    int 
ae_config_read(uint8_t config[128])
{
    for(int blk=0; blk<4; blk++) {
        // read 32 bytes (aligned) from config "zone"
        ae_send(OP_Read, 0x80, blk<<3);

        int rv = ae_read_n(32, &config[32*blk]);
        if(rv) return EIO;
    }

    return 0;
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
    // Need to wake up AE, since many things happen before this point.
    for(int retry=0; retry<5; retry++) {
        if(!ae_probe()) break;
    }

    // Is data zone is locked?
    // Allow rest of function to happen if it's not.

#if 1
    //  0x55 = unlocked; 0x00 = locked
    bool data_locked = (ae_read_config_byte(86) != 0x55);
    if(data_locked) return 0;       // basically success

    // Program the "config" area, and then lock it.

    // To lock, we need a CRC over whole thing, but we
    // only set a few values... plus the serial number is
    // in there, so start with some readout.
    uint8_t config[128];
    int rv = ae_config_read(config);
    if(rv) return rv;
#else
    // DEBUG
    uint8_t config[128];
    while(ae_config_read(config)) ;
#endif

    // verify some fixed values
    ASSERT(config[0] == 0x01);
    ASSERT(config[1] == 0x23);
    ASSERT(config[12] == 0xee);

    // guess part number: must be 608
    int8_t partno = ((config[6]>>4)&0xf);
    ASSERT(partno == 6);

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
    
    // will use zeros for all PIN codes, and customer-defined-secret starting values
    uint8_t     zeros[72];
    memset(zeros, 0, sizeof(zeros));

    // slots can already locked, if we re-run any of this code... can't overwrite in
    // that case.
    uint16_t unlocked = config[88] | (((uint8_t)config[89])<<8);

    for(int kn=0; kn<16; kn++) {
        ae_keep_alive();

        if(!(unlocked & (1<<kn))) {
            STATS(was_locked |= (1<<kn));
            continue;
        }

        switch(kn) {
            default:
            case 15: break;

            case KEYNUM_pairing:
                if(ae_write_data_slot(kn, rom_secrets->pairing_secret, 32, false)) {
                    INCONSISTENT("wr pair");
                }
                break;

            case KEYNUM_pin_stretch:
            case KEYNUM_pin_attempt: {
                    // HMAC-SHA256 key (forgotten immediately), for:
                    // - phishing words
                    // - each pin attempt (limited by counter0)
                    // - stretching pin/words attempts (iterated may times)
                    // See mathcheck.py for details.
                    uint8_t     tmp[32];

                    rng_buffer(tmp, sizeof(tmp));
                    //#warning "fixed secrets"
                    //memset(tmp, 0x41+kn, 32);

                    if(ae_write_data_slot(kn, tmp, 32, true)) {
                        INCONSISTENT("wr word");
                    }
                }
                break;

            case KEYNUM_main_pin:
            case KEYNUM_lastgood:
            case KEYNUM_firmware:
                if(ae_write_data_slot(kn, zeros, 32, false)) {
                    INCONSISTENT("wr blk 32");
                }
                break;

            case KEYNUM_secret:
            case KEYNUM_check_secret:
            case KEYNUM_spare_1:
            case KEYNUM_spare_2:
            case KEYNUM_spare_3:
                if(ae_write_data_slot(kn, zeros, 72, false)) {
                    INCONSISTENT("wr blk 72");
                }
                break;

            case KEYNUM_long_secret: {            // 416 bytes
                uint8_t long_zeros[416] = {0};
                if(ae_write_data_slot(kn, long_zeros, 416, false)) {
                    INCONSISTENT("wr blk 416");
                }
                break;
            }

            case KEYNUM_match_count: {
                uint32_t     buf[32/4] = { 1024, 1024 };
                if(ae_write_data_slot(KEYNUM_match_count, (const uint8_t *)buf,sizeof(buf),false)) {
                    INCONSISTENT("wr mc");
                }
                break;
            }

            case KEYNUM_joiner_key: {
                uint8_t     pubkey[64];

                // ? must prove we know the auth key (which is zeros, but still)
                if(ae_checkmac_hard(KEYNUM_main_pin, zeros) != 0) {
                    INCONSISTENT("ak");
                }

                // pick ECC keypair, lock it down, capture pubkey part
                if(ae_gen_ecc_key(KEYNUM_joiner_key, pubkey)) {
                    INCONSISTENT("kp");
                }

                // tell the SE2 part about that key, and apply it as the AUTH key C
                se2_save_auth_pubkey(pubkey);
                break;
            }

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


#if 0
// ae_write_match_count()
//
    int
ae_write_match_count(uint32_t count, const uint8_t *write_key)
{
    uint32_t     buf[8] = { count, count };

    // ASSERT(count & 31 == 0);                 // not clear, but probably should have 5LSB=0
    STATIC_ASSERT(sizeof(buf) == 32);           // limitation of ae_write_data_slot

    if(!write_key) {
        return ae_write_data_slot(KEYNUM_match_count, (const uint8_t *)buf, sizeof(buf), false);
    } else {
        return ae_encrypted_write32(KEYNUM_match_count, 0, KEYNUM_main_pin,
                                        write_key, (const uint8_t *)buf);
    }
}
#endif


// ae_stretch_iter()
//
// Do on-chip hashing, with lots of iterations.
//
// - using HMAC-SHA256 with keys that are known only to the 608a.
// - rate limiting factor here is communication time w/ 608a, not algos.
// - caution: result here is not confidential
// - cost of each iteration, approximately: 8ms
// - but our time to do each iteration is limited by software SHA256 in ae_pair_unlock
//
    int
ae_stretch_iter(const uint8_t start[32], uint8_t end[32], int iterations)
{
    ASSERT(start != end);           // we can't work inplace
    memcpy(end, start, 32);

    for(int i=0; i<iterations; i++) {
        // must unlock again, because pin_stretch is an auth'd key
        if(ae_pair_unlock()) return -2;

        int rv = ae_hmac32(KEYNUM_pin_stretch, end, end);
        RET_IF_BAD(rv);
    }

    return 0;
}

// ae_mixin_key()
//
// Apply HMAC using secret in chip as a HMAC key, then encrypt
// the result a little because read in clear over bus.
//
    int
ae_mixin_key(uint8_t keynum, const uint8_t start[32], uint8_t end[32])
{
    ASSERT(start != end);           // we can't work inplace

    if(ae_pair_unlock()) return -1;

    ASSERT(keynum != 0);
    int rv = ae_hmac32(keynum, start, end);
    RET_IF_BAD(rv);

    // Final value was just read over bus w/o any protection, but
    // we won't be using that, instead, mix in the pairing secret.
    //
    // Concern: what if mitm gave us some zeros or other known pattern here. We will
    // use the value provided in cleartext[sic--it's not] write back shortly (to test it).
    // Solution: one more SHA256, and to be safe, mixin lots of values!

	SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, rom_secrets->pairing_secret, 32);
    sha256_update(&ctx, start, 32);
    sha256_update(&ctx, &keynum, 1);
    sha256_update(&ctx, end, 32);
    sha256_final(&ctx, end);

    return 0;
}

// ae_brick_myself()
//
// Immediately destroy the pairing secret so that we become
// a useless brick. Ignore errors but retry.
//
    void
ae_brick_myself(void)
{
    for(int retry=0; retry<10; retry++) {
        ae_reset_chip();

        if(retry) rng_delay();

        ae_pair_unlock();

        // Concern: MitM could block this by trashing our write
        // - but they have to do it without causing CRC or other comm error
        // - ten times
        int rv = ae_destroy_key(KEYNUM_pairing);
        if(rv == 0) break;

        rng_delay();
    }

    ae_reset_chip();
}

// EOF
