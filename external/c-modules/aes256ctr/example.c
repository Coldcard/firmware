// from https://raw.githubusercontent.com/Ko-/aes-armcortexm/public/aes256ctr/aes_256_ctr.c
// taken Feb 25/2021
// REFERENCE ONLY -- not used.
#include "../common/stm32wrapper.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct param {
    uint32_t ctr;
    uint8_t nonce[12];
    uint8_t rk[15*16];
} param;

extern void AES_256_keyschedule(const uint8_t *, uint8_t *);
extern void AES_256_encrypt_ctr(param const *, const uint8_t *, uint8_t *, uint32_t);
#define AES_256_decrypt_ctr AES_256_encrypt_ctr

int main(void)
{
    clock_setup();
    gpio_setup();
    usart_setup(115200);

    // plainly reading from CYCCNT is more efficient than using the
    // dwt_read_cycle_counter() interface offered by libopencm3,
    // as this adds extra overhead because of the function call

    SCS_DEMCR |= SCS_DEMCR_TRCENA;
    DWT_CYCCNT = 0;
    DWT_CTRL |= DWT_CTRL_CYCCNTENA;

    const uint32_t LEN = 256*16;
    const uint32_t LEN_ROUNDED = ((LEN+15)/16)*16;

    const uint8_t nonce[12] = {1,2,3,1,2,4,1,2,5,1,2,6};
    const uint8_t key[32] = {4,5,6,7,4,5,6,8,4,5,6,9,4,5,6,10,4,5,6,11,4,5,6,12,4,5,6,13,4,5,6,14};
    uint8_t in[LEN];
    uint8_t out[LEN_ROUNDED];

    unsigned int i;
    for(i=0;i<LEN;++i)
        in[i] = i%256;

    char buffer[36];
    param p;
    p.ctr = 0;
    memcpy(p.nonce, nonce, 12);
    memcpy(p.rk, key, 32);

    unsigned int oldcount = DWT_CYCCNT;
    AES_256_keyschedule(key, p.rk+32);
    unsigned int cyclecount = DWT_CYCCNT-oldcount;

/*
    // Print all round keys
    unsigned int j;
    for(i=0;i<15*4;++i) {
        sprintf(buffer, "rk[%2d]: ", i);
        for(j=0;j<4;++j)
            sprintf(buffer+2*j+8, "%02x", p.rk[i*4+j]);
        send_USART_str(buffer);
    }
*/

    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);

    oldcount = DWT_CYCCNT;
    AES_256_encrypt_ctr(&p, in, out, LEN);
    cyclecount = DWT_CYCCNT-oldcount;

    sprintf(buffer, "cyc: %d", cyclecount);
    send_USART_str(buffer);

/*
    // Print ciphertext
    sprintf(buffer, "out: ");
    send_USART_str(buffer);
    for(i=0;i<LEN;++i) {
        sprintf(buffer+((2*i)%32), "%02x", out[i]);
        if(i%16 == 15)
            send_USART_str(buffer);
    }
    if(LEN%16 > 0)
        send_USART_str(buffer);
*/

/*
    // Perform decryption
    p.ctr = 0;

    AES_256_decrypt_ctr(&p, out, in, LEN);

    // Print plaintext
    sprintf(buffer, "in: ");
    send_USART_str(buffer);
    for(i=0;i<LEN;++i) {
        sprintf(buffer+((2*i)%32), "%02x", in[i]);
        if(i%16 == 15)
            send_USART_str(buffer);
    }
    if(LEN%16 > 0)
        send_USART_str(buffer);
*/

    while (1);

    return 0;
}
