/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * sflash.c -- talk to the serial flash
 *
 */
#include "sflash.h"
#include <string.h>
#include "delay.h"
#include "stm32l4xx_hal.h"
#include "sigheader.h"
#include "verify.h"
#include "sha256.h"
#include "oled.h"
#include "dispatch.h"
#include "storage.h"
#include "gpio.h"
#include "assets/screens.h"

// Connections:
// - SPI2 port
// - all port B
//
// SF_CS   => PB9
// SF_SCLK => PB10
// SF_MISO => PC2
// SF_MOSI => PC3

#define SF_CS_PIN      GPIO_PIN_9       // port B
#define SF_SPI_SCK     GPIO_PIN_10      // port B
#define SF_SPI_MISO    GPIO_PIN_2       // port C
#define SF_SPI_MOSI    GPIO_PIN_3       // port C

#define CMD_WRSR        0x01
#define CMD_WRITE       0x02
#define CMD_READ        0x03
#define CMD_FAST_READ   0x0b
#define CMD_RDSR        0x05
#define CMD_WREN        0x06
#define CMD_SEC_ERASE   0x20
#define CMD_RDCR        0x35
#define CMD_RD_DEVID    0x9f
#define CMD_CHIP_ERASE  0xc7

// active-low chip-select line
#define CS_LOW()       HAL_GPIO_WritePin(GPIOB, SF_CS_PIN, 0)
#define CS_HIGH()      HAL_GPIO_WritePin(GPIOB, SF_CS_PIN, 1)

static SPI_HandleTypeDef   sf_spi_port;

uint32_t     sf_completed_upgrade;

// sf_read_bytes()
//
    static HAL_StatusTypeDef
sf_read(uint32_t addr, int len, uint8_t *buf)
{
    // send via SPI(1)
    uint8_t     pkt[5] = { CMD_FAST_READ,
                            (addr>>16) & 0xff, (addr >> 8) & 0xff, addr & 0xff,
                            0x0 };  // for fast-read case

    CS_LOW();

    HAL_StatusTypeDef rv = HAL_SPI_Transmit(&sf_spi_port, pkt, sizeof(pkt), HAL_MAX_DELAY);
    if(rv == HAL_OK) {
        rv = HAL_SPI_Receive(&sf_spi_port, buf, len, HAL_MAX_DELAY);
    }

    CS_HIGH();

    return rv;
}


// sf_wait_wip_done()
//
    static HAL_StatusTypeDef
sf_wait_wip_done()
{
    // read RDSR (status register) and busy-wait until 
    // the write operation is done
    while(1) {
        uint8_t pkt = CMD_RDSR, stat = 0;

        CS_LOW();

        HAL_StatusTypeDef rv = HAL_SPI_Transmit(&sf_spi_port, &pkt, 1, HAL_MAX_DELAY);

        if(rv == HAL_OK) {
            rv = HAL_SPI_Receive(&sf_spi_port, &stat, 1, HAL_MAX_DELAY);
        }

        CS_HIGH();

        if(rv != HAL_OK) return rv;

        if(stat & 0x01) continue;

        return HAL_OK;
    }
}

// sf_write_enable()
//
    static HAL_StatusTypeDef
sf_write_enable(void)
{
    uint8_t pkt = CMD_WREN;

    CS_LOW();

    HAL_StatusTypeDef rv = HAL_SPI_Transmit(&sf_spi_port, &pkt, 1, HAL_MAX_DELAY);

    CS_HIGH();

    return rv;
}

// sf_write()
//
    static HAL_StatusTypeDef
sf_write(uint32_t addr, int len, const uint8_t *buf)
{
    // enable writing
    HAL_StatusTypeDef rv = sf_write_enable();
    if(rv) return rv;

    // do a "PAGE Program" aka. write
    uint8_t     pkt[4] = { CMD_WRITE,
                            (addr>>16) & 0xff, (addr >> 8) & 0xff, addr & 0xff 
                        };

    CS_LOW();

    rv = HAL_SPI_Transmit(&sf_spi_port, pkt, sizeof(pkt), HAL_MAX_DELAY);
    if(rv == HAL_OK) {
        rv = HAL_SPI_Transmit(&sf_spi_port, (uint8_t *)buf, len, HAL_MAX_DELAY);
    }

    CS_HIGH();

    if(rv == HAL_OK) {
        rv = sf_wait_wip_done();
    }

    return rv;
}

#if 0
// sf_sector_erase()
//
// Erase 4k of data (smallest possible amount).
//
    static HAL_StatusTypeDef
sf_sector_erase(uint32_t addr)
{
    sf_write_enable();
/*
        self.cmd(CMD_SEC_ERASE, address)
    def is_busy(self):
        # return status of WIP = Write In Progress bit
        r = self.read_reg(CMD_RDSR, 1)
        return bool(r[0] & 0x01)
*/
}
#endif

// sf_setup()
//
// Ok to call this lots.
//
    void
sf_setup(void)
{
    HAL_StatusTypeDef rv;

    // enable some internal clocks
    __HAL_RCC_GPIOB_CLK_ENABLE();
    __HAL_RCC_GPIOC_CLK_ENABLE();
    __HAL_RCC_SPI2_CLK_ENABLE();

    // simple pins
    GPIO_InitTypeDef setup = {
        .Pin = SF_CS_PIN,
        .Mode = GPIO_MODE_OUTPUT_PP,
        .Pull = GPIO_NOPULL,
        .Speed = GPIO_SPEED_FREQ_MEDIUM,
        .Alternate = 0,
    };
    HAL_GPIO_Init(GPIOB, &setup);

    // starting value: high
    HAL_GPIO_WritePin(GPIOB, SF_CS_PIN, 1);

    // SPI pins, on various ports
    setup.Pin = SF_SPI_SCK;
    setup.Mode = GPIO_MODE_AF_PP;
    setup.Alternate = GPIO_AF5_SPI2;
    HAL_GPIO_Init(GPIOB, &setup);

    setup.Pin = SF_SPI_MOSI | SF_SPI_MISO;
    HAL_GPIO_Init(GPIOC, &setup);

    memset(&sf_spi_port, 0, sizeof(sf_spi_port));

    sf_spi_port.Instance = SPI2;

    // see SPI_InitTypeDef
    sf_spi_port.Init.Mode = SPI_MODE_MASTER;
    sf_spi_port.Init.Direction = SPI_DIRECTION_2LINES;
    sf_spi_port.Init.DataSize = SPI_DATASIZE_8BIT;
    sf_spi_port.Init.CLKPolarity = SPI_POLARITY_LOW;
    sf_spi_port.Init.CLKPhase = SPI_PHASE_1EDGE;
    sf_spi_port.Init.NSS = SPI_NSS_SOFT;
    sf_spi_port.Init.BaudRatePrescaler = SPI_BAUDRATEPRESCALER_16;    // conservative
    sf_spi_port.Init.FirstBit = SPI_FIRSTBIT_MSB;
    sf_spi_port.Init.TIMode = SPI_TIMODE_DISABLED;
    sf_spi_port.Init.CRCCalculation = SPI_CRCCALCULATION_DISABLED;

    rv = HAL_SPI_Init(&sf_spi_port);
    ASSERT(!rv);
}

// sf_do_upgrade()
//
// Copy from SPI flash to real flash, at final executable location.
//
    static void
sf_do_upgrade(uint32_t size)
{
    ASSERT(size >= FW_MIN_LENGTH);

    flash_setup0();
    flash_unlock();

    uint8_t     tmp[256] __attribute__((aligned(8)));

    for(uint32_t pos=0; pos<size; pos += sizeof(tmp)) {
        // show some progress
        if((pos % 4096) == 0) {
            oled_show_progress(screen_upgrading, pos*100/size);
        }

        if(sf_read(pos, sizeof(tmp), tmp) != HAL_OK) {
            INCONSISTENT();
        }

        uint32_t addr = FIRMWARE_START + pos;
        uint64_t *b = (uint64_t *)tmp;

        for(int i=0; i<sizeof(tmp)/sizeof(uint64_t); i++) {
            int rv;

            if(addr % FLASH_PAGE_SIZE == 0) {
                rv = flash_page_erase(addr);
                ASSERT(rv == 0);
            }

            rv = flash_burn(addr, *(b++));
            ASSERT(rv == 0);
            addr += sizeof(uint64_t);
        }

        if(dfu_button_pressed() && !flash_is_security_level2()) {
            flash_lock();

            dfu_by_request();
            // NOT-REACHED
        }
    }

    flash_lock();
}

// sf_calc_checksum()
//
// Do double-sha256 of the contents of the firmware upgrade, presently
// in SPI flash. Similar to checksum_flash() in verify.c except only
// concerned with firmware, not the rest of flash.
//
    void
sf_calc_checksum(const coldcardFirmwareHeader_t *hdr, uint8_t fw_digest[32])
{

    SHA256_CTX  ctx;
    uint32_t    total_len = hdr->firmware_length;

    sha256_init(&ctx);

    uint32_t pos = 0;
    uint8_t buf[128];
    STATIC_ASSERT(FW_HEADER_OFFSET % sizeof(buf) == 0);

    oled_show_progress(screen_verify, 1);

    // do part up to header.
    for(; pos < FW_HEADER_OFFSET; pos += sizeof(buf)) { 
        if(sf_read(pos, sizeof(buf), buf) != HAL_OK) {
        fail:
            // fail for sure with bad signature; user can try again
            memset(fw_digest, 0, 32);
            return;
        }

        sha256_update(&ctx, buf, sizeof(buf));
    }

    // include file header (but not the signature)
    ASSERT(pos == FW_HEADER_OFFSET);
    sha256_update(&ctx, (const uint8_t *)hdr, FW_HEADER_SIZE - 64);

    // then the rest after the 'header' ... the useful firmware
    pos += FW_HEADER_SIZE;

    for(int count=0; pos < total_len; pos += sizeof(buf), count++) { 
        if(sf_read(pos, sizeof(buf), buf) != HAL_OK) {
            goto fail;
        }
        sha256_update(&ctx, buf, sizeof(buf));

        if((count % 16) == 0) {
            int percent = (pos * 100) / total_len;
            oled_show_progress(screen_verify, percent);
        }
    }

    ASSERT(pos == hdr->firmware_length);

    sha256_final(&ctx, fw_digest);

    // double SHA256
    sha256_init(&ctx);
    sha256_update(&ctx, fw_digest, 32);
    sha256_final(&ctx, fw_digest);
}

// sf_firmware_upgrade()
//
// maybe upgrade to a firmware image found in sflash
//
    void
sf_firmware_upgrade(void)
{
    coldcardFirmwareHeader_t    hdr = {};

    // simple: just read in right spot to see header.
    sf_setup();

    if(sf_read(FW_HEADER_OFFSET, sizeof(hdr), (void *)&hdr) != HAL_OK) {
        // hardware issues, keep going
        return;
    }

    if(!verify_header(&hdr)) {
        // something wrong with it. might be noise, blank or otherwise. Not an error.
        return;
    }

    // We have a good header so we can assume whole file there properly, right? (We could
    // check the signature first, but would be super slow.) And yet,
    // if you unpluged during the 'upload' process, after first part written, but before
    // you get to the end, we'd be bricked. Plus that seems really likely to happen.
    //
    // Solution: Look for a duplicated header at end of file. Will always write that last,
    // and even do a checksum over the data uploaded into the sflash before writing final
    // header out.
    // 
    uint32_t off = hdr.firmware_length;

    coldcardFirmwareHeader_t    hdr2 = {};
    if(sf_read(off, sizeof(hdr2), (void *)&hdr2) != HAL_OK) {
        // Huh??? Hardware issue?
        return;
    }

    if(memcmp(&hdr, &hdr2, sizeof(hdr)) != 0) {
        // mismatch? -- erase stuff to recover? Or just leave it?
        return;
    }

    // We might upgrade now ... but only want to try once, so wipe the
    // second header to assure that we won't get stuck in an upgrade loop.
    //
    // LATER: if they unplug power part way thru, they land in fully-bricked mode,
    // even tho we have enough data (from SPI) to complete upgrade successfully.
    // So only clear flash once we've comlpeted successfully, or determined it
    // cannot work (bad signature, etc).

    // Check for downgrade attack: show warning and stop.
    if(check_is_downgrade(hdr.timestamp, (const char *)hdr.version_string)) {
        oled_show(screen_downgrade);

    fail:{
            // prevent second attempts. pointless
            uint8_t zeros[128] = { 0 };
            sf_write(off, sizeof(zeros), zeros);
        }

        LOCKUP_FOREVER();
    }

    // Check the firmware signature before changing main flash at all.
    uint8_t fw_digest[32];
    sf_calc_checksum(&hdr, fw_digest);

    bool ok = verify_signature(&hdr, fw_digest);
    if(!ok) {
        // Bad signature over SPI contents; might be corruption or bad signature
        // We would not run the resulting firmware in main flash, so don't erase
        // what we have there now and abort.
        oled_show(screen_corrupt);

        goto fail;
    }

    // Start the upgrade ... takes about a minute.
    sf_do_upgrade(hdr.firmware_length);

    if(hdr.install_flags & FWHIF_HIGH_WATER) {
        // Maybe set a new high-waterlevel for future versions.
        // Ignore failures, since we can't recover anyway.
        record_highwater_version(hdr.timestamp);
    }

    // We're done, so clear header 
    uint8_t zeros[128] = { 0 };
    sf_write(off, sizeof(zeros), zeros);

    // Tell python, ultimately, that it worked.
    sf_completed_upgrade = SF_COMPLETED_UPGRADE;
}

// EOF
