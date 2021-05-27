/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * Implement a ram disk in PSRAM, accessibly by host as MSC and Mpy as block dev.
 *
 */
#include <stdint.h>

#include "usbd_cdc_msc_hid.h"
#include "usbd_msc_interface.h"
#include "usbd_cdc_msc_hid0.h"
#include "usbd_msc_bot.h"
#include "usbd_msc_scsi.h"
#include "usbd_ioreq.h"
#include "extmod/vfs.h"

// Our storage, in quad-serial SPI PSRAM chip
static uint8_t *PSRAM_BASE = (uint8_t *)0x90000000;    // OCTOSPI mapping
static const uint32_t PSRAM_SIZE = 0x800000;                 // 8 megs
static const uint32_t BLOCK_SIZE = 512;
static const uint32_t BLOCK_COUNT = 16384;     // =PSRAM_SIZE / BLOCK_SIZE

// This flag is needed to support removal of the medium, so that the USB drive
// can be unmounted and won't be remounted automatically.
#define FLAGS_STARTED (0x01)

#define FLAGS_READONLY (0x02)

STATIC const uint8_t psram_msc_lu_num = 1;
STATIC uint16_t psram_msc_lu_flags;

static inline void lu_flag_set(uint8_t lun, uint8_t flag) {
    psram_msc_lu_flags |= flag << (lun * 2);
}

static inline void lu_flag_clr(uint8_t lun, uint8_t flag) {
    psram_msc_lu_flags &= ~(flag << (lun * 2));
}

static inline bool lu_flag_is_set(uint8_t lun, uint8_t flag) {
    return psram_msc_lu_flags & (flag << (lun * 2));
}

// Sent in response to MODE SENSE(6) command
const uint8_t PSRAM_MSC_Mode_Sense6_Data[4] = {
    0x03, // mode data length
    0x00, // medium type
    0x00, // bit 7: write protect
    0x00, // block descriptor length
};

// Sent in response to MODE SENSE(10) command
const uint8_t PSRAM_MSC_Mode_Sense10_Data[8] = {
    0x00, 0x06, // mode data length
    0x00, // medium type
    0x00, // bit 7: write protect
    0x00,
    0x00,
    0x00, 0x00, // block descriptor length
};

STATIC const uint8_t psram_msc_vpd00[6] = {
    0x00, // peripheral qualifier; peripheral device type
    0x00, // page code
    0x00, // reserved
    2, // page length (additional bytes beyond this entry)
    0x00, // page 0x00 supported
    0x83, // page 0x83 supported
};

STATIC const uint8_t psram_msc_vpd83[4] = {
    0x00, // peripheral qualifier; peripheral device type
    0x83, // page code
    0x00, 0x00, // page length (additional bytes beyond this entry)
};

STATIC const int8_t psram_msc_inquiry_data[36] = {
    0x00, // peripheral qualifier; peripheral device type
    0x80, // 0x00 for a fixed drive, 0x80 for a removable drive
    0x02, // version
    0x02, // response data format
    (STANDARD_INQUIRY_DATA_LEN - 5), // additional length
    0x00, // various flags
    0x00, // various flags
    0x00, // various flags
    'M', 'i', 'c', 'r', 'o', 'P', 'y', ' ', // Manufacturer : 8 bytes
    'p', 'y', 'b', 'o', 'a', 'r', 'd', ' ', // Product      : 16 Bytes
    'F', 'l', 'a', 's', 'h', ' ', ' ', ' ',
    '1', '.', '0','0',                      // Version      : 4 Bytes
};

#if 0
// Set the logical units that will be exposed over MSC
void psram_msc_init_lu(size_t lu_n, const void *lu_data) {
    //psram_msc_lu_num = MIN(lu_n, USBD_MSC_MAX_LUN);
    //memcpy(psram_msc_lu_data, lu_data, sizeof(void *) * psram_msc_lu_num);
    psram_msc_lu_flags = 0;
}
#endif

// Helper function to perform an ioctl on a logical unit
STATIC int lu_ioctl(uint8_t lun, int op, uint32_t *data) {
    if (lun >= psram_msc_lu_num) {
        return -1;
    }
    mp_printf(&mp_plat_print, "PSRAMdisk: ioctl %d\n", op);

    switch (op) {
        case MP_BLOCKDEV_IOCTL_INIT:
            //storage_init();
            *data = 0;
            return 0;
        case MP_BLOCKDEV_IOCTL_SYNC:
            //storage_flush();
            return 0;
        case MP_BLOCKDEV_IOCTL_BLOCK_SIZE:
            *data = BLOCK_SIZE;
            return 0;
        case MP_BLOCKDEV_IOCTL_BLOCK_COUNT:
            *data = BLOCK_COUNT;
            return 0;
        default:
            return -1;
    }
}

// Initialise all logical units (it's only ever called once, with lun_in=0)
STATIC int8_t psram_msc_Init(uint8_t lun_in) {
    if (lun_in != 0) {
        return 0;
    }
    for (int lun = 0; lun < psram_msc_lu_num; ++lun) {
        uint32_t data = 0;
        int res = lu_ioctl(lun, MP_BLOCKDEV_IOCTL_INIT, &data);
        if (res != 0) {
            lu_flag_clr(lun, FLAGS_STARTED);
        } else {
            lu_flag_set(lun, FLAGS_STARTED);
            if (data) {
                lu_flag_set(lun, FLAGS_READONLY);
            }
        }
    }
    return 0;
}

// Process SCSI INQUIRY command for the logical unit
STATIC int psram_msc_Inquiry(uint8_t lun, const uint8_t *params, uint8_t *data_out) {
    if (params[1] & 1) {
        // EVPD set - return vital product data parameters
        uint8_t page_code = params[2];
        switch (page_code) {
            case 0x00: // Supported VPD pages
                memcpy(data_out, psram_msc_vpd00, sizeof(psram_msc_vpd00));
                return sizeof(psram_msc_vpd00);
            case 0x83: // Device identification
                memcpy(data_out, psram_msc_vpd83, sizeof(psram_msc_vpd83));
                return sizeof(psram_msc_vpd83);
            default: // Unsupported
                return -1;
        }
    }

    // A standard inquiry

    if (lun >= psram_msc_lu_num) {
        return -1;
    }

    uint8_t alloc_len = params[3] << 8 | params[4];
    int len = MIN(sizeof(psram_msc_inquiry_data), alloc_len);
    memcpy(data_out, psram_msc_inquiry_data, len);

    if (len == sizeof(psram_msc_inquiry_data)) {
        memcpy(data_out + 24, "PSRAMdisk", sizeof("PSRAMdisk") - 1);
    }

    return len;
}

// Get storage capacity of a logical unit
STATIC int8_t psram_msc_GetCapacity(uint8_t lun, uint32_t *block_num, uint16_t *block_size) {
    *block_num = BLOCK_COUNT;
    *block_size = BLOCK_SIZE;

    return 0;
#if 0
    uint32_t block_size_u32 = 0;
    int res = lu_ioctl(lun, MP_BLOCKDEV_IOCTL_BLOCK_SIZE, &block_size_u32);
    if (res != 0) {
        return -1;
    }
    *block_size = block_size_u32;
    return lu_ioctl(lun, MP_BLOCKDEV_IOCTL_BLOCK_COUNT, block_num);
#endif
}

// Check if a logical unit is ready
STATIC int8_t psram_msc_IsReady(uint8_t lun) {
    if (lun >= psram_msc_lu_num) {
        return -1;
    }
    return lu_flag_is_set(lun, FLAGS_STARTED) ? 0 : -1;
}

// Check if a logical unit is write protected
STATIC int8_t psram_msc_IsWriteProtected(uint8_t lun) {
    if (lun >= psram_msc_lu_num) {
        return -1;
    }
    return lu_flag_is_set(lun, FLAGS_READONLY) ? 1 : 0;
}

// Start or stop a logical unit
STATIC int8_t psram_msc_StartStopUnit(uint8_t lun, uint8_t started) {
    if (lun >= psram_msc_lu_num) {
        return -1;
    }
    if (started) {
        lu_flag_set(lun, FLAGS_STARTED);
    } else {
        lu_flag_clr(lun, FLAGS_STARTED);
    }
    return 0;
}

// Prepare a logical unit for possible removal
STATIC int8_t psram_msc_PreventAllowMediumRemoval(uint8_t lun, uint8_t param) {
    uint32_t dummy;
    // Sync the logical unit so the device can be unplugged/turned off
    return lu_ioctl(lun, MP_BLOCKDEV_IOCTL_SYNC, &dummy);
}

// Read data from a logical unit
STATIC int8_t psram_msc_Read(uint8_t lun, uint8_t *buf, uint32_t blk_addr, uint16_t blk_len) {
    if (lun >= psram_msc_lu_num) {
        return -1;
    }

    // TODO: tight range check

    memcpy(buf, &PSRAM_BASE[blk_addr*BLOCK_SIZE], blk_len*BLOCK_SIZE);

    return 0;
}

// Write data to a logical unit
STATIC int8_t psram_msc_Write(uint8_t lun, uint8_t *buf, uint32_t blk_addr, uint16_t blk_len) {
    if (lun >= psram_msc_lu_num) {
        return -1;
    }

    // TODO: tight range check

    memcpy(&PSRAM_BASE[blk_addr*BLOCK_SIZE], buf, blk_len*BLOCK_SIZE);

    return 0;
}

// Get the number of attached logical units
STATIC int8_t psram_msc_GetMaxLun(void) {
    return psram_msc_lu_num - 1;
}


// Table of operations for the SCSI layer to call
USBD_StorageTypeDef psramdisk_fops = {
    psram_msc_Init,
    psram_msc_Inquiry,
    psram_msc_GetCapacity,
    psram_msc_IsReady,
    psram_msc_IsWriteProtected,
    psram_msc_StartStopUnit,
    psram_msc_PreventAllowMediumRemoval,
    psram_msc_Read,
    psram_msc_Write,
    psram_msc_GetMaxLun,
};

void psramdisk_USBD_MSC_RegisterStorage(int num_lun, usbd_cdc_msc_hid_state_t *usbd) {
    // equiv to usbdev/class/inc/usbd_cdc_msc_hid.h
    usbd->MSC_BOT_ClassData.bdev_ops = &psramdisk_fops;
    mp_printf(&mp_plat_print, "PSRAMdisk: installed\n");
}

// EOF
