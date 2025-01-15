/*
 * (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 *
 * Implement a ram disk in PSRAM, accessible by host as MSC and mpy as block dev.
 *
 */
#include <stdint.h>

#include "usbd_cdc_msc_hid.h"
#include "usbd_msc_interface.h"
#include "usbd_cdc_msc_hid0.h"
#include "usbd_msc_bot.h"
#include "usbd_msc_scsi.h"
#include "usbd_ioreq.h"
#include "py/gc.h"
#include "py/mphal.h"
#include "py/runtime.h"
#include "extmod/vfs.h"
#include "extmod/vfs_fat.h"
#include "lib/oofatfs/ff.h"
#include "py/runtime.h"
#include "py/mperrno.h"
#include "softtimer.h"
#include "ulight.h"

// Our storage, in quad-serial SPI PSRAM chip
// - using top half of chip only
static uint8_t *PSRAM_TOP_BASE = (uint8_t *)0x90400000;    // OCTOSPI mapping, top half
static uint8_t *PSRAM_BOT_BASE = (uint8_t *)0x90000000;    // OCTOSPI mapping, bot half
static const uint32_t PSRAM_SIZE = 0x400000;           // 4 megs (half)
static const uint32_t BLOCK_SIZE = 512;
static const uint32_t BLOCK_COUNT = PSRAM_SIZE / BLOCK_SIZE;    // = 8192

extern __IO uint32_t uwTick;

// this code will always be the first LUN
static const uint8_t MY_LUN = 0;

STATIC mp_obj_t psram_wipe_and_setup(mp_obj_t unused_self);
STATIC const uint8_t psram_msc_lu_num = 1;

typedef struct _psram_obj_t {
    mp_obj_base_t base;

    uint32_t        host_write_time;
} psram_obj_t;

// singleton
const mp_obj_type_t psram_type;
psram_obj_t psram_obj = {
    { &psram_type },
};

#define HOST_WR_TIMEOUT     750            // (ms)
static soft_timer_entry_t  host_wr_done;

// we only have a single LUN, so flags can be simple
// - note that "started" is more like inserted vs. ejected
bool flag_STARTED = false;
bool flag_READONLY = false;

// psram_init()
//
    void
psram_init(void)
{
    // always clear and reset contents
    psram_wipe_and_setup(NULL);

    //mp_pairheap_t pairheap;
    host_wr_done.mode = SOFT_TIMER_MODE_ONE_SHOT;
    host_wr_done.expiry_ms = HOST_WR_TIMEOUT;
    host_wr_done.callback = MP_ROM_NONE;
    host_wr_done.pairheap.base.type = &psram_type;      // callback gets this object as only arg
}

// reset_wr_timeout()
//
    static void
reset_wr_timeout(void)
{
    // host has written something, reset/set a timeout to look at new change,
    // assuming more is not written before the timeout expires.

    soft_timer_remove(&host_wr_done);

    psram_obj.host_write_time = uwTick;

    if(host_wr_done.callback != MP_ROM_NONE) {
        host_wr_done.expiry_ms = uwTick + HOST_WR_TIMEOUT;
        soft_timer_insert(&host_wr_done);
    }
}

// wr_timeout_now()
//
    static void
wr_timeout_now(void)
{
    // host did something that indicates it won't be writing anymore to
    // the disk, and therefore ok to immediately look at contents.

    soft_timer_remove(&host_wr_done);

    psram_obj.host_write_time = uwTick;

    if(host_wr_done.callback != MP_ROM_NONE) {
        mp_sched_schedule(host_wr_done.callback, MP_OBJ_FROM_PTR(&psram_obj));
    }
}

// block_to_ptr()
//
    static uint8_t *
block_to_ptr(uint32_t blk, uint16_t num_blk)
{
    // Range checking on incoming requests also done in SCSI_CheckAddressRange()
    // but this is an extra layer of safety, important since we might expose
    // our address space otherwise!
    // - note unsigned arguments

    if(blk >= BLOCK_COUNT) return NULL;
    if((blk+num_blk) > BLOCK_COUNT) return NULL;

    return &PSRAM_TOP_BASE[blk * BLOCK_SIZE];
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
    'C', 'o', 'i', 'n', 'k', 'i', 't', 'e', // Manufacturer : 8 bytes
    'C', 'O', 'L', 'D', 'C', 'A', 'R', 'D', // Product      : 16 Bytes
    ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ',
    '4', '.', '0','0',                      // Version      : 4 Bytes
};

// Initialise all logical units (it's only ever called once, with lun_in=0)
STATIC int8_t psram_msc_Init(uint8_t lun_in)
{
    if(lun_in != MY_LUN) return -1;

    // don't change flag here, might have been set by python
    //flags_STARTED = false;
    //flags_READONLY = false;

    return 0;
}

// Process SCSI INQUIRY command for the logical unit
STATIC int psram_msc_Inquiry(uint8_t lun, const uint8_t *params, uint8_t *data_out)
{
    if(lun != MY_LUN) return -1;

    ckcc_usb_active = true;

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
    uint16_t alloc_len = params[3] << 8 | params[4];
    int len = MIN(sizeof(psram_msc_inquiry_data), alloc_len);
    memcpy(data_out, psram_msc_inquiry_data, len);

    return len;
}

// Get storage capacity of a logical unit
STATIC int8_t psram_msc_GetCapacity(uint8_t lun, uint32_t *block_num, uint16_t *block_size)
{
    // might be important not to write to pointers if unexpected LUN
    if(lun != MY_LUN) return -1;

    ckcc_usb_active = true;

    *block_num = BLOCK_COUNT;
    *block_size = BLOCK_SIZE;

    return 0;
}

// Check if a logical unit is ready
STATIC int8_t psram_msc_IsReady(uint8_t lun)
{
    if(lun != MY_LUN) return -1;

    // NOTE: called frequently, and must be T for MacOS to recognize at all
    // when F, macos keeps trying to work until it's ready again (freezing programs
    // trying to work with the drive).
    return flag_STARTED ? 0 : -1;
}

// Check if a logical unit is write protected
STATIC int8_t psram_msc_IsWriteProtected(uint8_t lun)
{
    if(lun != MY_LUN) return -1;

    return flag_READONLY ? 1 : 0;
}

// Start or stop a logical unit
STATIC int8_t psram_msc_StartStopUnit(uint8_t lun, uint8_t started)
{
    if(lun != MY_LUN) return -1;

    // host is not allowed to change our ready status: always fail
    //printf("PSRAMdisk: started=%d tried\n", started);
    ckcc_usb_active = true;

    if(!started) {
        // (macos) is trying to "eject" the disk. Note this event.
        wr_timeout_now();
    }

    return -1;
#if 0
    if (started) {
        flag_STARTED = true;
        ckcc_usb_active = true;
    } else {
        flag_STARTED = false;
    }
    return 0;
#endif
}

// Prepare a logical unit for possible removal
STATIC int8_t psram_msc_PreventAllowMediumRemoval(uint8_t lun, uint8_t param)
{
    if(lun != MY_LUN) return -1;

    //printf("PSRAMdisk: prevallow=%d\n", param);
    if(param == 0) {
        // allow removal == host is done (like after umount in MacOS)
        wr_timeout_now();
    }

    return 0;
}

// Read data from a logical unit
STATIC int8_t psram_msc_Read(uint8_t lun, uint8_t *buf, uint32_t blk_addr, uint16_t blk_len)
{
    if(lun != MY_LUN) return -1;

    ckcc_usb_active = true;

    uint8_t *ptr = block_to_ptr(blk_addr, blk_len);
    if(!ptr) return -1;

    memcpy(buf, ptr, blk_len*BLOCK_SIZE);

    return 0;
}

// Write data to a logical unit
STATIC int8_t psram_msc_Write(uint8_t lun, uint8_t *buf, uint32_t blk_addr, uint16_t blk_len)
{
    if(lun != MY_LUN) return -1;

    ckcc_usb_active = true;

    uint8_t *ptr = block_to_ptr(blk_addr, blk_len);
    if(!ptr) return -1;

    memcpy(ptr, buf, blk_len*BLOCK_SIZE);

    reset_wr_timeout();

    return 0;
}

// Get the number of attached logical units
STATIC int8_t psram_msc_GetMaxLun(void) {
    ckcc_usb_active = true;

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
    //mp_printf(&mp_plat_print, "PSRAMdisk: activated\n");
}

//
// mpy user interface: os.AbstractBlockDev interface
//
// see <https://docs.micropython.org/en/latest/library/uos.html#simple-and-extended-interface>
//


STATIC void psram_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    mp_printf(print, "PSRAM()");
}

STATIC mp_obj_t psram_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *all_args) {
    // Parse arguments: none allowed
    mp_arg_parse_all_kw_array(n_args, n_kw, all_args, 0, NULL, NULL);

    // singleton, we take no args
    return MP_OBJ_FROM_PTR(&psram_obj);
}

STATIC mp_obj_t psram_readblocks(size_t n_args, const mp_obj_t *args) {
    //psram_obj_t *self = MP_OBJ_TO_PTR(args[0]);
    uint32_t block_num = mp_obj_get_int(args[1]);

    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[2], &bufinfo, MP_BUFFER_WRITE);

    // Full range check; not supporting partial blocks nor offsets
    uint16_t blk_len = bufinfo.len / BLOCK_SIZE;
    if(blk_len < 1) goto fail;
    if((blk_len * BLOCK_SIZE) != bufinfo.len) goto fail;

    uint8_t *ptr = block_to_ptr(block_num, blk_len);
    if(!ptr) goto fail;

    memcpy(bufinfo.buf, ptr, bufinfo.len);

    return MP_OBJ_NEW_SMALL_INT(0);
fail:
    mp_raise_ValueError(NULL);
    return mp_const_none;                   // not reached
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(psram_readblocks_obj, 3, 3, psram_readblocks);

STATIC mp_obj_t psram_writeblocks(size_t n_args, const mp_obj_t *args) {
    //psram_obj_t *self = MP_OBJ_TO_PTR(args[0]);
    uint32_t block_num = mp_obj_get_int(args[1]);

    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(args[2], &bufinfo, MP_BUFFER_READ);

    // Full range check; not supporting partial blocks nor offsets
    uint16_t blk_len = bufinfo.len / BLOCK_SIZE;
    if(blk_len < 1) goto fail;
    if((blk_len * BLOCK_SIZE) != bufinfo.len) goto fail;

    uint8_t *ptr = block_to_ptr(block_num, blk_len);
    if(!ptr) goto fail;

    memcpy(ptr, bufinfo.buf, bufinfo.len);

    return MP_OBJ_NEW_SMALL_INT(0);
fail:
    mp_raise_ValueError(NULL);
    return mp_const_none;                   // not reached
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(psram_writeblocks_obj, 3, 3, psram_writeblocks);

int direct_psram_read_blocks(uint8_t *dest, uint32_t block_num, uint32_t num_blocks) {
    // Return zero or -MP_EIO
    uint8_t *ptr = block_to_ptr(block_num, num_blocks);
    if(!ptr) return -MP_EIO;

    memcpy(dest, ptr, num_blocks * BLOCK_SIZE);

    return 0;
}
int direct_psram_write_blocks(const uint8_t *src, uint32_t block_num, uint32_t num_blocks) {
    // Return zero or -MP_EIO
    uint8_t *ptr = block_to_ptr(block_num, num_blocks);
    if(!ptr) return -MP_EIO;

    memcpy(ptr, src, num_blocks * BLOCK_SIZE);

    // Need some recovery time here for PSRAM or QUADSPI module. Otherwise, lockup!
    asm("nop");
    asm("nop");
    asm("nop");
    asm("nop");

    return 0;
}

STATIC mp_obj_t psram_ioctl(mp_obj_t self_in, mp_obj_t cmd_in, mp_obj_t arg_in) {
    //psram_obj_t *self = MP_OBJ_TO_PTR(self_in);
    mp_int_t cmd = mp_obj_get_int(cmd_in);

    switch (cmd) {
        case MP_BLOCKDEV_IOCTL_SYNC:
            // umount() called; CC done w/ filesystem
            return MP_OBJ_NEW_SMALL_INT(0);

        case MP_BLOCKDEV_IOCTL_INIT:            // when mount() happens (even R/O)
        case MP_BLOCKDEV_IOCTL_DEINIT:          // not observed
            // nothing to do
            return MP_OBJ_NEW_SMALL_INT(0);

        case MP_BLOCKDEV_IOCTL_BLOCK_COUNT:
            return MP_OBJ_NEW_SMALL_INT(BLOCK_COUNT);

        case MP_BLOCKDEV_IOCTL_BLOCK_SIZE:
            return MP_OBJ_NEW_SMALL_INT(BLOCK_SIZE);

        case MP_BLOCKDEV_IOCTL_BLOCK_ERASE: {
            mp_int_t block_num = mp_obj_get_int(arg_in);

            uint8_t *ptr = block_to_ptr(block_num, 1);
            if(!ptr) return mp_const_none;

            memset(ptr, 0xff, BLOCK_SIZE);

            return MP_OBJ_NEW_SMALL_INT(0);
        }

        default:
            return mp_const_none;
    }
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(psram_ioctl_obj, psram_ioctl);

static void psram_init_vfs(fs_user_mount_t *vfs, bool readonly) {
    // Simulates mounting the block device into VFS system. Assumes FAT format.
    vfs->base.type = &mp_fat_vfs_type;
    vfs->blockdev.flags |= MP_BLOCKDEV_FLAG_NATIVE | MP_BLOCKDEV_FLAG_HAVE_IOCTL;

    vfs->fatfs.drv = vfs;
    vfs->fatfs.part = 0; // no partions; we have no MBR, like a floppy
    vfs->blockdev.readblocks[0] = MP_OBJ_FROM_PTR(&psram_readblocks_obj);
    vfs->blockdev.readblocks[1] = MP_OBJ_FROM_PTR(&psram_obj);
    vfs->blockdev.readblocks[2] = MP_OBJ_FROM_PTR(direct_psram_read_blocks);
    if(!readonly) {
        vfs->blockdev.writeblocks[0] = MP_OBJ_FROM_PTR(&psram_writeblocks_obj);
        vfs->blockdev.writeblocks[1] = MP_OBJ_FROM_PTR(&psram_obj);
        vfs->blockdev.writeblocks[2] = MP_OBJ_FROM_PTR(direct_psram_write_blocks);
    }
    vfs->blockdev.u.ioctl[0] = MP_OBJ_FROM_PTR(&psram_ioctl_obj);
    vfs->blockdev.u.ioctl[1] = MP_OBJ_FROM_PTR(&psram_obj);
}

// psram_memset4()
//
    static void
psram_memset4(void *dest_addr, uint32_t byte_len)
{
    // Fast, aligned, and bug-fixing memset
    // - PSRAM can starve the internal bus with too many writes, too fast
    // - leads to a weird crash where SRAM bus (at least) is locked up, but flash works
    // - and/or just call w/ interrupts off for reliable non-crashing behaviour
    uint32_t *dest = (uint32_t *)dest_addr;

    for(; byte_len; byte_len-=4, dest++) {
        *dest = 0x12345678;
    }
}

// mp_obj_t psram_wipe_and_setup()
//
mp_obj_t psram_wipe_and_setup(mp_obj_t unused_self)
{
    // Erase and reformat filesystem
    //  - you probably should unmount it, before calling this 

    // Wipe contents for security.
    mp_uint_t before = disable_irq();
        psram_memset4(PSRAM_TOP_BASE, BLOCK_SIZE * BLOCK_COUNT);
    enable_irq(before);

    // Build obj to handle blockdev protocol
    fs_user_mount_t vfs = {0};
    psram_init_vfs(&vfs, false);

    // newfs:
    // - FAT16 (auto)
    // - cluster=sector=512 to keep it simple
    // - FM_SFD=>start sector=0, not 63 "single partition" no MBR wastage
    uint8_t working_buf[FF_MAX_SS];
    FRESULT res = f_mkfs(&vfs.fatfs, FM_FAT|FM_SFD, BLOCK_SIZE, working_buf, sizeof(working_buf));
    if (res != FR_OK) {
        //mp_printf(&mp_plat_print, "PSRAM: can't create filesystem\n");
        goto fail;
    }

    // set volume label, which becomes mountpoint on MacOS
    // .. can't do this from python AFAIK
    f_setlabel(&vfs.fatfs, "COLDCARD");
    f_mkdir(&vfs.fatfs, "ident");

    FIL fp;
    UINT n;

    // create an ident file, or two
    // - algo matches shared/version.py serial_number() function
    {   char    fname[80];
        const uint8_t *id = (const uint8_t *)MP_HAL_UNIQUE_ID_ADDRESS;     // 12 bytes, binary
        snprintf(fname, sizeof(fname),
                "ident/ckcc-%02X%02X%02X%02X%02X%02X.txt",
                id[11], id[10] + id[2], id[9], id[8] + id[0], id[7], id[6]);
        const char *serial = &fname[11];

        f_open(&vfs.fatfs, &fp, fname, FA_WRITE | FA_CREATE_ALWAYS);
        f_write(&fp, serial, 12, &n);
        f_write(&fp, "\r\n", 2, &n);
        f_close(&fp);

        f_open(&vfs.fatfs, &fp, "ident/serial.txt", FA_WRITE | FA_CREATE_ALWAYS);
        f_write(&fp, serial, 12, &n);
        f_write(&fp, "\r\n", 2, &n);
        f_close(&fp);
    }

    return mp_const_none;

fail:
    mp_raise_ValueError(NULL);
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(psram_wipe_obj, psram_wipe_and_setup);

// copy from lib/oofatfs/ff.c
static DWORD clst2sect (    /* !=0:Sector number, 0:Failed (invalid cluster#) */
    FATFS* fs,      /* Filesystem object */
    DWORD clst      /* Cluster# to be converted */
)
{
    clst -= 2;      /* Cluster number is origin from 2 */
    if (clst >= fs->n_fatent - 2) return 0;     /* Is it invalid cluster number? */
    return fs->database + fs->csize * clst;     /* Start sector number of the cluster */
}


mp_obj_t psram_mmap_file(mp_obj_t unused_self, mp_obj_t fname_in)
{
    // Find a file inside a FATFS and return a list of tuples which
    // provide the physical locations/lengths of the bytes of the
    // file's contents. Effectively it's the mmap call.
    // - file path must be striped of mountpt
    const char *fname = mp_obj_str_get_str(fname_in);

    // Build obj to handle python protocol
    fs_user_mount_t vfs = {0};
    psram_init_vfs(&vfs, true);

    FRESULT res = f_mount(&vfs.fatfs);
    if (res != FR_OK) {
        mp_raise_ValueError(MP_ERROR_TEXT("unmountable"));
    }

    // open the file directly
    FIL fp = {0};
    if(f_open(&vfs.fatfs, &fp, fname, FA_READ) != FR_OK) {
        mp_raise_ValueError(MP_ERROR_TEXT("file no open"));
    }

    // see <http://elm-chan.org/fsw/ff/doc/lseek.html> to learn this magic
    DWORD   mapping[64];
    mapping[0] = MP_ARRAY_SIZE(mapping);
    fp.cltbl = mapping;

    int rv = f_lseek(&fp, CREATE_LINKMAP);
    if(rv != FR_OK) {
        mp_raise_ValueError(MP_ERROR_TEXT("lseek"));
    }

    // Convert and remap list of clusters

    // import ckcc; ckcc.PSRAM().mmap('serial.txt')
    
    int num_used = (mapping[0] - 1) / 2;
    if((num_used < 1) || (num_used >= MP_ARRAY_SIZE(mapping))) {
        mp_raise_ValueError(NULL);
    }
    DWORD *ptr = &mapping[1];

    mp_obj_t    tups[num_used];

    uint32_t so_far = 0;
    for(int i=0; i<num_used; i++) {
        int num_clusters = *(ptr++);
        uint32_t cluster = *(ptr++);

        uint8_t *spot = block_to_ptr(clst2sect(&vfs.fatfs, cluster), num_clusters);
        if(!spot) {
            //printf("[%d] (cl=0x%lx ln=%d) => ", i, cluster, num_clusters);
            //printf("0x%lx\n", clst2sect(&vfs.fatfs, cluster));
            mp_raise_ValueError(MP_ERROR_TEXT("clstfck"));
        }
        uint32_t len = num_clusters*BLOCK_SIZE;

        if(i == num_used-1) {
            // final cluster might include some bytes past the EOF
            len = fp.obj.objsize - so_far;
        } else {
            so_far += len;
        }

        mp_obj_t    here[2] = { 
            mp_obj_new_int_from_uint((uint32_t)spot),
            MP_OBJ_NEW_SMALL_INT(len)
        };

        tups[i] = mp_obj_new_tuple(2, here);

    }
    f_close(&fp);

    return mp_obj_new_list(num_used, tups);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(psram_mmap_file_obj, psram_mmap_file);

mp_obj_t psram_copy_file(mp_obj_t unused_self, mp_obj_t offset_in, mp_obj_t fname_in)
{
    // Find a file inside a FATFS and copy it into another area of PSRAM.
    // - file path must be striped of mountpt
    uint32_t    offset = mp_obj_get_int(offset_in);         // checks below
    const char *fname = mp_obj_str_get_str(fname_in);

    // Build obj to handle python protocol
    fs_user_mount_t vfs = {0};
    psram_init_vfs(&vfs, true);

    FRESULT res = f_mount(&vfs.fatfs);
    if (res != FR_OK) {
        mp_raise_ValueError(MP_ERROR_TEXT("unmountable"));
    }

    // open the file directly
    FIL fp = {0};
    if(f_open(&vfs.fatfs, &fp, fname, FA_READ) != FR_OK) {
        mp_raise_ValueError(MP_ERROR_TEXT("file no open"));
    }

    // see <http://elm-chan.org/fsw/ff/doc/lseek.html> to learn this magic
    DWORD   mapping[64];
    mapping[0] = MP_ARRAY_SIZE(mapping);
    fp.cltbl = mapping;

    int rv = f_lseek(&fp, CREATE_LINKMAP);
    if(rv != FR_OK) {
        mp_raise_ValueError(MP_ERROR_TEXT("lseek"));
    }

    // Convert and remap list of clusters
    
    int num_used = (mapping[0] - 1) / 2;
    if((num_used < 1) || (num_used >= MP_ARRAY_SIZE(mapping))) {
        mp_raise_ValueError(NULL);
    }

    uint32_t actual_len = fp.obj.objsize;

    // where we will put copy
    uint8_t     *dest = PSRAM_BOT_BASE + offset;
    if(offset % 4) mp_raise_ValueError(NULL);
    if(((uint32_t)dest) % 4) mp_raise_ValueError(NULL);
    if(dest < PSRAM_BOT_BASE) mp_raise_ValueError(NULL);
    if(dest >= PSRAM_TOP_BASE) mp_raise_ValueError(NULL);
    if(dest+actual_len+3 >= PSRAM_TOP_BASE) mp_raise_ValueError(NULL);

    uint32_t so_far = 0;
    DWORD *ptr = &mapping[1];
    for(int i=0; i<num_used; i++) {
        int num_clusters = *(ptr++);
        uint32_t cluster = *(ptr++);

        uint8_t *spot = block_to_ptr(clst2sect(&vfs.fatfs, cluster), num_clusters);
        if(!spot) {
            //printf("[%d] (cl=0x%lx ln=%d) => ", i, cluster, num_clusters);
            //printf("0x%lx\n", clst2sect(&vfs.fatfs, cluster));
            mp_raise_ValueError(MP_ERROR_TEXT("clstfck"));
        }
        uint32_t len = num_clusters*BLOCK_SIZE;

        if(i == num_used-1) {
            // final cluster might include some bytes past the EOF
            len = actual_len - so_far;
            // align4
            len = (len + 3) & ~0x3;
        } else {
            so_far += len;
        }

        memcpy(dest, spot, len);
        dest += len;

        if(dest >= PSRAM_TOP_BASE) mp_raise_ValueError(NULL);
    }
    f_close(&fp);

    return MP_OBJ_NEW_SMALL_INT(actual_len);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(psram_copy_file_obj, psram_copy_file);

mp_obj_t psram_set_callback(mp_obj_t unused_self, mp_obj_t callback_in)
{
    // set or clear the callback, use None to disable
    soft_timer_remove(&host_wr_done);

    host_wr_done.callback = callback_in;

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(psram_set_callback_obj, psram_set_callback);

mp_obj_t psram_set_inserted(mp_obj_t unused_self, mp_obj_t enable_in)
{
    // set or clear insertion status (media started)
    if(enable_in != MP_ROM_NONE) {
        bool enable = !!mp_obj_get_int(enable_in);

        flag_STARTED = enable;
    }

    return MP_OBJ_NEW_SMALL_INT(flag_STARTED);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(psram_set_inserted_obj, psram_set_inserted);

mp_obj_t psram_get_time(mp_obj_t unused_self)
{
    // return time of last write from host

    return mp_obj_new_int_from_uint(psram_obj.host_write_time);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(psram_get_time_obj, psram_get_time);


STATIC const mp_rom_map_elem_t psram_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_readblocks), MP_ROM_PTR(&psram_readblocks_obj) },
    { MP_ROM_QSTR(MP_QSTR_writeblocks), MP_ROM_PTR(&psram_writeblocks_obj) },
    { MP_ROM_QSTR(MP_QSTR_ioctl), MP_ROM_PTR(&psram_ioctl_obj) },
    { MP_ROM_QSTR(MP_QSTR_wipe), MP_ROM_PTR(&psram_wipe_obj) },
    { MP_ROM_QSTR(MP_QSTR_mmap), MP_ROM_PTR(&psram_mmap_file_obj) },
    { MP_ROM_QSTR(MP_QSTR_copy_file), MP_ROM_PTR(&psram_copy_file_obj) },
    { MP_ROM_QSTR(MP_QSTR_callback), MP_ROM_PTR(&psram_set_callback_obj) },
    { MP_ROM_QSTR(MP_QSTR_set_inserted), MP_ROM_PTR(&psram_set_inserted_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_time), MP_ROM_PTR(&psram_get_time_obj) },
};

STATIC MP_DEFINE_CONST_DICT(psram_locals_dict, psram_locals_dict_table);

// our block device object for Micropython
const mp_obj_type_t psram_type = {
    { &mp_type_type },
    .name = MP_QSTR_PSRAM,
    .print = psram_print,
    .make_new = psram_make_new,
    .locals_dict = (mp_obj_dict_t *)&psram_locals_dict,
};


// EOF
