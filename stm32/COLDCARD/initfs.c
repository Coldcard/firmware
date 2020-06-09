/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 *
 * Based on part of ports/stm32/main.c
 *
 */
/*
 * This file is part of the MicroPython project, http://micropython.org/
 *
 * The MIT License (MIT)
 *
 * Copyright (c) 2013, 2014 Damien P. George
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>

#include "py/runtime.h"
#include "py/stackctrl.h"
#include "py/gc.h"
#include "py/mphal.h"
#include "lib/oofatfs/ff.h"
#include "extmod/vfs.h"
#include "extmod/vfs_fat.h"

#include "systick.h"
#include "storage.h"
#include "sdcard.h"

// Important: system assumes this is always the /flash filesystem, mounted.
extern fs_user_mount_t fs_user_mount_flash;

// force_boot_py_contents()
//
    static void
force_boot_py_contents(FATFS *fs)
{

    static const char fresh_boot_py[] = 
        "# boot.py - CANNOT CHANGE\r\n"
        "import machine, pyb, sys, os\r\n"
        "from machine import bootloader as dfu\r\n"
        "from machine import reset\r\n"
        "\r\n"
        "from main import loop, go; go()\r\n"
        ;

    // Always replace boot.py with correct content. Never run modified
    // version that might be there already.
    FIL fp;
    UINT n;
    FRESULT res;

    res = f_open(fs, &fp, "/boot.py", FA_READ);
    if(res == FR_OK) {
        // verify contents
        uint8_t buf[sizeof(fresh_boot_py) + 10];

        UINT actual = 0;
        res = f_read(&fp, buf, sizeof(buf), &actual);

        f_close(&fp);

        if(res == FR_OK && actual == sizeof(fresh_boot_py)-1) {
            // right size, but check contents too
            if(memcmp(buf, fresh_boot_py, sizeof(fresh_boot_py) - 1) == 0) {
                // good!
                return;
            }
        }
    }

    // re-write it
    f_open(fs, &fp, "/boot.py", FA_WRITE | FA_CREATE_ALWAYS);
    f_write(&fp, fresh_boot_py, sizeof(fresh_boot_py) - 1, &n);
    f_close(&fp);

    printf("initfs: rewrote boot.py\n");
}

// Replace standard version of this function, so it's useful for this project.
//
MP_NOINLINE bool init_flash_fs(uint reset_mode)
{

    static const char fresh_readme_txt[] =
        "Coldcard Wallet: Virtual Disk\r\n"
        "\r\n"
        "Developers can put files into /lib to use in place of normal Coldcard code.\r\n"
        "\r\n"
        "- reference data could also be stored, for your code to read\r\n"
        "- stock firmware does not use this area for anything\r\n"
        "- this area mounted at /flash during normal bootup\r\n"
        "- limited to 128k, must be FAT32\r\n"
        "- there is a menu command to reset this area to stock values\r\n"
        "- contents will survive firmware upgrades\r\n"
        ;

    // init the vfs object
    fs_user_mount_t *vfs_fat = &fs_user_mount_flash;
    vfs_fat->flags = 0;
    pyb_flash_init_vfs(vfs_fat);

    // try to mount the flash
    FRESULT res = f_mount(&vfs_fat->fatfs);

    if (reset_mode == 3 || res == FR_NO_FILESYSTEM) {
        // no filesystem, or asked to reset it, so create a fresh one

        uint8_t working_buf[_MAX_SS];
        res = f_mkfs(&vfs_fat->fatfs, FM_FAT, 0, working_buf, sizeof(working_buf));
        if (res == FR_OK) {
            // success creating fresh LFS
        } else {
            printf("PYB: can't create flash filesystem\n");
            return false;
        }

        // set volume label, which becomes mountpoint on MacOS
        f_setlabel(&vfs_fat->fatfs, "COLDCARD");

        FIL fp;
        UINT n;

        // create readme file
        f_open(&vfs_fat->fatfs, &fp, "/README.txt", FA_WRITE | FA_CREATE_ALWAYS);
        f_write(&fp, fresh_readme_txt, sizeof(fresh_readme_txt) - 1, &n);
        f_close(&fp);

        // make required subdirs
        f_mkdir(&vfs_fat->fatfs, "/lib");

        // XXX need this due to a line of code in stm32/main.c
        f_open(&vfs_fat->fatfs, &fp, "/SKIPSD", FA_WRITE | FA_CREATE_ALWAYS);
        f_write(&fp, "y", 1, &n);
        f_close(&fp);

        // create an ident file, or two
        // - algo matches shared/version.py serial_number() function
        {   char    fname[80];
            const uint8_t *id = (const uint8_t *)MP_HAL_UNIQUE_ID_ADDRESS;     // 12 bytes, binary
            snprintf(fname, sizeof(fname),
                    "ckcc-%02X%02X%02X%02X%02X%02X.txt",
                    id[11], id[10] + id[2], id[9], id[8] + id[0], id[7], id[6]);

            f_open(&vfs_fat->fatfs, &fp, fname, FA_WRITE | FA_CREATE_ALWAYS);
            f_write(&fp, fname+5, 12, &n);
            f_close(&fp);

            f_open(&vfs_fat->fatfs, &fp, "serial.txt", FA_WRITE | FA_CREATE_ALWAYS);
            f_write(&fp, fname+5, 12, &n);
            f_close(&fp);
        }


    } else if (res == FR_OK) {
        // mount sucessful
    } else {
    fail:
        printf("PYB: can't mount flash\n");
        return false;
    }

    // mount the flash device (there should be no other devices mounted at this point)
    // we allocate this structure on the heap because vfs->next is a root pointer
    mp_vfs_mount_t *vfs = m_new_obj_maybe(mp_vfs_mount_t);
    if (vfs == NULL) {
        goto fail;
    }
    vfs->str = "/flash";
    vfs->len = 6;
    vfs->obj = MP_OBJ_FROM_PTR(vfs_fat);
    vfs->next = NULL;
    MP_STATE_VM(vfs_mount_table) = vfs;

    // The current directory is used as the boot up directory.
    // It is set to the internal flash filesystem by default.
    MP_STATE_PORT(vfs_cur) = vfs;

    // Make sure we have a /flash/boot.py.  Create it if needed, also verify and force contents
    force_boot_py_contents(&vfs_fat->fatfs);

    return true;
}

// EOF
