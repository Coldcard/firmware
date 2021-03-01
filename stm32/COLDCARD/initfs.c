/*
 * (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
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
#include "py/mperrno.h"
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

// Replace standard version of this function, so it's useful for this project.
//
int factory_reset_create_filesystem(void) {
    fs_user_mount_t vfs;
    pyb_flash_init_vfs(&vfs);

    uint8_t working_buf[FF_MAX_SS];
    FRESULT res = f_mkfs(&vfs.fatfs, FM_FAT, 0, working_buf, sizeof(working_buf));
    if (res != FR_OK) {
        mp_printf(&mp_plat_print, "MPY: can't create flash filesystem\n");
        return -MP_ENODEV;
    }

    static const char fresh_readme_txt[] =
        "Coldcard Wallet: Virtual Disk\r\n"
        "\r\n"
        "- reference data could also be stored, for your code to read\r\n"
        "- this area mounted at /flash during normal bootup\r\n"
        "- limited to 128k, must be FAT32\r\n"
        "- there is a menu command to reset this area to stock values\r\n"
        "- contents will survive firmware upgrades\r\n"
        ;

    // set volume label, which becomes mountpoint on MacOS
    f_setlabel(&vfs.fatfs, "COLDCARD");

    FIL fp;
    UINT n;

    // create readme file
    f_open(&vfs.fatfs, &fp, "/README.txt", FA_WRITE | FA_CREATE_ALWAYS);
    f_write(&fp, fresh_readme_txt, sizeof(fresh_readme_txt) - 1, &n);
    f_close(&fp);

    // make required subdirs
    f_mkdir(&vfs.fatfs, "/lib");

    // We don't need this anymore, but seems harmless to keep it.
    f_open(&vfs.fatfs, &fp, "/SKIPSD", FA_WRITE | FA_CREATE_ALWAYS);
    f_write(&fp, "y", 1, &n);
    f_close(&fp);

    // create an ident file, or two
    // - algo matches shared/version.py serial_number() function
    {   char    fname[80];
        const uint8_t *id = (const uint8_t *)MP_HAL_UNIQUE_ID_ADDRESS;     // 12 bytes, binary
        snprintf(fname, sizeof(fname),
                "ckcc-%02X%02X%02X%02X%02X%02X.txt",
                id[11], id[10] + id[2], id[9], id[8] + id[0], id[7], id[6]);

        f_open(&vfs.fatfs, &fp, fname, FA_WRITE | FA_CREATE_ALWAYS);
        f_write(&fp, fname+5, 12, &n);
        f_close(&fp);

        f_open(&vfs.fatfs, &fp, "serial.txt", FA_WRITE | FA_CREATE_ALWAYS);
        f_write(&fp, fname+5, 12, &n);
        f_close(&fp);
    }

    // Make sure we have a /flash/boot.py.  Create it if needed, also verify and force contents
    // LATER:
    // - v3 and earlier relied on the contents of boot.py to operate correctly,
    // so at bootup it verified contents and forced it.
    // - in v4, file is ignored, so we could delete but let's perserve easy downgrade
    // and just do nothing.
    //force_boot_py_contents(&vfs.fatfs);

    return 0; // success
}

// EOF
