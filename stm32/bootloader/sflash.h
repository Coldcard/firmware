/*
 * (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
 * and is covered by GPLv3 license found in COPYING.
 */
#include "basics.h"

#define SF_COMPLETED_UPGRADE          0xb50d5c24
extern uint32_t     sf_completed_upgrade;

extern void sf_setup(void);

// maybe upgrade to a firmware image found in sflash
void sf_firmware_upgrade(void);

