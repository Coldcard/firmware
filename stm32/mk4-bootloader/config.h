/*
 * (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
 */
#pragma once
#include "../sigheader.h"

#ifdef FOR_Q1_ONLY
# define BOOT_BANNER         "\r\n\nQ1 Bootloader: "
# define HW_COMPAT_MASK      MK_Q1_OK
# define SCREENS_H           "assets/q1_screens.h"
#else
# define BOOT_BANNER         "\r\n\nMk4 Bootloader: "
# define HW_COMPAT_MASK      MK_4_OK
# define SCREENS_H           "assets/screens.h"
#endif

// EOF
