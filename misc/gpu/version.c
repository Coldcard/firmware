// (c) Copyright 2023 by Coinkite Inc. This file is covered by license found in COPYING-CC.
//
// Version string. Careful with changes because parsed by python code and probably others.
//
#include "version.h"

// the Makefile will define BUILD and GIT values.
const char version_string[] = RELEASE_VERSION 
#ifdef BUILD_TIME
    " time=" BUILD_TIME 
#endif
#ifdef GIT_HASH
    " git=" GIT_HASH 
#endif
#ifndef RELEASE
    " DEV=1" 
#endif
;
