# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Placeholder for lazy devs. Builds debug version of Q1 by default. For a few specific
# goals, will do it for all supported platforms.
#
# Normally you should use:
#
#	make -f MK4-Makefile
# or
#	make -f Q1-Makefile
#

.DEFAULT:
	$(MAKE) DEBUG_BUILD=1 -f Q1-Makefile $(MAKECMDGOALS)

clean clobber rc1 release repro:
	$(MAKE) -f Q1-Makefile $(MAKECMDGOALS)
# 	$(MAKE) -f MK4-Makefile $(MAKECMDGOALS)

# EOF
