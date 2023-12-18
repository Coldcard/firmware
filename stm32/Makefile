# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Placeholder for lazy devs. Builds debug version of Mk4 by default. For a few specific
# goals, will do it for both Mk3 and Mk4.
#
# Normally you should use:
#
#	make -f MK4-Makefile
# or
#	make -f MK3-Makefile
#

.DEFAULT:
	$(MAKE) DEBUG_BUILD=1 -f MK4-Makefile $(MAKECMDGOALS)


clean clobber rc1:
	$(MAKE) -f MK4-Makefile $(MAKECMDGOALS)

release repro:
	$(MAKE) -f MK4-Makefile $(MAKECMDGOALS)

# EOF
