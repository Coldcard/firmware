# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# This file is just a placeholder/short-cut for lazy devs.
# It builds a debug version of Q1 by default.
#
# Normally you must use:
#
#	make -f MK-Makefile
# or
#	make -f Q1-Makefile
#

.DEFAULT_GOAL := all
.DEFAULT all:
	$(MAKE) DEBUG_BUILD=1 -f MK-Makefile $(MAKECMDGOALS)

clean clobber repro:
	@echo You should do either:
	@echo
	@echo "   make" -f Q1-Makefile $(MAKECMDGOALS)
	@echo "-OR-"
	@echo "   make" -f MK-Makefile $(MAKECMDGOALS)

rc1 rc2 release:
	make -f Q1-Makefile $(MAKECMDGOALS) && make -f MK-Makefile $(MAKECMDGOALS)

# EOF
