# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Just a little helper for CK devs ... so we can do "make up" in this dir.

all:
	(cd ../stm32; make all firmware-signed.dfu)

dfu:
	(cd ../stm32; make && make dfu)

q1:
	(cd ../stm32; make dfu-up)

up:
	(cd ../stm32; make up)

tags:
	ctags --python-kinds=-i -f .tags *.py */*.py

.PHONY: up tags q1 dfu
