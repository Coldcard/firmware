# (c) Copyright 2018 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Just a little helper for CK devs ... so we can do "make up" in this dir.

all:
	(cd ../stm32; make all firmware-signed.dfu)

dfu:
	(cd ../stm32; make && make dfu)

# Find any python files newer than the last firmware DFU file, and copy
# them onto the flash filesystem of the device. They will replace the
# frozen versions of the same name.
#
#NEWER = $(shell find . -name \*.py -newer ../stm32/firmware-signed.dfu)
#up:
#	cp $(NEWER) /Volumes/COLDCARD/lib

# Remove old junk code, restore use of frozen modules.
clean:
	rm /Volumes/COLDCARD/lib/*.py

tags:
	ctags --python-kinds=-i -f .tags *.py */*.py

.PHONY: up clean tags
