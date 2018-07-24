# (c) Copyright 2018 by Coinkite Inc. This file is part of Coldcard <coldcardwallet.com>
# and is covered by GPLv3 license found in COPYING.
#
# Build micropython for stm32 (an ARM processor). Also handles signing of resulting firmware images.
#
MPY_TOP = ../external/micropython
PORT_TOP = $(MPY_TOP)/ports/stm32
MPY_CROSS = $(MPY_TOP)/mpy-cross/mpy-cross
PYTHON_MAKE_DFU = $(MPY_TOP)/tools/dfu.py
PYTHON_DO_DFU = $(MPY_TOP)/tools/pydfu.py
SIGNIT = ../ENV/bin/signit

MAKE_ARGS = BOARD=COLDCARD -j 4


all:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS)

clean-mpy:
	rm -rf build

clean: clean-mpy
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) clean

up: mpy-files.timestamp
	-rm -rf /Volumes/COLDCARD/{main.py,.Trashes,._.Trashes}
	rsync -ra --exclude Makefile build/ /Volumes/COLDCARD/lib

# Used only when making .DFU files; many other things also need to be right!
FIRMWARE_BASE   = 0x08008000
BOOTLOADER_BASE = 0x08000000
FILESYSTEM_BASE = 0x080e0000

# Our version
VERSION_STRING = 0.5.4

#
# Sign and merge various parts
#
firmware-signed.bin: l-port/build-COLDCARD/firmware?.bin
	$(SIGNIT) sign $(VERSION_STRING)
firmware-signed.dfu: firmware-signed.bin Makefile
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):$< $@
dfu: firmware-signed.dfu
	$(PYTHON_DO_DFU) -u firmware-signed.dfu

# Make a factory release: using key #1
production.bin: firmware-signed.bin Makefile
	$(SIGNIT) sign $(VERSION_STRING) -r firmware-signed.bin -k 1 -o production.bin

# This is release of the bootloader that will be build into the release firmware.
BOOTLOADER_VERSION = 1.0.0

.PHONY: release
release: NEW_VERSION = $(shell $(SIGNIT) version production.bin)
release: RELEASE_FNAME = ../releases/$(NEW_VERSION)-coldcard.dfu
release: production.bin
	test ! -f $(RELEASE_FNAME) # Relase file exists!
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):production.bin \
		-b $(BOOTLOADER_BASE):bootloader/releases/$(BOOTLOADER_VERSION)/bootloader.bin \
		$(RELEASE_FNAME)
	@echo
	@echo 'Made release: ' $(RELEASE_FNAME)

# install the latest production version you have on hand
latest: 
	$(PYTHON_DO_DFU) -u `ls -t1 ../releases/*.dfu | head -1`

# sent latest/all versions to factory
publish-factory:
	rsync -av ../releases/20*.dfu ckcc-prod:src

# Tag source code associate with built release version.
# - use when a new release is built
publish-source: PUBLIC_VERSION = $(shell $(SIGNIT) version production.bin)
publish-source:
	git diff --stat --exit-code .		# uncommited changes?
	echo "Taging version: " $(PUBLIC_VERSION)
	git tag -a $(PUBLIC_VERSION) -m "Release "$(PUBLIC_VERSION)
	git push --tags

# DFU file of boot and main code; no need for filesystem, since that is built as needed.
# - bootloader is last so it can fail if already installed (maybe)
#
mostly.dfu: firmware-signed.bin bootloader/bootloader.bin Makefile
	$(PYTHON_MAKE_DFU) \
			-b $(FIRMWARE_BASE):firmware-signed.bin \
			-b $(BOOTLOADER_BASE):bootloader/bootloader.bin $@

# Clear the internal filesystem (for dev-mistakes recovery)
# - unused?
.PHONY: wipe-fs
wipe-fs: 
	dd if=/dev/urandom of=tmp.bin bs=512 count=1
	$(PYTHON_MAKE_DFU) -b $(FILESYSTEM_BASE):tmp.bin tmp.dfu
	$(PYTHON_DO_DFU) -u tmp.dfu
	rm tmp.bin tmp.dfu

# send everything

m-dfu: mostly.dfu
	$(PYTHON_DO_DFU) -u mostly.dfu

stlink:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) deploy-stlink

# useless, wont' be run:
unsigned-dfu:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) deploy

# see COLDCARD/mpconfigboard.mk
tags: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) tags
checksum: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) checksum
files:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) files

# compile and freeze python code
PY_FILES = $(shell find ../shared -name \*.py)
ALL_MPY_FILES = $(addprefix build/, $(PY_FILES:../shared/%.py=%.mpy))
MPY_FILES = $(filter-out build/obsolete/%, $(ALL_MPY_FILES))


mpy-files.timestamp: Makefile build/boot.py $(MPY_FILES)
	touch build/SKIPSD
	date > $@

build/%.mpy: ../shared/%.py Makefile
	mkdir -p $(dir $@)
	$(MPY_CROSS) -o $@ -s $*.py $<


# 1) See <https://github.com/texane/stlink>
# 2) In another window: 
#		st-util
# Can do:
# - "load" which writes the flash (medium speed, lots of output on st-util)
# - "cont" starts/continues system
# - "br main" sets breakpoints
# - "mon reset" to reset micro
# - and so on
#
debug:
	arm-none-eabi-gdb $(PORT_TOP)/build-COLDCARD/firmware.elf -x gogo.gdb

# detailed listing, very handy
OBJDUMP = arm-none-eabi-objdump
firmware.lss: $(PORT_TOP)/build-COLDCARD/firmware.elf
	$(OBJDUMP) -h -S $< > $@



setup:
	cd $(MPY_TOP) ; git submodule update --init lib/stm32lib
	cd $(MPY_TOP)/mpy-cross ; make
	-ln -s $(PORT_TOP) l-port
	-ln -s $(MPY_TOP) l-mpy
	-cd $(PORT_TOP)/boards ; ln -s ../../../../../stm32/COLDCARD COLDCARD
	ln -s COLDCARD

