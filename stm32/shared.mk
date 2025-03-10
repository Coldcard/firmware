# (c) Copyright 2021 by Coinkite Inc. This file is covered by license found in COPYING-CC.
#
# Shared values and target rules for Mk4 and Q.
#

# Define these vars to suit board
#BOARD = COLDCARD_MK4
# These values used to make .DFU files. Flash memory locations.
#FIRMWARE_BASE   = 0x08020000
#BOOTLOADER_BASE = 0x08000000
#BOOTLOADER_DIR = mk4-bootloader vs bootloader
#HW_MODEL = mk4
#PARENT_MKFILE = xx-Makefile

MPY_TOP = ../external/micropython
PORT_TOP = $(MPY_TOP)/ports/stm32
MPY_CROSS = $(MPY_TOP)/mpy-cross/mpy-cross
PYTHON_MAKE_DFU = $(MPY_TOP)/tools/dfu.py
PYTHON_DO_DFU = $(MPY_TOP)/tools/pydfu.py
DEBUG_BUILD ?= 0
# aka ../cli/signit.py
SIGNIT = signit

PROD_KEYNUM = -k 1

BUILD_DIR = l-port/build-$(BOARD)
MAKE_ARGS = BOARD=$(BOARD) -j 4 EXCLUDE_NGU_TESTS=1 DEBUG_BUILD=$(DEBUG_BUILD)

all: $(BOARD)/file_time.c
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS)

clean:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) clean
	$(RM) dev.dfu dev.bin
	git clean -xf built

clobber: clean
	rm -f *RC1*.dfu

# These trigger the 'all' target when we haven't completed a successful build yet
$(BUILD_DIR)/firmware.elf: all
$(BUILD_DIR)/firmware0.bin: all
$(BUILD_DIR)/firmware1.bin: all

firmware.elf: $(BUILD_DIR)/firmware.elf
	cp $(BUILD_DIR)/firmware.elf .

#
# Sign and merge various parts
#
firmware-signed.bin: $(BUILD_DIR)/firmware0.bin $(BUILD_DIR)/firmware1.bin
	$(SIGNIT) sign -b $(BUILD_DIR) -m $(HW_MODEL) $(VERSION_STRING) -o $@
firmware-signed.dfu: firmware-signed.bin
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):$< $@

# make the DFU file which is shared for upgrades
dfu: firmware-signed.dfu

# Build a binary, signed w/ production key
# - always rebuild binary for this one
.PHONY: dev.dfu
dev.dfu: $(BUILD_DIR)/firmware0.bin
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS)
	$(SIGNIT) sign -b $(BUILD_DIR) -m $(HW_MODEL) $(VERSION_STRING) $(PROD_KEYNUM) -o dev.bin
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):dev.bin dev.dfu

.PHONY: relink
relink:
	rm -rf $(BUILD_DIR)/firmware?.bin $(BUILD_DIR)/frozen_mpy*

# Slow, but works with unmod-ed board: use USB protocol to upgrade (2 minutes)
.PHONY: dev
dev: dev.dfu
	ckcc upgrade dev.dfu

# Requires special bootrom w/ DFU still enabled
.PHONY: up-dfu
up-dfu: dev.dfu
	$(PYTHON_DO_DFU) -u dev.dfu

$(BOARD)/file_time.c: make_filetime.py *-Makefile shared.mk
	./make_filetime.py $(BOARD)/file_time.c $(VERSION_STRING)
	cp $(BOARD)/file_time.c .

# Make a factory release: using key #1
# - when executed in a repro w/o the required key, it defaults to key zero
# - and that's what happens inside the Docker build
production.bin: firmware-signed.bin Makefile
	$(SIGNIT) sign -m $(HW_MODEL) $(VERSION_STRING) -r firmware-signed.bin $(PROD_KEYNUM) -o $@

SUBMAKE = $(MAKE) -f $(PARENT_MKFILE)

.PHONY: release
release: submods-match code-committed
	$(SUBMAKE) clean
	$(SUBMAKE) repro
	test -f built/production.bin
	$(SUBMAKE) release-products
	$(SUBMAKE) tag-source

# Make a release-candidate, faster.
.PHONY: rc1
rc1: 
	$(SUBMAKE) clean 		# critical, or else you get a mix of debug/not
	$(SUBMAKE) DEBUG_BUILD=0 all
	$(SIGNIT) sign -b $(BUILD_DIR) -m $(HW_MODEL) $(VERSION_STRING) $(PROD_KEYNUM) -o rc1.bin
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):rc1.bin \
		`signit version rc1.bin`-$(HW_MODEL)-RC1-coldcard.dfu
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):rc1.bin \
		-b $(BOOTLOADER_BASE):$(BOOTLOADER_DIR)/releases/$(BOOTLOADER_VERSION)/bootloader.bin \
		`signit version rc1.bin`-$(HW_MODEL)-RC1-factory-coldcard.dfu
	ls -1 *-RC1-*.dfu

# Make a test release-candidate but use full repro flow; slower than rc1 above.
# - no factory release, does no GIT tagging nor committing
# - but still must commit changed because code get into docker image via local git repo
.PHONY: rc2
rc2: RC2_TIMESTAMP = $(shell date "+%F_%H%M")
rc2: RC2_FNAME = ./RC2-$(RC2_TIMESTAMP)-$(HW_MODEL)-coldcard.dfu
rc2: submods-match code-committed
	$(SUBMAKE) clean
	$(SUBMAKE) repro
	test -f built/production.bin
	$(SIGNIT) sign -m $(HW_MODEL) $(VERSION_STRING) -r built/production.bin $(PROD_KEYNUM) -o built/rc2.bin
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):built/rc2.bin $(RC2_FNAME)
	ls -1 ./RC2-*.dfu

# This target just combines latest version of production firmware with bootrom into a DFU
# file, stored in ../releases with appropriately dated file name.
.PHONY: release-products
release-products: NEW_VERSION = $(shell $(SIGNIT) version built/production.bin)
release-products: RELEASE_FNAME = ../releases/$(NEW_VERSION)-$(HW_MODEL)-coldcard.dfu
release-products: built/production.bin
	test ! -f $(RELEASE_FNAME)
	cp built/file_time.c $(BOARD)/file_time.c
	-git commit $(BOARD)/file_time.c -m "For $(NEW_VERSION)"
	$(SIGNIT) sign -m $(HW_MODEL) $(VERSION_STRING) -r built/production.bin $(PROD_KEYNUM) -o built/production.bin
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):built/production.bin $(RELEASE_FNAME)
ifeq ($(findstring X,$(NEW_VERSION)),)
	$(PYTHON_MAKE_DFU) -b $(FIRMWARE_BASE):built/production.bin \
		-b $(BOOTLOADER_BASE):$(BOOTLOADER_DIR)/releases/$(BOOTLOADER_VERSION)/bootloader.bin \
		$(RELEASE_FNAME:%.dfu=%-factory.dfu)
endif
	@echo
	@echo 'Made release: ' $(RELEASE_FNAME)
	@echo

built/production.bin:
	@echo "To make production build, must run docker code"
	@false

# Use DFU to install the latest production version you have on hand
dfu-latest: 
	$(PYTHON_DO_DFU) -u $(LATEST_RELEASE)

# Use slow USB upload and reboot method.
latest:
	ckcc upgrade $(LATEST_RELEASE)

# verify submodules are checked-out at the correct revision
.PHONY: submods-match
SUBMODULES := $(shell git config --file ../.gitmodules --name-only --get-regex path)
SUBMODULES := $(SUBMODULES:submodule.%.path=%)
SUBMODULES := $(filter-out stm32/mk4-bootloader/hal, $(SUBMODULES))
submods-match:
	@echo Submodules: $(SUBMODULES)
	git submodule status --cached $(SUBMODULES:%=../%) > sm-want.txt
	git submodule status $(SUBMODULES:%=../%) > sm-have.txt
	@echo "Submodules: <WANT vs. >HAVE"
	diff sm-want.txt sm-have.txt
	rm sm-have.txt sm-want.txt
	@echo "Submodules are right revisions."

.PHONY: code-committed
code-committed:
	@echo ""
	@echo "Are all changes commited already?"
	git diff --stat --exit-code .
	@echo '... yes'

# Sign a message with the contents of ../releases on the developer's machine
.PHONY: sign-release
sign-release:
	(cd ../releases; shasum -a 256 *.dfu *.md | sort -rk 2 | \
		gpg --clearsign -u A3A31BAD5A2A5B10 --digest-algo SHA256 --output signatures.txt --yes - )
	git commit -m "Signed for $(HW_MODEL) release." ../releases/signatures.txt

# Tag source code associate with built release version.
# - do "make release" before this step!
# - also edit/commit ChangeLog text too
# - update & sign signatures file
# - and tag everything
tag-source: PUBLIC_VERSION = $(shell $(SIGNIT) version built/production.bin)
tag-source: sign-release submods-match code-committed
	git commit  --allow-empty -am "New release: "$(PUBLIC_VERSION)
	echo "Tagging version: " $(PUBLIC_VERSION)
	git tag -a $(PUBLIC_VERSION) -m "Release "$(PUBLIC_VERSION)
	git push
	git push --tags

# DFU file of boot and main code
# - bootloader is last so it can fail if already installed (maybe)
#
mostly.dfu: firmware-signed.bin $(BOOTLOADER_DIR)/bootloader.bin Makefile
	$(PYTHON_MAKE_DFU) \
			-b $(FIRMWARE_BASE):firmware-signed.bin \
			-b $(BOOTLOADER_BASE):$(BOOTLOADER_DIR)/bootloader.bin $@

# send everything
m-dfu: mostly.dfu
	$(PYTHON_DO_DFU) -u mostly.dfu

# unused
stlink:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) deploy-stlink

# useless, will be ignored by bootloader
unsigned-dfu:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) deploy

# see $(BOARD)/mpconfigboard.mk
tags: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) tags
checksum: 
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) checksum
files:
	cd $(PORT_TOP) && $(MAKE) $(MAKE_ARGS) files

# OLD dev junk?
# compile and freeze python code
PY_FILES = $(shell find ../shared -name \*.py)
ALL_MPY_FILES = $(addprefix build/, $(PY_FILES:../shared/%.py=%.mpy))
MPY_FILES = $(filter-out build/obsolete/%, $(ALL_MPY_FILES))

# detailed listing, very handy
OBJDUMP = arm-none-eabi-objdump
firmware.lss: $(BUILD_DIR)/firmware.elf
	$(OBJDUMP) -h -S $< > $@

# Dump sizes of all frozen py files; requires recent build.
.PHONY: sizes
sizes:
	wc -c $(BUILD_DIR)/frozen_mpy/*.mpy | sort -n

# Measure flash impact of a single file. Great for before/after.
# 	make F=foo.py size
# where: foo.py is anything in ../shared
size:
	$(MPY_CROSS) -o tmp.mpy -s $F ../shared/$F
	wc -c tmp.mpy

# one time setup, after repo checkout
setup:
	cd $(MPY_TOP) ; git submodule update --init lib/stm32lib
	cd ../external/libngu; make min-one-time
	cd $(MPY_TOP)/mpy-cross ; make
	-ln -s $(PORT_TOP) l-port
	-ln -s $(MPY_TOP) l-mpy
	cd $(PORT_TOP)/boards; if [ ! -L COLDCARD ]; then \
		ln -s ../../../../../stm32/COLDCARD COLDCARD; fi
	cd $(PORT_TOP)/boards; if [ ! -L COLDCARD_MK4 ]; then \
		ln -s ../../../../../stm32/COLDCARD_MK4 COLDCARD_MK4; fi
	cd $(PORT_TOP)/boards; if [ ! -L COLDCARD_Q1 ]; then \
		ln -s ../../../../../stm32/COLDCARD_Q1 COLDCARD_Q1; fi
	

# Caution: docker container has read access to your source tree
# - a readonly copy of source tree, and one output directory
# - build products are copied to there, see repro-build.sh
# - works from this repo, but starts with copy of HEAD
DOCK_RUN_ARGS = -v $(realpath ..):/work/src:ro \
				-v $(realpath built):/work/built:rw \
				-u $$(id -u):$$(id -g) coldcard-build
repro: submods-match code-committed
repro: 
	docker build -t coldcard-build - < dockerfile.build
	(cd ..; docker run $(DOCK_RUN_ARGS) sh src/stm32/repro-build.sh $(VERSION_STRING) $(HW_MODEL) $(PARENT_MKFILE))

# debug: shell into docker container
shell:
	docker run -it $(DOCK_RUN_ARGS) sh

# debug: allow docker to write into source tree
#DOCK_RUN_ARGS := -v $(realpath ..):/work/src:rw --privileged coldcard-build

PUBLISHED_BIN ?= $(wildcard ../releases/*-v$(VERSION_STRING)-$(HW_MODEL)-coldcard.dfu)

# final step in repro-building: check you got the right bytes
# - but you don't have the production signing key, so that section is removed
check-repro: TRIM_SIG = sed -e 's/^00003f[89abcdef]0 .*/(firmware signature here)/'
check-repro: firmware-signed.bin
ifeq ($(PUBLISHED_BIN),)
	@echo ""
	@echo "Need published binary for: $(VERSION_STRING)"
	@echo ""
	@echo "Copy it into ../releases"
	@echo ""
else
	@echo Comparing against: $(PUBLISHED_BIN)
	test -n "$(PUBLISHED_BIN)" -a -f $(PUBLISHED_BIN)
	$(RM) -f check-fw.bin check-bootrom.bin
	$(SIGNIT) split $(PUBLISHED_BIN) check-fw.bin check-bootrom.bin
	$(SIGNIT) check check-fw.bin
	$(SIGNIT) check firmware-signed.bin
	hexdump -C firmware-signed.bin | $(TRIM_SIG) > repro-got.txt
	hexdump -C check-fw.bin | $(TRIM_SIG) > repro-want.txt
	diff repro-got.txt repro-want.txt
	@echo ""
	@echo "SUCCESS. "
	@echo ""
	@echo "You have built a bit-for-bit identical copy of Coldcard firmware for v$(VERSION_STRING)"
endif

# revert "make release" and it's actions
unrelease: BAD_VERSIONS ?= $(shell git tag --contains HEAD^^)
unrelease:
	echo "Trying to forget: $(BAD_VERSIONS)"

#
# Various debug firmware upload methods. Won't work on production units due to bootrom.
#

# This is fast for Coinkite devs, but no DFU support in the wild.
dfu-up: dev.dfu
	echo 'dfu' | nc localhost 4444
	$(PYTHON_DO_DFU) -u dev.dfu

# When device already in DFU mode
dfu up2: dev.dfu
	$(PYTHON_DO_DFU) -u dev.dfu

# Slowest DFU, but easier w/ stock tools
dfu-slow: dev.dfu
	dfu-util -d 0483:df11 -a 0 -D $< -R

# Super fast, assumes Coldcard already attached and unlocked on this Mac.
up: dev.dfu
	cp dev.dfu /Volumes/COLDCARD/.
	diskutil eject /Volumes/COLDCARD

# Fairly fast, assumes openocd already running, and its current directory is here.
ocp-up: dev.dfu
	echo "load_image dev.dfu $(FIRMWARE_BASE) bin; reset run" | nc localhost 4444

# EOF
